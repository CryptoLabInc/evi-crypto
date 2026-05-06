"""
Benchmark: multi-threaded encrypt_row scaling with GIL-released encryptRow
Usage: python bench_encrypt_threads.py [--dim 512] [--rows 500] [--threads 1,2,4,8]
"""
import argparse
import os
import shutil
import sys
import threading
import time

import evi

KEY_DIR = "/tmp/bench_keys"
DIM = 512
ROWS = 500


def setup_keys(dim):
    shutil.rmtree(KEY_DIR, ignore_errors=True)
    os.makedirs(KEY_DIR, exist_ok=True)
    ctx = evi.Context(evi.ParameterPreset.IP0, evi.DeviceType.CPU, dim, evi.EvalMode.MM, None)
    kg = evi.MultiKeyGenerator([ctx], KEY_DIR, evi.SealInfo(evi.SealMode.NONE))
    kg.generate_keys()
    return ctx


def load_keypack(ctx):
    kp = evi.KeyPack(ctx)
    kp.load_enc_key_file(KEY_DIR + "/EncKey.bin")
    return kp


def encrypt_chunk(ctx, enc_key_path, data_chunk, results, idx, errors):
    try:
        enc = evi.Encryptor(ctx)
        results[idx] = enc.encrypt_row(data_chunk, enc_key_path, evi.EncodeType.ITEM)
    except Exception as e:
        errors[idx] = str(e)


def run_benchmark(ctx, enc_key_path, data, n_threads):
    chunk_size = len(data) // n_threads
    chunks = [data[i * chunk_size : (i + 1) * chunk_size] for i in range(n_threads)]
    # last chunk gets any remainder
    if len(data) % n_threads:
        chunks[-1] = data[(n_threads - 1) * chunk_size :]

    results = [None] * n_threads
    errors = [None] * n_threads
    threads = []

    t0 = time.perf_counter()
    for i in range(n_threads):
        t = threading.Thread(
            target=encrypt_chunk,
            args=(ctx, enc_key_path, chunks[i], results, i, errors),
        )
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - t0

    for i, err in enumerate(errors):
        if err:
            print(f"  [thread {i}] ERROR: {err}", file=sys.stderr)

    total_encrypted = sum(len(r) for r in results if r)
    return elapsed, total_encrypted


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dim", type=int, default=DIM)
    parser.add_argument("--rows", type=int, default=ROWS)
    parser.add_argument("--threads", type=str, default="1,2,4,8")
    args = parser.parse_args()

    thread_counts = [int(x) for x in args.threads.split(",")]

    print(f"Setup: dim={args.dim}, rows={args.rows}")
    print("Generating keys... ", end="", flush=True)
    ctx = setup_keys(args.dim)
    enc_key_path = KEY_DIR + "/EncKey.bin"
    print("done")

    data = [[float(j) * 0.001 for j in range(args.dim)] for _ in range(args.rows)]

    # warmup
    enc = evi.Encryptor(ctx)
    _ = enc.encrypt_row(data[:2], enc_key_path, evi.EncodeType.ITEM)

    print(f"\n{'threads':>8} {'time(s)':>10} {'rows/s':>10} {'speedup':>10} {'rows_ok':>10}")
    print("-" * 55)

    baseline = None
    for n in thread_counts:
        elapsed, total = run_benchmark(ctx, enc_key_path, data, n)
        rows_per_sec = total / elapsed
        speedup = (baseline / elapsed) if baseline else 1.0
        if baseline is None:
            baseline = elapsed
        print(f"{n:>8} {elapsed:>10.3f} {rows_per_sec:>10.1f} {speedup:>10.2f}x {total:>10}")


if __name__ == "__main__":
    main()
