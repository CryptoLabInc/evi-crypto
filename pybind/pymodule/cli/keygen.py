#////////////////////////////////////////////////////////////////////////////////
#//                                                                            //
#//  Copyright (C) 2025, CryptoLab, Inc.                                       //
#//                                                                            //
#//  Licensed under the Apache License, Version 2.0 (the "License");           //
#//  you may not use this file except in compliance with the License.          //
#//  You may obtain a copy of the License at                                   //
#//                                                                            //
#//     http://www.apache.org/licenses/LICENSE-2.0                             //
#//                                                                            //
#//  Unless required by applicable law or agreed to in writing, software       //
#//  distributed under the License is distributed on an "AS IS" BASIS,         //
#//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
#//  See the License for the specific language governing permissions and       //
#//  limitations under the License.                                            //
#//                                                                            //
#////////////////////////////////////////////////////////////////////////////////

import argparse
import sys
from pathlib import Path

import evi


def ensure_dir_empty(path_str: str) -> None:
    p = Path(path_str).expanduser().resolve()

    if p.exists() and p.is_file():
        print(f"[ERROR] '{p}' is file. This should be directory.")
        sys.exit(1)

    if p.exists() and any(p.iterdir()):
        print(f"[ERROR] '{p}' directory is NOT empty. Key generation canceled.")
        sys.exit(1)


def ensure_kek_loaded(args, parser) -> evi.SealInfo:
    if args.seal_mode == "none":
        return evi.SealInfo(evi.SealMode.NONE)
    elif args.seal_mode != "aes":
        raise ValueError(f"Invalid seal mode: {args.seal_mode}. Choose from 'none' or 'aes'.")

    if args.aes_kek is None:
        parser.error("--seal_mode aes requires --aes_kek (eg. --aes_kek ./aes.kek)")

    kek_bytes = args.aes_kek.read()
    try:
        args.aes_kek.close()
    except Exception:
        pass

    if len(kek_bytes) < 32:
        raise ValueError("KEK have to be 32 bytes for secret key sealing.")
    kek_bytes = kek_bytes[:32]
    return evi.SealInfo(evi.SealMode.AES_KEK, list(kek_bytes))


def string_to_preset(preset: str) -> evi.ParameterPreset:
    if preset == "runtime":
        return evi.ParameterPreset.RUNTIME
    elif preset == "ip0" or preset == "ip":
        return evi.ParameterPreset.IP0
    elif preset == "ip1" :
        return evi.ParameterPreset.IP1
    elif preset == "qf0" or preset == "qf":
        return evi.ParameterPreset.QF0
    elif preset == "qf1":
        return evi.ParameterPreset.QF1
    elif preset == "qf2":
        return evi.ParameterPreset.QF2
    elif preset == "qf3":
        return evi.ParameterPreset.QF3
    else:
        raise ValueError(f"Invalid preset: {preset}. Choose from 'runtime', 'ip0', 'ip1', 'qf0', 'qf1', 'qf2', or 'qf3'.")


def string_to_eval_mode(eval_mode: str) -> evi.EvalMode:
    if eval_mode == "flat":
        return evi.EvalMode.FLAT
    elif eval_mode == "rmp":
        return evi.EvalMode.RMP
    else:
        raise ValueError(f"Invalid evaluation mode: {eval_mode}. Choose from 'flat' or 'rmp'.")


def generate_key(dim_list, outdir, seal_info, preset, eval_mode):
    converted_preset = string_to_preset(preset)
    converted_eval_mode = string_to_eval_mode(eval_mode)
    contexts = [evi.Context(converted_preset, evi.DeviceType.CPU, d, converted_eval_mode) for d in dim_list]

    keygen = evi.MultiKeyGenerator(contexts, outdir, seal_info)

    print("Generating key...")
    keygen.generate_keys()

    print("Key generated with")
    print(f"  Dim: {dim_list}")
    print(f"  Preset: {preset}")

    print(f"  Seal Mode: {seal_info.mode.name}")
    print(f"  Path: {outdir}")


def main():
    parser = argparse.ArgumentParser(description="Generate a key for the ES2 API.")
    parser.add_argument(
        "--dim",
        type=int,
        nargs="+",
        default=[32, 64, 128, 256, 512, 1024, 2048, 4096],
        help="Dimension(s) of the key (default: All). You can specify multiple values, e.g., --dim 512 1024",
    )
    parser.add_argument(
        "--key_path", type=str, default="./keys", help="Output directory for the key (default: './keys')"
    )
    parser.add_argument("--key_id", type=str, default=None, help="Key ID for the key (default: None)")
    parser.add_argument(
        "--seal_mode",
        type=str,
        default="none",
        choices=["none", "aes"],
        help="Sealing mode for the key (default: 'none')",
    )
    parser.add_argument(
        "--preset",
        type=str,
        default="ip",
        choices=["runtime", "ip", "ip0", "ip1", "qf", "qf0", "qf1", "qf2", "qf3"],
        help="Parameter preset for the key (default: 'ip')",
    )
    parser.add_argument(
        "--eval_mode",
        type=str,
        default="rmp",
        choices=["flat", "rmp"],
        help="Evaluation mode for the key (default: 'rmp')",
    )
    parser.add_argument(
        "--aes_kek",
        type=argparse.FileType("rb"),
        default=None,
        help="When using --seal_mode aes, the secret key will be encrypted (sealed) "
        "with this KEK before storing it, providing stronger protection.",
    )
    args = parser.parse_args()
    outdir = args.key_path + "/" + args.key_id if args.key_id else args.key_path

    ensure_dir_empty(outdir)
    s_info = ensure_kek_loaded(args, parser)
    generate_key(args.dim, outdir, s_info, args.preset, args.eval_mode)


if __name__ == "__main__":
    main()
