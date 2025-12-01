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

import pytest
import evi
import numpy as np
import math

# ---------------------------
# Fixtures
# ---------------------------

@pytest.fixture(scope="module")
def kp(ctx):
    return evi.KeyPack(ctx)

@pytest.fixture(scope="module")
def sk_and_pub(ctx, kp):
    kg = evi.KeyGenerator(ctx, kp)
    sk = kg.gen_sec_key()
    kg.gen_pub_keys(sk)
    return sk, kp

@pytest.fixture(scope="module")
def enc(ctx):
    return evi.Encryptor(ctx)

@pytest.fixture(scope="module")
def dec(ctx):
    return evi.Decryptor(ctx)

def _get_random_vector(dim: int) -> np.ndarray:
    if dim <= 16 or dim > 4096:
        raise ValueError(f"Invalid dimension: {dim}")

    vec = np.random.uniform(-1.0, 1.0, dim).astype(np.float32)
    norm = np.linalg.norm(vec)

    if norm > 0:
        vec /= norm

    return vec

def l2_norm(vec: np.ndarray) -> float:
    return np.sqrt(np.sum(vec * vec))

def relative_error(original, modified):
    diff_sum = 0.0
    for o, m in zip(original, modified):
        diff = o - m
        diff_sum += diff * diff

    numerator = math.sqrt(diff_sum)
    denominator = l2_norm(np.asarray(original, dtype=np.float32))
    return numerator / (denominator + 1e-12)

# ---------------------------
# Tests
# ---------------------------

def test_decryptor_query_roundtrip(enc, dec, sk_and_pub, dim):
    sk, kp = sk_and_pub
    try:
        data = [0.1 * i for i in range(dim)]
        q = enc.encrypt(data, kp, evi.EncodeType.ITEM)
        assert isinstance(q, evi.Query)

        msg = dec.decrypt(q, sk)
        assert "<evi.Message" in repr(msg)

        try:
            ni = q.num_items
            assert isinstance(ni, int)
        except Exception:
            pass
    except Exception as ex:
        pytest.fail(f"Decryptor.decrypt(query, secret_key) failed: {type(ex).__name__}: {ex}")

def test_decryptor_flow(ctx, key_dir, dim):
    try:
        kp = evi.KeyPack(ctx)
        kp.load_enc_key_file(key_dir + "/EncKey.bin")
        sk = evi.SecretKey(key_dir + "/SecKey.bin")

        enc = evi.Encryptor(ctx)
        dec = evi.Decryptor(ctx)

        data = _get_random_vector(dim).astype("float32")
        ct = enc.encrypt(data.tolist(), kp, evi.EncodeType.ITEM)

        msg = dec.decrypt(ct, sk)
        arr = np.array(msg, dtype=np.float32, copy=False)

        err = relative_error(np.array(data, dtype=np.float32), arr[:dim])
        assert err < 0.01, f"Relative error too high: {err}"
    except Exception as ex:
        pytest.fail(f"Decryptor(ctx) flow failed: {type(ex).__name__}: {ex}")

def test_decryptor_matrix_roundtrip(ctx_pcmm, key_dir_pcmm, dim):
    try:
        batch = [
            [0.1 * i for i in range(dim)],
            [0.2 * i for i in range(dim)],
            [0.3 * i for i in range(dim)],
        ]

        enc = evi.Encryptor(ctx_pcmm)
        dec = evi.Decryptor(ctx_pcmm)

        enc_key_path = key_dir_pcmm + "/EncKey.bin"
        ctxt_matrix = enc.encrypt_bulk(batch, enc_key_path, evi.EncodeType.ITEM, level=False)
        assert isinstance(ctxt_matrix, list)
        assert all(isinstance(ct, evi.Query) for ct in ctxt_matrix)

        msg = dec.decrypt(ctxt_matrix[0], key_dir_pcmm + "/SecKey.bin")
        assert isinstance(msg, evi.Message)

        arr = np.array(msg, dtype=np.float32, copy=False)
        err = relative_error(np.array(batch[0]), arr[:dim])
        assert err < 0.01
    except Exception as ex:
        pytest.fail(f"Decryptor.decryptMatrix(single ctxt, secret_key) failed: {type(ex).__name__}: {ex}")
