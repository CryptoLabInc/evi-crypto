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

import os
import tempfile
import pytest
import evi

SEED_SIZE = 64

# ---------------------------
# Helpers
# ---------------------------
def _make_seal_info_from_env():
    aes_path = os.getenv("AES_KEK_PATH")
    if aes_path and os.path.isfile(aes_path):
        with open(aes_path, "rb") as f:
            key = list(f.read())
        if len(key) != 32:
            pytest.fail(f"AES_KEK_PATH must be 32 bytes, got {len(key)}")
        return evi.SealInfo(evi.SealMode.AES_KEK, key)
    return evi.SealInfo(evi.SealMode.NONE)

@pytest.fixture(scope="module")
def pack(ctx):
    return evi.KeyPack(ctx)


# ---------------------------
# KeyGenerator
# ---------------------------
def test_keygenerator_with_pack_and_seed(ctx, pack):
    try:
        seed = bytes(range(SEED_SIZE))
        kg = evi.KeyGenerator(ctx, pack, seed)

        sk = kg.gen_sec_key()
        assert repr(sk).startswith("<evi.SecretKey>")

        kg.gen_pub_keys(sk)
    except Exception as ex:
        pytest.fail(f"KeyGenerator(ctx, pack, seed) failed: {type(ex).__name__}: {ex}")


def test_keygenerator_context_only(ctx):
    try:
        kg = evi.KeyGenerator(ctx)
        sk = kg.gen_sec_key()
        assert repr(sk).startswith("<evi.SecretKey>")
        kg.gen_pub_keys(sk)
    except Exception as ex:
        pytest.fail(f"KeyGenerator(ctx) failed: {type(ex).__name__}: {ex}")


def _max_abs_diff(a, b):
    return max(abs(x - y) for x, y in zip(a, b))


def test_multikey_generate_stream_roundtrip(ctx, dim, tmp_path):
    out_dir = tmp_path / "stream-key"
    out_dir.mkdir(parents=True, exist_ok=True)

    contexts = [ctx]
    keygen = evi.MultiKeyGenerator(contexts, str(out_dir), evi.SealInfo(evi.SealMode.NONE))
    secret_from_stream, key_bundle = keygen.generate_keys_stream()

    assert isinstance(secret_from_stream, evi.SecretKey)
    assert isinstance(key_bundle, (bytes, bytearray))
    assert len(key_bundle) > 0

    restored_sec, restored_pack = evi.utils.deserialize_key_files(key_bundle, ctx)

    enc = evi.Encryptor(ctx)
    dec = evi.Decryptor(ctx)

    msg = [0.5 - 0.001 * i for i in range(dim)]
    query = enc.encrypt(msg, restored_pack, evi.EncodeType.ITEM)
    decrypted = dec.decrypt(query, restored_sec)

    recovered = [decrypted[i] for i in range(len(msg))]
    assert _max_abs_diff(msg, recovered) < 1e-3
