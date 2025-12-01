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

# ---------------------------
# Helpers
# ---------------------------
def _seal_info_from_env():
    aes_path = os.getenv("AES_KEK_PATH")
    if aes_path and os.path.isfile(aes_path):
        with open(aes_path, "rb") as f:
            key = list(f.read())
        if len(key) != 32:
            pytest.fail(f"AES_KEK_PATH must be 32 bytes, got {len(key)}")
        return evi.SealInfo(evi.SealMode.AES_KEK, key)
    return evi.SealInfo(evi.SealMode.NONE)

# ---------------------------
# Tests
# ---------------------------
def test_encryptor_with_keypack(ctx, key_dir, dim):
    try:
        kp = evi.KeyPack(ctx)
        kp.load_enc_key_file(key_dir + "/EncKey.bin")

        enc = evi.Encryptor(ctx)
        assert repr(enc).startswith("<evi.Encryptor>")

        data = [0.1 * i for i in range(dim)]
        batch = [
            [0.1 * i for i in range(dim)],
            [0.2 * i for i in range(dim)],
            [0.3 * i for i in range(dim)],
        ]

        c1 = enc.encrypt(data, kp, evi.EncodeType.ITEM)
        isinstance(c1, evi.Query)

        clist = enc.encrypt_bulk(batch, kp, evi.EncodeType.ITEM)
        if isinstance(clist, evi.Query):
            clist = [clist]
        assert isinstance(clist, list)
        total_blocks = sum(query.getInnerItemCount() for query in clist)
        assert total_blocks == len(batch)
    except Exception as ex:
        pytest.fail(f"Encryptor(ctx, key_pack) flow failed: {type(ex).__name__}: {ex}")


def test_encryptor_with_keypath(ctx, key_dir, dim):
    try:
        enc = evi.Encryptor(ctx)
        assert repr(enc).startswith("<evi.Encryptor>")

        data = [0.05 * i for i in range(dim)]
        batch = [
            [0.05 * i for i in range(dim)],
            [0.15 * i for i in range(dim)],
        ]

        q = enc.encode(data, evi.EncodeType.ITEM)
        assert q is not None

        c = enc.encrypt(data, key_dir + "/EncKey.bin", evi.EncodeType.ITEM)
        assert c is not None

        try:
            bl = enc.encrypt_bulk(batch, key_dir + "/EncKey.bin", evi.EncodeType.ITEM)
            if isinstance(bl, evi.Query):
                bl = [bl]
            assert isinstance(bl, list)
        except RuntimeError:
            bl = [enc.encrypt(vec, key_dir + "/EncKey.bin", evi.EncodeType.ITEM) for vec in batch]
        total_blocks = sum(query.getInnerItemCount() for query in bl)
        assert total_blocks == len(batch)
    except Exception as ex:
        pytest.fail(f"Encryptor(ctx, key_path) flow failed: {type(ex).__name__}: {ex}")

def test_encryptor_with_pcmm(ctx_pcmm, key_dir_pcmm, dim):
    try:
        enc = evi.Encryptor(ctx_pcmm)
        assert repr(enc).startswith("<evi.Encryptor>")

        batch = [
            [0.1 * i for i in range(dim)],
            [0.2 * i for i in range(dim)],
            [0.3 * i for i in range(dim)],
        ]

        enc_key_path = key_dir_pcmm + "/EncKey.bin"
        ctxt_matrix = enc.encrypt_bulk(batch, enc_key_path, evi.EncodeType.ITEM, level=False)
        assert isinstance(ctxt_matrix, list)
        assert all(isinstance(q, evi.Query) for q in ctxt_matrix)
        assert len(ctxt_matrix) == 1

    except Exception as ex:
        pytest.fail(f"Encryptor(ctx, key_path) flow failed: {type(ex).__name__}: {ex}")
