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
import pytest
import evi

def test_secretkey_from_context(ctx):
    try:
        sk = evi.SecretKey(ctx)
        assert repr(sk).startswith("<evi.SecretKey>")
    except Exception as ex:
        pytest.fail(f"SecretKey(context) failed: {type(ex).__name__}: {ex}")

def test_secretkey_from_path(key_dir):
    key_path = key_dir + "/SecKey.bin"
    if not os.path.isfile(key_path):
        pytest.fail(f"Secret key file not found: {key_path}")
    try:
        sk = evi.SecretKey(key_path)
        assert repr(sk).startswith("<evi.SecretKey>")
    except Exception as ex:
        pytest.fail(
            f"SecretKey(path) failed: {type(ex).__name__}: {ex}\n"
            f"Check if the file '{key_path}' contains a valid SecretKey."
        )

def test_secretkey_from_path_with_sealinfo(key_dir_sealed, kek_bytes):
    key_path = key_dir_sealed + "/SecKey_sealed.bin"

    seal_info = evi.SealInfo(evi.SealMode.AES_KEK, kek_bytes)
    try:
        sk = evi.SecretKey(key_path, seal_info)
        assert repr(sk).startswith("<evi.SecretKey>")
    except Exception as ex:
        pytest.fail(
            f"SecretKey(path, seal_info) failed: {type(ex).__name__}: {ex}\n"
            f"Check if the file '{key_path}' and seal_info are valid."
        )
