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
import io
import tempfile
import pytest
import evi

def test_keypack_from_context(ctx):
    kp = evi.KeyPack(ctx)
    assert repr(kp).startswith("<evi.KeyPack>")

def test_keypack_save_load_enc(ctx, key_dir):
    kp = evi.KeyPack(ctx)
    kp.load_enc_key_file(f"{key_dir}/EncKey.bin")
    kp.load_eval_key_file(f"{key_dir}/EvalKey.bin")

    kp.save_enc_key_file(f"{key_dir}/EncKey_copy.bin")
    kp.save_eval_key_file(f"{key_dir}/EvalKey_copy.bin")

    kp2 = evi.KeyPack(ctx)
    kp2.load_enc_key_file(f"{key_dir}/EncKey_copy.bin")
    kp2.load_eval_key_file(f"{key_dir}/EvalKey_copy.bin")

    assert repr(kp2).startswith("<evi.KeyPack>")
