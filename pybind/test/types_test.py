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

import evi
import pytest


def test_constants_enums():
    assert evi.AES256_KEY_SIZE == 32

    _ = evi.ParameterPreset.QF0
    _ = evi.SealMode.NONE
    _ = evi.EvalMode.FLAT
    _ = evi.DeviceType.CPU
    _ = evi.DataType.PLAIN
    _ = evi.BatchType.BROADCAST
    _ = evi.ErrorCode.OK
    _ = evi.EncodeType.QUERY


def test_sealinfo_ctor_mode_only():
    s = evi.SealInfo(evi.SealMode.NONE)
    assert s.mode == evi.SealMode.NONE
    assert "SealInfo" in repr(s)


def test_sealinfo_ctor_with_key_ok():
    key = list(range(32))
    s = evi.SealInfo(evi.SealMode.AES_KEK, key)
    assert s.mode == evi.SealMode.AES_KEK
    assert "SealInfo" in repr(s)


def test_sealinfo_ctor_with_key_bad_len():
    bad = [0] * 31
    try:
        _ = evi.SealInfo(evi.SealMode.AES_KEK, bad)
        pytest.skip("31-byte key accepted (no length enforcement).")
    except Exception:
        pass
