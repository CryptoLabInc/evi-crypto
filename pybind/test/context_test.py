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


def test_context_ctor_basic():
    ctx = evi.Context(
        evi.ParameterPreset.QF0,
        evi.DeviceType.CPU,
        512,
        evi.EvalMode.FLAT,
        None,  # device_id
    )
    assert isinstance(ctx, evi.Context)


@pytest.mark.parametrize("dim", [32, 128, 256, 512])
def test_context_ctor_various_dims(dim):
    ctx = evi.Context(
        evi.ParameterPreset.QF0,
        evi.DeviceType.CPU,
        dim,
        evi.EvalMode.FLAT,
        None,
    )
    assert isinstance(ctx, evi.Context)


def test_context_ctor_with_device_id_zero():
    ctx = evi.Context(
        evi.ParameterPreset.QF0,
        evi.DeviceType.CPU,
        512,
        evi.EvalMode.FLAT,
        0,  # device_id
    )
    assert isinstance(ctx, evi.Context)


def test_make_multi_context_basic():
    lst = evi.make_multi_context(
        evi.ParameterPreset.IP0,
        evi.DeviceType.CPU,
        evi.EvalMode.FLAT,
        None,
    )
    assert isinstance(lst, list)
    assert all(isinstance(c, evi.Context) for c in lst)
