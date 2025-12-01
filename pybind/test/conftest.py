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
import shutil

import evi
import pytest


@pytest.fixture(scope="session")
def dim():
    return 512


@pytest.fixture(scope="session")
def ctx(dim):
    return evi.Context(
        evi.ParameterPreset.IP0,
        evi.DeviceType.CPU,
        dim,
        evi.EvalMode.RMP,
        None,
    )

@pytest.fixture(scope="session")
def ctx_pcmm(dim):
    return evi.Context(
        evi.ParameterPreset.IP0,
        evi.DeviceType.CPU,
        dim,
        evi.EvalMode.MM,
        None,
    )

@pytest.fixture(scope="session")
def key_dir():
    return "./temp/keys/no_seal"

@pytest.fixture(scope="session")
def key_dir_sealed():
    return "./temp/keys/sealed"

@pytest.fixture(scope="session")
def key_dir_pcmm():
    return "./temp/keys/pcmm"

@pytest.fixture(scope="session")
def kek_bytes():
    return list(bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))


@pytest.fixture(scope="session", autouse=True)
def generate_evi_keys(key_dir):
    shutil.rmtree(key_dir, ignore_errors=True)
    os.makedirs(key_dir, exist_ok=True)

    dim_list = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    context_list = [
        evi.Context(evi.ParameterPreset.IP0, evi.DeviceType.CPU, d, evi.EvalMode.RMP, None) for d in dim_list
    ]
    keygen = evi.MultiKeyGenerator(context_list, key_dir, evi.SealInfo(evi.SealMode.NONE))
    keygen.generate_keys()
    yield

    shutil.rmtree(key_dir, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def generate_evi_keys_sealed(key_dir_sealed, kek_bytes):
    shutil.rmtree(key_dir_sealed, ignore_errors=True)
    os.makedirs(key_dir_sealed, exist_ok=True)

    dim_list = [32, 64, 128, 256, 512, 1024, 2048, 4096]
    context_list = [
        evi.Context(evi.ParameterPreset.IP0, evi.DeviceType.CPU, d, evi.EvalMode.RMP, None) for d in dim_list
    ]
    keygen = evi.MultiKeyGenerator(context_list, key_dir_sealed, evi.SealInfo(evi.SealMode.AES_KEK, kek_bytes))
    keygen.generate_keys()
    yield

    shutil.rmtree(key_dir_sealed, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def generate_pcmm_keys(key_dir_pcmm):
    shutil.rmtree(key_dir_pcmm, ignore_errors=True)
    os.makedirs(key_dir_pcmm, exist_ok=True)

    dim_list = [512]
    context_list = [
        evi.Context(evi.ParameterPreset.IP0, evi.DeviceType.CPU, d, evi.EvalMode.MM, None) for d in dim_list
    ]
    keygen = evi.MultiKeyGenerator(context_list, key_dir_pcmm, evi.SealInfo(evi.SealMode.NONE))
    keygen.generate_keys()
    yield

    # shutil.rmtree(key_dir_pcmm, ignore_errors=True)
