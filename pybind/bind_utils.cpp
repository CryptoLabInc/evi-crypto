////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "EVI/Context.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/SecretKey.hpp"
#include "EVI/Utils.hpp"
#include "utils/Utils.hpp"

#include <pybind11/pybind11.h>

#include <sstream>
#include <stdexcept>
#include <tuple>

namespace py = pybind11;

void bind_utils(py::module_ &m) {
    auto utils_mod = m.def_submodule("utils");

    utils_mod.def(
        "serialize_key_files",
        [](const std::string &dir_path) {
            std::ostringstream os(std::ios::binary);
            evi::Utils::serializeKeyFiles(dir_path, os);
            const std::string blob = os.str();
            return py::bytes(blob.data(), blob.size());
        },
        py::arg("key_dir"));

    utils_mod.def(
        "deserialize_key_files",
        [](const py::bytes &blob, const evi::Context &context) {
            std::string buffer = blob;
            std::istringstream is(buffer, std::ios::binary);
            evi::SecretKey seckey = evi::makeSecKey(context);
            evi::KeyPack keypack = evi::makeKeyPack(context);
            evi::Utils::deserializeKeyFiles(is, seckey, keypack);
            return std::make_tuple(seckey, keypack);
        },
        py::arg("data"), py::arg("context"));

    utils_mod.def(
        "deserialize_key_files_into",
        [](const py::bytes &blob, evi::SecretKey &seckey, evi::KeyPack &keypack) {
            std::string buffer = blob;
            std::istringstream is(buffer, std::ios::binary);
            evi::Utils::deserializeKeyFiles(is, seckey, keypack);
        },
        py::arg("data"), py::arg("secret_key"), py::arg("key_pack"));
}
