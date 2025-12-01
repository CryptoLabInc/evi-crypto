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
#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include <iostream>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <fstream>
#include <sstream>

namespace py = pybind11;
using namespace evi;

static std::istringstream bytes_to_iss(const py::bytes &b) {
    std::string s = b;
    return std::istringstream(s);
}

void bind_keypack(py::module_ &m) {
    // ===========================
    // SecretKey
    // ===========================
    py::class_<SecretKey>(m, "SecretKey")
        .def(py::init([](const Context &ctx) {
                 return makeSecKey(ctx);
             }),
             py::arg("context"), py::keep_alive<1, 2>())

        .def(py::init([](const std::string &path) {
                 return makeSecKey(path, std::nullopt);
             }),
             py::arg("path"))

        .def(py::init([](const py::bytes &key_blob, const SealInfo &s) {
                 auto key_stream = bytes_to_iss(key_blob);
                 return makeSecKey(key_stream, std::optional<SealInfo>(s));
             }),
             py::arg("key_blob"), py::arg("seal_info"))

        .def(py::init([](const std::string &path, const SealInfo &s) {
                 return makeSecKey(path, std::optional<SealInfo>(s));
             }),
             py::arg("path"), py::arg("seal_info"))

        .def("__repr__", [](const SecretKey &) {
            return std::string("<evi.SecretKey>");
        });

    // ===========================
    // KeyPack
    // ===========================
    py::class_<KeyPack>(m, "KeyPack")
        .def(py::init([](const Context &ctx) {
                 return makeKeyPack(ctx);
             }),
             py::arg("context"), py::keep_alive<1, 2>())

        .def(py::init([](const Context &ctx, const std::string &dir_path) {
                 std::string path_copy = dir_path;
                 return makeKeyPack(ctx, path_copy);
             }),
             py::arg("context"), py::arg("dir_path"), py::keep_alive<1, 2>())

        .def("save_enc_key_file", py::overload_cast<const std::string &>(&KeyPack::saveEncKey), py::arg("dir_path"))
        .def(
            "load_enc_key_stream",
            [](KeyPack &self, const py::bytes &key_blob) {
                std::istringstream key_stream = bytes_to_iss(key_blob);
                self.loadEncKey(key_stream);
            },
            py::arg("key_blob"))
        .def(
            "load_enc_key_stream",
            [](KeyPack &self, const std::string &key_blob) {
                std::istringstream key_stream(key_blob, std::ios::binary);
                self.loadEncKey(key_stream);
            },
            py::arg("key_blob"))
        .def("load_enc_key_file", py::overload_cast<const std::string &>(&KeyPack::loadEncKey), py::arg("file_path"))
        .def("save_eval_key_file", py::overload_cast<const std::string &>(&KeyPack::saveEvalKey), py::arg("dir_path"))
        .def(
            "load_eval_key_stream",
            [](KeyPack &self, const py::bytes &key_blob) {
                std::istringstream key_stream = bytes_to_iss(key_blob);
                self.loadEvalKey(key_stream);
            },
            py::arg("key_blob"))
        .def(
            "load_eval_key_stream",
            [](KeyPack &self, const std::string &key_blob) {
                std::istringstream key_stream(key_blob, std::ios::binary);
                self.loadEvalKey(key_stream);
            },
            py::arg("key_blob"))
        .def("load_eval_key_file", py::overload_cast<const std::string &>(&KeyPack::loadEvalKey), py::arg("file_path"))
        .def("__repr__", [](const KeyPack &) {
            return std::string("<evi.KeyPack>");
        });
}
