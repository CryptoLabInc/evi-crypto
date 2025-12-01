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

// pybind/bind_encryptor.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <sstream>

#include "EVI/Context.hpp"
#include "EVI/Encryptor.hpp"
#include "EVI/Enums.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/Query.hpp"

namespace py = pybind11;
using namespace evi;

namespace {
std::string bytes_like_to_string(const py::object &obj) {
    if (!PyObject_CheckBuffer(obj.ptr())) {
        throw py::type_error("expected a bytes-like object");
    }
    py::buffer buf(obj);
    py::buffer_info info = buf.request();
    if (info.itemsize != 1) {
        throw py::type_error("buffer must be byte-addressable");
    }
    const char *begin = static_cast<const char *>(info.ptr);
    const auto length = static_cast<size_t>(info.size);
    return std::string(begin, begin + length);
}
} // namespace

void bind_encryptor(py::module_ &m) {
    py::class_<Encryptor>(m, "Encryptor")
        .def(py::init([](const Context &ctx) {
                 return makeEncryptor(ctx);
             }),
             py::arg("context"), py::keep_alive<1, 2>())

        .def(
            "encode",
            [](Encryptor &self, const std::vector<float> &data, EncodeType type, int level,
               std::optional<float> scale) {
                return self.encode(data, type, level, scale);
            },
            py::arg("data"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def(
            "encode_bulk",
            [](Encryptor &self, const std::vector<std::vector<float>> &msg, const EncodeType type, const int level,
               std::optional<float> scale) {
                return self.encode(msg, type, level, scale);
            },
            py::arg("data"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def(
            "encrypt",
            [](Encryptor &self, const std::vector<float> &data, const std::string &enckey_path, EncodeType type,
               int level, std::optional<float> scale) {
                return self.encrypt(data, enckey_path, type, level, scale);
            },
            py::arg("data"), py::arg("enckey_path"), py::arg("type"), py::arg("level") = 0,
            py::arg("scale") = py::none())

        .def(
            "encrypt",
            [](Encryptor &self, const std::vector<float> &data, const KeyPack &keypack, EncodeType type, int level,
               std::optional<float> scale) {
                return self.encrypt(data, keypack, type, level, scale);
            },
            py::arg("data"), py::arg("keypack"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def(
            "encrypt_with_key_stream",
            [](Encryptor &self, const std::vector<float> &data, const py::object &key_blob, EncodeType type, int level,
               std::optional<float> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::istringstream key_stream(blob, std::ios::binary);
                return self.encrypt(data, key_stream, type, level, scale);
            },
            py::arg("data"), py::arg("key_blob"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def("encrypt_bulk",
             py::overload_cast<const std::vector<std::vector<float>> &, const std::string &, evi::EncodeType, int,
                               std::optional<float>>(&Encryptor::encrypt, py::const_),
             py::arg("data"), py::arg("enckey_path"), py::arg("type"), py::arg("level") = 0,
             py::arg("scale") = py::none())

        .def("encrypt_bulk",
             py::overload_cast<const std::vector<std::vector<float>> &, const KeyPack &, evi::EncodeType, int,
                               std::optional<float>>(&Encryptor::encrypt, py::const_),
             py::arg("data"), py::arg("keypack"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def(
            "encrypt_bulk_with_key_stream",
            [](Encryptor &self, const std::vector<std::vector<float>> &data, const py::object &key_blob,
               EncodeType type, int level, std::optional<float> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::istringstream key_stream(blob, std::ios::binary);
                return self.encrypt(data, key_stream, type, level, scale);
            },
            py::arg("data"), py::arg("key_blob"), py::arg("type"), py::arg("level") = 0, py::arg("scale") = py::none())

        .def("__repr__", [](const Encryptor &) {
            return std::string("<evi.Encryptor>");
        });
}
