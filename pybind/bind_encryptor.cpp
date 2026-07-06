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

py::list serialize_rows_to_bytes(const std::vector<std::string> &rows) {
    py::list out;
    for (const auto &row : rows) {
        out.append(py::bytes(row.data(), row.size()));
    }
    return out;
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
            [](Encryptor &self, const std::vector<float> &data, EncodeType type, std::optional<uint32_t> level,
               std::optional<float> scale) {
                return self.encode(data, type, level, scale);
            },
            py::arg("data"), py::arg("type"), py::arg("level") = py::none(), py::arg("scale") = py::none())

        .def(
            "encode_bulk",
            [](Encryptor &self, const std::vector<std::vector<float>> &msg, const EncodeType type,
               std::optional<uint32_t> level, std::optional<float> scale) {
                return self.encode(msg, type, level, scale);
            },
            py::arg("data"), py::arg("type"), py::arg("level") = py::none(), py::arg("scale") = py::none())

        .def(
            "encrypt",
            [](Encryptor &self, const std::vector<float> &data, const std::string &enckey_path, EncodeType type,
               std::optional<uint32_t> level, std::optional<float> scale) {
                return self.encrypt(data, enckey_path, type, level, scale);
            },
            py::arg("data"), py::arg("enckey_path"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def(
            "encrypt",
            [](Encryptor &self, const std::vector<float> &data, const KeyPack &keypack, EncodeType type,
               std::optional<uint32_t> level, std::optional<float> scale) {
                return self.encrypt(data, keypack, type, level, scale);
            },
            py::arg("data"), py::arg("keypack"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def(
            "encrypt_with_key_stream",
            [](Encryptor &self, const std::vector<float> &data, const py::object &key_blob, EncodeType type,
               std::optional<uint32_t> level, std::optional<float> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::istringstream key_stream(blob, std::ios::binary);
                return self.encrypt(data, key_stream, type, level, scale);
            },
            py::arg("data"), py::arg("key_blob"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        // call_guard releases the GIL for the native bulk encrypt (after argument
        // conversion, reacquired before return-value conversion), matching the
        // encrypt_row bindings below so bulk encryption can scale across threads.
        .def("encrypt_bulk",
             py::overload_cast<const std::vector<std::vector<float>> &, const std::string &, evi::EncodeType,
                               std::optional<uint32_t>, std::optional<float>>(&Encryptor::encrypt, py::const_),
             py::arg("data"), py::arg("enckey_path"), py::arg("type"), py::arg("level") = py::none(),
             py::arg("scale") = py::none(), py::call_guard<py::gil_scoped_release>())

        .def("encrypt_bulk",
             py::overload_cast<const std::vector<std::vector<float>> &, const KeyPack &, evi::EncodeType,
                               std::optional<uint32_t>, std::optional<float>>(&Encryptor::encrypt, py::const_),
             py::arg("data"), py::arg("keypack"), py::arg("type"), py::arg("level") = py::none(),
             py::arg("scale") = py::none(), py::call_guard<py::gil_scoped_release>())

        .def(
            "encrypt_row",
            [](Encryptor &self, const std::vector<std::vector<float>> &data, const std::string &enckey_path,
               EncodeType type, std::optional<uint32_t> level, std::optional<float> scale) {
                std::vector<std::string> raw;
                {
                    py::gil_scoped_release release;
                    raw = self.encryptRow(data, enckey_path, type, level, scale);
                }
                return serialize_rows_to_bytes(raw);
            },
            py::arg("data"), py::arg("enckey_path"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def(
            "encrypt_row",
            [](Encryptor &self, const std::vector<std::vector<float>> &data, const KeyPack &keypack, EncodeType type,
               std::optional<uint32_t> level, std::optional<float> scale) {
                std::vector<std::string> raw;
                {
                    py::gil_scoped_release release;
                    raw = self.encryptRow(data, keypack, type, level, scale);
                }
                return serialize_rows_to_bytes(raw);
            },
            py::arg("data"), py::arg("keypack"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def(
            "encrypt_row_with_key_stream",
            [](Encryptor &self, const std::vector<std::vector<float>> &data, const py::object &key_blob,
               EncodeType type, std::optional<uint32_t> level, std::optional<float> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::vector<std::string> raw;
                {
                    py::gil_scoped_release release;
                    std::istringstream key_stream(blob, std::ios::binary);
                    raw = self.encryptRow(data, key_stream, type, level, scale);
                }
                return serialize_rows_to_bytes(raw);
            },
            py::arg("data"), py::arg("key_blob"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def(
            "encrypt_bulk_with_key_stream",
            [](Encryptor &self, const std::vector<std::vector<float>> &data, const py::object &key_blob,
               EncodeType type, std::optional<uint32_t> level, std::optional<float> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                // Release the GIL only after the py::object is consumed above.
                py::gil_scoped_release release;
                std::istringstream key_stream(blob, std::ios::binary);
                return self.encrypt(data, key_stream, type, level, scale);
            },
            py::arg("data"), py::arg("key_blob"), py::arg("type"), py::arg("level") = py::none(),
            py::arg("scale") = py::none())

        .def("__repr__", [](const Encryptor &) {
            return std::string("<evi.Encryptor>");
        });
}
