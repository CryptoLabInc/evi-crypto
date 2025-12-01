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

// pybind/bind_decryptor.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <memory>
#include <sstream>
#include <utility>

#include "EVI/Context.hpp"
#include "EVI/Decryptor.hpp"
#include "EVI/Enums.hpp"
#include "EVI/Message.hpp"
#include "EVI/Query.hpp"
#include "EVI/SearchResult.hpp"
#include "EVI/SecretKey.hpp"

namespace py = pybind11;
using namespace evi;

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

void bind_decryptor(py::module_ &m) {
    py::class_<Decryptor>(m, "Decryptor")
        .def(py::init([](const Context &ctx) {
                 return makeDecryptor(ctx);
             }),
             py::arg("context"), py::keep_alive<1, 2>())

        // ---- SearchResult ----
        .def(
            "decrypt",
            [](Decryptor &self, const SearchResult &item, const SecretKey &key) {
                return self.decrypt(item, key);
            },
            py::arg("item"), py::arg("secret_key"))

        .def(
            "decrypt",
            [](Decryptor &self, const SearchResult &item, const SecretKey &key, bool is_score,
               std::optional<double> scale) {
                return self.decrypt(item, key, is_score, scale);
            },
            py::arg("item"), py::arg("secret_key"), py::arg("is_score"), py::arg("scale") = py::none())

        .def(
            "decrypt",
            [](Decryptor &self, const SearchResult &item, const std::string &key_path, bool is_score,
               std::optional<double> scale) {
                return self.decrypt(item, key_path, is_score, scale);
            },
            py::arg("item"), py::arg("key_path"), py::arg("is_score"), py::arg("scale") = py::none())

        .def(
            "decrypt_with_key_stream",
            [](Decryptor &self, const SearchResult &item, const py::object &key_blob, bool is_score,
               std::optional<double> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::istringstream key_stream(blob, std::ios::binary);
                return self.decrypt(item, key_stream, is_score, scale);
            },
            py::arg("item"), py::arg("key_blob"), py::arg("is_score"), py::arg("scale") = py::none())

        // ---- Query ----
        .def(
            "decrypt",
            [](Decryptor &self, const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
                return self.decrypt(ctxt, key, scale);
            },
            py::arg("query"), py::arg("secret_key"), py::arg("scale") = py::none())
        .def(
            "decrypt",
            [](Decryptor &self, const Query &ctxt, const std::string &key_path, std::optional<double> scale) {
                return self.decrypt(ctxt, key_path, scale);
            },
            py::arg("query"), py::arg("key_path"), py::arg("scale") = py::none())

        .def(
            "decrypt_query_with_key_stream",
            [](Decryptor &self, const Query &ctxt, const py::object &key_blob, std::optional<double> scale) {
                std::string blob = bytes_like_to_string(key_blob);
                std::istringstream key_stream(blob, std::ios::binary);
                return self.decrypt(ctxt, key_stream, scale);
            },
            py::arg("query"), py::arg("key_blob"), py::arg("scale") = py::none())

        .def(
            "decrypt",
            [](Decryptor &self, int idx, const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
                return self.decrypt(idx, ctxt, key, scale);
            },
            py::arg("index"), py::arg("query"), py::arg("secret_key"), py::arg("scale") = py::none())

        .def("__repr__", [](const Decryptor &) {
            return std::string("<evi.Decryptor>");
        });
}
