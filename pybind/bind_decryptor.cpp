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
#include "utils/security/Security.hpp"

namespace py = pybind11;
using namespace evi;
using evi::security::SensitiveDataGuard;

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
                SensitiveDataGuard guard(blob);
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
                SensitiveDataGuard guard(blob);
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

        // ---- bulk decrypt + topk ----
        .def(
            "decrypt_batch_topk_parallel",
            [](Decryptor &self, const std::vector<py::object> &shard_blobs_py, const py::object &key_blob_py, int k,
               std::optional<double> scale, int n_jobs) {
                std::string key_blob = bytes_like_to_string(key_blob_py);
                SensitiveDataGuard guard(key_blob);

                std::vector<std::string> shard_strings;
                shard_strings.reserve(shard_blobs_py.size());
                for (const auto &s : shard_blobs_py)
                    shard_strings.push_back(bytes_like_to_string(s));

                std::vector<const char *> ptrs;
                std::vector<std::size_t> lens;
                ptrs.reserve(shard_strings.size());
                lens.reserve(shard_strings.size());
                for (const auto &s : shard_strings) {
                    ptrs.push_back(s.data());
                    lens.push_back(s.size());
                }

                return self.decryptBatchTopKParallel(ptrs.data(), lens.data(), ptrs.size(), key_blob.data(),
                                                     key_blob.size(), k, scale, n_jobs);
            },
            py::arg("shard_blobs"), py::arg("key_blob"), py::arg("k"), py::arg("scale") = py::none(),
            py::arg("n_jobs") = 1)

        .def("__repr__", [](const Decryptor &) {
            return std::string("<evi.Decryptor>");
        });
}
