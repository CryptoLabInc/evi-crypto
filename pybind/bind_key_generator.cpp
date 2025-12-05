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

#include <pybind11/numpy.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <sstream>

#include "EVI/Enums.hpp"
#include "EVI/KeyGenerator.hpp"
#include "EVI/SealInfo.hpp"

namespace py = pybind11;
using namespace evi;

static inline std::optional<std::vector<uint8_t>> to_opt_bytes_vec(const py::object &obj) {
    if (obj.is_none())
        return std::nullopt;

    if (py::isinstance<py::bytes>(obj) || py::isinstance<py::bytearray>(obj)) {
        std::string s = obj.cast<std::string>(); // contiguous
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    return obj.cast<std::vector<uint8_t>>();
}

void bind_key_generator(py::module_ &m) {
    // =========================
    //        KeyGenerator
    // =========================
    py::class_<KeyGenerator>(m, "KeyGenerator")
        .def(py::init([](const Context &ctx, KeyPack &pack, py::object seed_obj) {
                 auto seed = to_opt_bytes_vec(seed_obj);
                 return makeKeyGenerator(ctx, pack, std::move(seed));
             }),
             py::arg("context"), py::arg("key_pack"), py::arg("seed") = py::none(), py::keep_alive<1, 2>(),
             py::keep_alive<1, 3>())

        .def(py::init([](const Context &ctx, py::object seed_obj) {
                 auto seed = to_opt_bytes_vec(seed_obj);
                 return makeKeyGenerator(ctx, std::move(seed));
             }),
             py::arg("context"), py::arg("seed") = py::none(), py::keep_alive<1, 2>())

        .def("gen_sec_key", &KeyGenerator::genSecKey)
        .def("gen_pub_keys", &KeyGenerator::genPubKeys, py::arg("secret_key"));

    // =========================
    //     MultiKeyGenerator
    // =========================
    py::class_<MultiKeyGenerator>(m, "MultiKeyGenerator")
        .def(py::init([](const std::vector<Context> &contexts, const std::string &store_path, SealInfo &s_info,
                         py::object seed_obj) {
                 auto seed = to_opt_bytes_vec(seed_obj);
                 return MultiKeyGenerator(contexts, store_path, s_info, std::move(seed));
             }),
             py::arg("contexts"), py::arg("store_path"), py::arg("seal_info"), py::arg("seed") = py::none(),
             py::keep_alive<1, 2>(), py::keep_alive<1, 3>(), py::keep_alive<1, 4>())

        .def("check_file_exist", &MultiKeyGenerator::checkFileExist)
        .def("generate_keys", static_cast<SecretKey (MultiKeyGenerator::*)()>(&MultiKeyGenerator::generateKeys))
        .def("generate_keys_stream",
             [](MultiKeyGenerator &self) {
                 std::ostringstream os(std::ios::binary);
                 auto secret = self.generateKeys(os);
                 return py::make_tuple(secret, py::bytes(os.str()));
             })
        .def("generate_keys_per_stream", [](MultiKeyGenerator &self) {
            std::ostringstream sec(std::ios::binary);
            std::ostringstream enc(std::ios::binary);
            std::ostringstream eval(std::ios::binary);
            auto secret = self.generateKeys(sec, enc, eval);
            return py::make_tuple(secret, py::bytes(sec.str()), py::bytes(enc.str()), py::bytes(eval.str()));
        });
}
