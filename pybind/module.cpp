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

#include <filesystem>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

void bind_types(py::module_ &m);
void bind_context(py::module_ &m);
void bind_keypack(py::module_ &m);
void bind_key_generator(py::module_ &m);
void bind_encryptor(py::module_ &m);
void bind_decryptor(py::module_ &m);
void bind_utils(py::module_ &m);

PYBIND11_MODULE(evi, m) {
    py::class_<std::filesystem::path>(m, "Path").def(py::init<std::string>());
    py::implicitly_convertible<std::string, std::filesystem::path>();

    m.doc() = "Binding EVI with Python via pybind11";

    bind_context(m);
    bind_types(m);
    bind_keypack(m);
    bind_key_generator(m);
    bind_encryptor(m);
    bind_decryptor(m);
    bind_utils(m);
}
