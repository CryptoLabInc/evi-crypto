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

#include <memory>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "EVI/Context.hpp"
#include "EVI/Enums.hpp"

namespace py = pybind11;
using namespace evi;

void bind_context(py::module_ &m) {
    py::class_<evi::Context>(m, "Context")
        .def(py::init([](evi::ParameterPreset preset, evi::DeviceType device_type, std::uint64_t dim,
                         evi::EvalMode eval_mode, std::optional<int> device_id) {
                 return evi::makeContext(preset, device_type, dim, eval_mode, device_id);
             }),
             py::arg("preset"), py::arg("device_type"), py::arg("dim"), py::arg("eval_mode"),
             py::arg("device_id") = py::none())
        .def("__repr__", [](const evi::Context &) {
            return std::string("<evi.Context>");
        });

    // ----- Multi-context factory -----
    m.def(
        "make_multi_context",
        [](evi::ParameterPreset preset, evi::DeviceType device_type, evi::EvalMode eval_mode,
           std::optional<int> device_id) {
            return evi::makeMultiContext(preset, device_type, eval_mode, device_id);
        },
        py::arg("preset"), py::arg("device_type"), py::arg("eval_mode"), py::arg("device_id") = py::none(),
        py::return_value_policy::move);
}
