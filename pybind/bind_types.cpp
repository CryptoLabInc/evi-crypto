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

#include "EVI/Enums.hpp"
#include "EVI/Message.hpp"
#include "EVI/Query.hpp"
#include "EVI/SealInfo.hpp"
#include "EVI/SearchResult.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstring>
#include <sstream>

namespace py = pybind11;
using namespace evi;

void bind_types(py::module_ &m) {

    m.attr("AES256_KEY_SIZE") = py::int_(evi::AES256_KEY_SIZE);

    py::enum_<ParameterPreset>(m, "ParameterPreset", py::arithmetic())
        .value("RUNTIME", ParameterPreset::RUNTIME)
        .value("QF0", ParameterPreset::QF0)
        .value("QF1", ParameterPreset::QF1)
        .value("QF2", ParameterPreset::QF2)
        .value("QF3", ParameterPreset::QF3)
        .value("IP0", ParameterPreset::IP0)
        .value("IP1", ParameterPreset::IP1)
        .export_values();

    py::enum_<evi::SealMode>(m, "SealMode")
        .value("AES_KEK", SealMode::AES_KEK)
        .value("NONE", SealMode::NONE)
        .export_values();

    py::enum_<EvalMode>(m, "EvalMode")
        .value("RMP", EvalMode::RMP)
        .value("MM", EvalMode::MM)
        .value("RMS", EvalMode::RMS)
        .value("MS", EvalMode::MS)
        .value("FLAT", EvalMode::FLAT)
        .export_values();

    py::enum_<DeviceType>(m, "DeviceType")
        .value("CPU", DeviceType::CPU)
        .value("GPU", DeviceType::GPU)
        .value("AVX2", DeviceType::AVX2)
        .export_values();

    py::enum_<DataType>(m, "DataType")
        .value("CIPHER", DataType::CIPHER)
        .value("PLAIN", DataType::PLAIN)
        .value("SERIALIZED_CIPHER", DataType::SERIALIZED_CIPHER)
        .value("SERIALIZED_PLAIN", DataType::SERIALIZED_PLAIN)
        .export_values();

    py::enum_<BatchType>(m, "BatchType")
        .value("ISOLATED", BatchType::ISOLATED)
        .value("BROADCAST", BatchType::BROADCAST)
        .export_values();

    py::enum_<ErrorCode>(m, "ErrorCode", py::arithmetic())
        .value("UNDEFINED", ErrorCode::UNDEFINED)
        .value("FAIL", ErrorCode::FAIL)
        .value("OK", ErrorCode::OK)
        .value("INVALID_ARGUMENT_ERROR", ErrorCode::INVALID_ARGUMENT_ERROR)
        .value("OUT_OF_INDEX_ERROR", ErrorCode::OUT_OF_INDEX_ERROR)
        .value("NOT_FOUND_ERROR", ErrorCode::NOT_FOUND_ERROR)
        .export_values();

    py::enum_<EncodeType>(m, "EncodeType", py::arithmetic())
        .value("ITEM", EncodeType::ITEM)
        .value("QUERY", EncodeType::QUERY)
        .export_values();

    py::class_<evi::SealInfo>(m, "SealInfo")
        .def(py::init<evi::SealMode>(), py::arg("mode"))
        .def(py::init([](evi::SealMode mode, const std::vector<uint8_t> &aes_key) {
                 return evi::SealInfo(mode, aes_key);
             }),
             py::arg("mode"), py::arg("aes_key"))
        .def_property_readonly("mode", &evi::SealInfo::getSealMode)
        .def("__repr__", [](const evi::SealInfo &s) {
            return "<evi.SealInfo mode=" + std::to_string(static_cast<int>(s.getSealMode())) + ">";
        });

    py::class_<Query>(m, "Query")
        .def("size", &Query::size)
        .def("getInnerItemCount", &Query::getInnerItemCount)
        .def_static("serializeTo",
                    [](const Query &q) {
                        std::ostringstream os(std::ios::binary);
                        Query::serializeTo(q, os);
                        const std::string &s = os.str();
                        return py::bytes(s.data(), s.size());
                    })
        .def_static("deserializeFrom", [](py::bytes b) {
            std::string s = b;
            std::istringstream is(s, std::ios::binary);
            return Query::deserializeFrom(is);
        });

    py::class_<Message>(m, "Message", py::buffer_protocol())
        .def(py::init<>())
        .def("resize", &Message::resize, py::arg("n"))
        .def("reserve", &Message::reserve, py::arg("n"))
        .def("clear", &Message::clear)
        .def("push_back", &Message::push_back, py::arg("value"))
        .def("emplace_back", &Message::emplace_back, py::arg("value"))
        .def(
            "extend",
            [](Message &self, const std::vector<float> &vals) {
                if (!vals.empty()) {
                    auto old = self.size();
                    self.resize(old + vals.size());
                    std::memcpy(self.data() + old, vals.data(), vals.size() * sizeof(float));
                }
            },
            py::arg("values"))
        .def_buffer([](Message &self) -> py::buffer_info {
            return py::buffer_info(self.data(), sizeof(float), py::format_descriptor<float>::format(), 1, {self.size()},
                                   {sizeof(float)});
        })
        .def("__len__", &Message::size)
        .def("__getitem__",
             [](const Message &self, py::ssize_t i) {
                 const auto n = static_cast<py::ssize_t>(self.size());
                 if (i < 0)
                     i += n;
                 if (i < 0 || i >= n)
                     throw py::index_error("index out of range");
                 return self.data()[i];
             })
        .def("__getitem__",
             [](const Message &self, py::slice slice) {
                 size_t start, stop, step, slicelen;
                 if (!slice.compute(self.size(), &start, &stop, &step, &slicelen))
                     throw py::error_already_set();
                 py::list out(slicelen);
                 for (size_t i = 0, idx = start; i < slicelen; ++i, idx += step)
                     out[py::ssize_t(i)] = self.data()[idx];
                 return out;
             })
        .def(
            "__iter__",
            [](const Message &self) {
                return py::make_iterator(self.data(), self.data() + self.size());
            },
            py::keep_alive<0, 1>())
        .def("__repr__", [](const Message &self) {
            return "<evi.Message size=" + std::to_string(self.size()) + ">";
        });

    py::class_<evi::SearchResult>(m, "SearchResult")
        .def(py::init<>())
        .def("get_item_count", &evi::SearchResult::getItemCount)
        .def_static(
            "serializeTo",
            [](const evi::SearchResult &res) {
                std::ostringstream os(std::ios::binary);
                evi::SearchResult::serializeTo(res, os);
                const std::string &s = os.str();
                return py::bytes(s.data(), s.size());
            },
            py::arg("res"))
        .def_static(
            "deserializeFrom",
            [](py::bytes b) {
                std::string s = b;
                std::istringstream is(s, std::ios::binary);
                return evi::SearchResult::deserializeFrom(is);
            },
            py::arg("data"))
        .def("__repr__", [](const evi::SearchResult &) {
            return std::string("<evi.SearchResult>");
        });
}
