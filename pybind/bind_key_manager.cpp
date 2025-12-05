////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
// This software and/or source code may be commercially used and/or           //
// disseminated only with the written permission of CryptoLab Inc,            //
// or in accordance with the terms and conditions stipulated in the           //
// agreement/contract under which the software and/or source code has been    //
// supplied by CryptoLab Inc. Any unauthorized commercial use and/or          //
// dissemination of this file is strictly prohibited and will constitute      //
// an infringement of copyright.                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "km/Enums.hpp"
#include "km/KeyEnvelope.hpp"
#include "km/KeyManager.hpp"
#include "km/ProviderMeta.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <sstream>
#include <string>

namespace py = pybind11;
using namespace evi;

namespace {

std::istringstream bytesToStream(const py::bytes &blob) {
    std::string buffer = blob;
    return std::istringstream(buffer, std::ios::binary);
}

py::bytes streamToBytes(std::ostringstream &oss) {
    const std::string buffer = oss.str();
    return py::bytes(buffer);
}

} // namespace

void bind_key_manager(py::module_ &m) {
    // ----- Enums -----
    py::enum_<KeyFormatVersion>(m, "KeyFormatVersion", py::arithmetic())
        .value("V1", KeyFormatVersion::V1)
        .value("LATEST", KeyFormatVersion::Latest)
        .export_values();

    py::enum_<ProviderType>(m, "ProviderType").value("LOCAL", ProviderType::Local).export_values();

    // ----- Provider metadata -----
    py::class_<LocalProviderMeta>(m, "LocalProviderMeta")
        .def(py::init<>())
        .def_readwrite("type", &LocalProviderMeta::type)
        .def_readwrite("provider_version", &LocalProviderMeta::provider_version)
        .def_readwrite("version_id", &LocalProviderMeta::version_id)
        .def_readwrite("wrap_alg", &LocalProviderMeta::wrap_alg);

    py::class_<ProviderMeta>(m, "ProviderMeta")
        .def(py::init<>())
        .def(py::init<const LocalProviderMeta &>())
        .def_static("make_local", &ProviderMeta::makeLocal, py::arg("meta"))
        .def_property_readonly("type",
                               [](const ProviderMeta &self) {
                                   return self.type;
                               })
        .def("as_local",
             [](ProviderMeta &self) {
                 auto *meta = self.asLocal();
                 if (!meta) {
                     throw py::value_error("ProviderMeta does not contain LocalProviderMeta");
                 }
                 return *meta;
             })
        .def("__repr__", [](const ProviderMeta &self) {
            return std::string("<evi.ProviderMeta type=") +
                   (self.type == ProviderType::Local ? "LOCAL>" : "AWS_SECRET_MANAGER>");
        });

    // ----- Provider envelope content -----
    py::class_<detail::KeyEntryParameter>(m, "KeyEntryParameter")
        .def(py::init<>())
        .def_readwrite("P", &detail::KeyEntryParameter::P)
        .def_readwrite("Q", &detail::KeyEntryParameter::Q)
        .def_readwrite("DB_SCALE_FACTOR", &detail::KeyEntryParameter::DB_SCALE_FACTOR)
        .def_readwrite("QUERY_SCALE_FACTOR", &detail::KeyEntryParameter::QUERY_SCALE_FACTOR)
        .def_readwrite("preset", &detail::KeyEntryParameter::preset);

    py::class_<detail::KeyEntryMetadata>(m, "KeyEntryMetadata")
        .def(py::init<>())
        .def_readwrite("parameter", &detail::KeyEntryMetadata::parameter)
        .def_readwrite("eval_mode", &detail::KeyEntryMetadata::eval_mode)
        .def_readwrite("dim", &detail::KeyEntryMetadata::dim);

    py::class_<ProviderEntry>(m, "ProviderEntry")
        .def(py::init<>())
        .def_readwrite("name", &ProviderEntry::name)
        .def_readwrite("format_version", &ProviderEntry::format_version)
        .def_readwrite("role", &ProviderEntry::role)
        .def_readwrite("hash", &ProviderEntry::hash)
        .def_readwrite("metadata", &ProviderEntry::metadata)
        .def_readwrite("key_data", &ProviderEntry::key_data)
        .def_readwrite("alg", &ProviderEntry::alg)
        .def_readwrite("iv", &ProviderEntry::iv)
        .def_readwrite("tag", &ProviderEntry::tag);

    py::class_<ProviderEnvelope>(m, "ProviderEnvelope")
        .def(py::init<>())
        .def_readwrite("provider_meta", &ProviderEnvelope::provider_meta)
        .def_readwrite("entries", &ProviderEnvelope::entries);

    // ----- KeyManager -----
    py::class_<KeyManager>(m, "KeyManager")
        .def(py::init([]() {
            return makeKeyManager();
        }))
        .def(py::init([](const ProviderMeta &provider_meta) {
                 return makeKeyManager(provider_meta);
             }),
             py::arg("provider_meta"))
        .def("wrap_sec_key",
             py::overload_cast<const std::string &, const std::string &, const std::string &>(&KeyManager::wrapSecKey),
             py::arg("key_id"), py::arg("key_path"), py::arg("output_path"))
        .def(
            "unwrap_sec_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path) {
                self.unwrapSecKey(envelope_path, output_path, std::nullopt);
            },
            py::arg("envelope_path"), py::arg("output_path"))
        .def(
            "unwrap_sec_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path,
               const SealInfo &seal_info) {
                self.unwrapSecKey(envelope_path, output_path, std::optional<SealInfo>(seal_info));
            },
            py::arg("envelope_path"), py::arg("output_path"), py::arg("seal_info"))
        .def("wrap_enc_key",
             py::overload_cast<const std::string &, const std::string &, const std::string &>(&KeyManager::wrapEncKey),
             py::arg("key_id"), py::arg("key_path"), py::arg("output_path"))
        .def("unwrap_enc_key", py::overload_cast<const std::string &, const std::string &>(&KeyManager::unwrapEncKey),
             py::arg("envelope_path"), py::arg("output_path"))
        .def("wrap_eval_key",
             py::overload_cast<const std::string &, const std::string &, const std::string &>(&KeyManager::wrapEvalKey),
             py::arg("key_id"), py::arg("key_path"), py::arg("output_path"))
        .def("unwrap_eval_key", py::overload_cast<const std::string &, const std::string &>(&KeyManager::unwrapEvalKey),
             py::arg("envelope_path"), py::arg("output_path"))
        // Stream/bytes helpers for in-memory wrapping/unwrapping
        .def(
            "wrap_sec_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapSecKey(key_id, key_stream, out);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"))
        .def(
            "wrap_enc_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapEncKey(key_id, key_stream, out);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"))
        .def(
            "wrap_eval_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapEvalKey(key_id, key_stream, out);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"))
        .def(
            "unwrap_sec_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapSecKey(envelope_stream, out, std::nullopt);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def(
            "unwrap_sec_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob, const SealInfo &seal_info) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapSecKey(envelope_stream, out, std::optional<SealInfo>(seal_info));
                return streamToBytes(out);
            },
            py::arg("envelope_blob"), py::arg("seal_info"))
        .def(
            "unwrap_enc_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapEncKey(envelope_stream, out);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def(
            "unwrap_eval_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapEvalKey(envelope_stream, out);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def("wrap_keys", py::overload_cast<const std::string &, const std::string &>(&KeyManager::wrapKeys),
             py::arg("key_id"), py::arg("key_dir_path"))
        .def("unwrap_keys", py::overload_cast<const std::string &, const std::string &>(&KeyManager::unwrapKeys),
             py::arg("envelope_dir_path"), py::arg("output_dir_path"))
        .def("__repr__", [](const KeyManager &) {
            return std::string("<evi.KeyManager>");
        });
}
