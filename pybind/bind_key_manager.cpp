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

#include "km/KeyEnvelope.hpp"
#include "km/KeyManager.hpp"
#include "km/KeyStorageConfig.hpp"
#include "utils/security/Security.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <sstream>
#include <string>

namespace py = pybind11;
using namespace evi;
using evi::security::SensitiveDataGuard;
using evi::security::wipeBuffer;

namespace {

std::istringstream bytesToStream(const py::bytes &blob) {
    std::string buffer = blob;
    return std::istringstream(buffer, std::ios::binary);
}

py::bytes streamToBytes(std::ostringstream &oss) {
    std::string buffer = oss.str();
    py::bytes out(buffer.data(), buffer.size());
    wipeBuffer(buffer);
    return out;
}

} // namespace

void bind_key_manager(py::module_ &m) {
    // ----- Enums -----
    py::enum_<KeyFormatVersion>(m, "KeyFormatVersion", py::arithmetic())
        .value("V1", KeyFormatVersion::V1)
        .value("LATEST", KeyFormatVersion::Latest)
        .export_values();

    py::enum_<ProviderType>(m, "ProviderType")
        .value("LOCAL", ProviderType::Local)
        .value("VAULT", ProviderType::Vault)
        .value("AWS", ProviderType::Aws)
        .value("GCP", ProviderType::Gcp)
        .export_values();

    // ----- Provider config -----
    py::class_<LocalConfig>(m, "LocalConfig")
        .def(py::init<>())
        .def_readwrite("type", &LocalConfig::type)
        .def_readwrite("provider_version", &LocalConfig::provider_version)
        .def_readwrite("version_id", &LocalConfig::version_id)
        .def_readwrite("wrap_alg", &LocalConfig::wrap_alg);

    py::class_<VaultConfig>(m, "VaultConfig")
        .def(py::init<>())
        .def_readwrite("type", &VaultConfig::type)
        .def_readwrite("provider_version", &VaultConfig::provider_version)
        .def_readwrite("version_id", &VaultConfig::version_id)
        .def_readwrite("address", &VaultConfig::address)
        .def_readwrite("token_env", &VaultConfig::token_env)
        .def_readwrite("kv_mount", &VaultConfig::kv_mount)
        .def_readwrite("namespace", &VaultConfig::name_space)
        .def_readwrite("tls_skip_verify", &VaultConfig::tls_skip_verify);

    py::class_<AwsConfig>(m, "AwsConfig")
        .def(py::init<>())
        .def_readwrite("type", &AwsConfig::type)
        .def_readwrite("provider_version", &AwsConfig::provider_version)
        .def_readwrite("version_id", &AwsConfig::version_id)
        .def_readwrite("region", &AwsConfig::region)
        .def_readwrite("bucket_name", &AwsConfig::bucket_name)
        .def_readwrite("access_key_env", &AwsConfig::access_key_env)
        .def_readwrite("secret_key_env", &AwsConfig::secret_key_env)
        .def_readwrite("session_token_env", &AwsConfig::session_token_env)
        .def_readwrite("endpoint", &AwsConfig::endpoint)
        .def_readwrite("force_path_style", &AwsConfig::force_path_style)
        .def_readwrite("tls_skip_verify", &AwsConfig::tls_skip_verify);

    py::class_<GcpConfig>(m, "GcpConfig")
        .def(py::init<>())
        .def_readwrite("type", &GcpConfig::type)
        .def_readwrite("provider_version", &GcpConfig::provider_version)
        .def_readwrite("version_id", &GcpConfig::version_id)
        .def_readwrite("bucket_name", &GcpConfig::bucket_name)
        .def_readwrite("oauth_token_env", &GcpConfig::oauth_token_env)
        .def_readwrite("endpoint", &GcpConfig::endpoint)
        .def_readwrite("tls_skip_verify", &GcpConfig::tls_skip_verify);

    py::class_<KeyStorageConfig>(m, "KeyStorageConfig")
        .def(py::init<>())
        .def(py::init<const LocalConfig &>())
        .def(py::init<const VaultConfig &>())
        .def(py::init<const AwsConfig &>())
        .def(py::init<const GcpConfig &>())
        .def_static("make_local", &KeyStorageConfig::makeLocal, py::arg("config"))
        .def_static("make_vault", &KeyStorageConfig::makeVault, py::arg("config"))
        .def_static("make_aws", &KeyStorageConfig::makeAws, py::arg("config"))
        .def_static("make_gcp", &KeyStorageConfig::makeGcp, py::arg("config"))
        .def_property_readonly("type",
                               [](const KeyStorageConfig &self) {
                                   return self.type;
                               })
        .def("as_local",
             [](KeyStorageConfig &self) {
                 auto *cfg = self.asLocal();
                 if (!cfg) {
                     throw py::value_error("KeyStorageConfig does not contain LocalConfig");
                 }
                 return *cfg;
             })
        .def("as_vault",
             [](KeyStorageConfig &self) {
                 auto *cfg = self.asVault();
                 if (!cfg) {
                     throw py::value_error("KeyStorageConfig does not contain VaultConfig");
                 }
                 return *cfg;
             })
        .def("as_aws",
             [](KeyStorageConfig &self) {
                 auto *cfg = self.asAws();
                 if (!cfg) {
                     throw py::value_error("KeyStorageConfig does not contain AwsConfig");
                 }
                 return *cfg;
             })
        .def("as_gcp",
             [](KeyStorageConfig &self) {
                 auto *cfg = self.asGcp();
                 if (!cfg) {
                     throw py::value_error("KeyStorageConfig does not contain GcpConfig");
                 }
                 return *cfg;
             })
        .def("__repr__", [](const KeyStorageConfig &self) {
            std::string t = "UNKNOWN";
            if (self.type == ProviderType::Local) {
                t = "LOCAL";
            } else if (self.type == ProviderType::Vault) {
                t = "VAULT";
            } else if (self.type == ProviderType::Aws) {
                t = "AWS";
            } else if (self.type == ProviderType::Gcp) {
                t = "GCP";
            }
            return std::string("<evi.KeyStorageConfig type=") + t + ">";
        });

    // ----- Provider envelope content -----
    py::class_<KeyEntryParameter>(m, "KeyEntryParameter")
        .def(py::init<>())
        .def_readwrite("P", &KeyEntryParameter::P)
        .def_readwrite("Q", &KeyEntryParameter::Q)
        .def_readwrite("DB_SCALE_FACTOR", &KeyEntryParameter::DB_SCALE_FACTOR)
        .def_readwrite("QUERY_SCALE_FACTOR", &KeyEntryParameter::QUERY_SCALE_FACTOR)
        .def_readwrite("preset", &KeyEntryParameter::preset);

    py::class_<KeyEntryMetadata>(m, "KeyEntryMetadata")
        .def(py::init<>())
        .def_readwrite("parameter", &KeyEntryMetadata::parameter)
        .def_readwrite("eval_mode", &KeyEntryMetadata::eval_mode)
        .def_readwrite("dim", &KeyEntryMetadata::dim);

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
        .def_readwrite("entries", &ProviderEnvelope::entries);

    // ----- KeyManager -----
    py::class_<KeyManager>(m, "KeyManager")
        .def(py::init([]() {
            return makeKeyManager();
        }))
        .def(py::init([](const KeyStorageConfig &storage_config) {
                 return makeKeyManager(storage_config);
             }),
             py::arg("storage_config"))
        .def(
            "wrap_sec_key",
            [](KeyManager &self, const std::string &key_id, const std::string &key_path,
               const std::string &output_path) {
                self.wrapSecKey(key_id, key_path, output_path);
            },
            py::arg("key_id"), py::arg("key_path"), py::arg("output_path"))
        .def(
            "wrap_sec_key",
            [](KeyManager &self, const std::string &key_id, const std::string &key_path, const std::string &output_path,
               const SealInfo &seal_info) {
                self.wrapSecKey(key_id, key_path, output_path, seal_info);
            },
            py::arg("key_id"), py::arg("key_path"), py::arg("output_path"), py::arg("seal_info"))
        .def(
            "unwrap_sec_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path) {
                self.unwrapSecKey(envelope_path, output_path);
            },
            py::arg("envelope_path"), py::arg("output_path"))
        .def(
            "unwrap_sec_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path,
               const SealInfo &seal_info) {
                self.unwrapSecKey(envelope_path, output_path, seal_info);
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
        .def(
            "wrap_metadata_key",
            [](KeyManager &self, const std::string &key_id, const std::string &key_path,
               const std::string &output_path) {
                self.wrapMetadataKey(key_id, key_path, output_path);
            },
            py::arg("key_id"), py::arg("key_path"), py::arg("output_path"))
        .def(
            "wrap_metadata_key",
            [](KeyManager &self, const std::string &key_id, const std::string &key_path, const std::string &output_path,
               const SealInfo &seal_info) {
                self.wrapMetadataKey(key_id, key_path, output_path, seal_info);
            },
            py::arg("key_id"), py::arg("key_path"), py::arg("output_path"), py::arg("seal_info"))
        .def(
            "unwrap_metadata_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path) {
                self.unwrapMetadataKey(envelope_path, output_path);
            },
            py::arg("envelope_path"), py::arg("output_path"))
        .def(
            "unwrap_metadata_key",
            [](KeyManager &self, const std::string &envelope_path, const std::string &output_path,
               const SealInfo &seal_info) {
                self.unwrapMetadataKey(envelope_path, output_path, seal_info);
            },
            py::arg("envelope_path"), py::arg("output_path"), py::arg("seal_info"))
        // Stream/bytes helpers for in-memory wrapping/unwrapping
        .def(
            "wrap_sec_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob) {
                std::string buffer = key_blob;
                SensitiveDataGuard guard(buffer);
                std::istringstream key_stream(buffer, std::ios::binary);
                std::ostringstream out(std::ios::binary);
                self.wrapSecKey(key_id, key_stream, out);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"))
        .def(
            "wrap_sec_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob, const SealInfo &seal_info) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapSecKey(key_id, key_stream, out, seal_info);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"), py::arg("seal_info"))
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
            "wrap_metadata_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapMetadataKey(key_id, key_stream, out);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"))
        .def(
            "wrap_metadata_key_bytes",
            [](KeyManager &self, const std::string &key_id, const py::bytes &key_blob, const SealInfo &seal_info) {
                auto key_stream = bytesToStream(key_blob);
                std::ostringstream out(std::ios::binary);
                self.wrapMetadataKey(key_id, key_stream, out, seal_info);
                return streamToBytes(out);
            },
            py::arg("key_id"), py::arg("key_blob"), py::arg("seal_info"))
        .def(
            "unwrap_sec_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob) {
                std::string buffer = envelope_blob;
                SensitiveDataGuard guard(buffer);
                std::istringstream envelope_stream(buffer, std::ios::binary);
                std::ostringstream out(std::ios::binary);
                self.unwrapSecKey(envelope_stream, out);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def(
            "unwrap_sec_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob, const SealInfo &seal_info) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapSecKey(envelope_stream, out, seal_info);
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
                std::string buffer = envelope_blob;
                std::istringstream envelope_stream(buffer, std::ios::binary);
                std::ostringstream out(std::ios::binary);
                self.unwrapEvalKey(envelope_stream, out);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def(
            "unwrap_metadata_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapMetadataKey(envelope_stream, out);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"))
        .def(
            "unwrap_metadata_key_bytes",
            [](KeyManager &self, const py::bytes &envelope_blob, const SealInfo &seal_info) {
                auto envelope_stream = bytesToStream(envelope_blob);
                std::ostringstream out(std::ios::binary);
                self.unwrapMetadataKey(envelope_stream, out, seal_info);
                return streamToBytes(out);
            },
            py::arg("envelope_blob"), py::arg("seal_info"))
        .def(
            "wrap_keys",
            [](KeyManager &self, const std::string &key_id, const std::string &key_dir_path) {
                self.wrapKeys(key_id, key_dir_path);
            },
            py::arg("key_id"), py::arg("key_dir_path"))
        .def(
            "unwrap_keys",
            [](KeyManager &self, const std::string &envelope_dir_path, const std::string &output_dir_path) {
                self.unwrapKeys(envelope_dir_path, output_dir_path);
            },
            py::arg("envelope_dir_path"), py::arg("output_dir_path"))
        .def("deactivate_sec_key", &KeyManager::deactivateSecKey, py::arg("storage_key_path"), py::arg("reason"))
        .def("deactivate_pub_key", &KeyManager::deactivatePubKey, py::arg("storage_key_path"), py::arg("reason"))
        .def("destroy_sec_key", &KeyManager::destroySecKey, py::arg("storage_key_path"), py::arg("reason"))
        .def("destroy_pub_key", &KeyManager::destroyPubKey, py::arg("storage_key_path"), py::arg("reason"))
        .def("list_keys", &KeyManager::listKeys, py::arg("prefix") = "")
        .def(
            "get_sec_key",
            [](KeyManager &self, const std::string &storage_key_path) {
                std::ostringstream out(std::ios::binary);
                self.getSecKey(storage_key_path, out);
                return streamToBytes(out);
            },
            py::arg("storage_key_path"))
        .def(
            "get_pub_key",
            [](KeyManager &self, const std::string &storage_key_path) {
                std::ostringstream out(std::ios::binary);
                self.getPubKey(storage_key_path, out);
                return streamToBytes(out);
            },
            py::arg("storage_key_path"))
        .def("delete_sec_key", &KeyManager::deleteSecKey, py::arg("storage_key_path"))
        .def("delete_pub_key", &KeyManager::deletePubKey, py::arg("storage_key_path"))
        .def("list_versions", &KeyManager::listVersions, py::arg("storage_key_path"))
        .def(
            "put_sec_key",
            [](KeyManager &self, const std::string &storage_key_path, const py::bytes &key_blob) {
                std::string buffer = key_blob;
                SensitiveDataGuard guard(buffer);
                std::istringstream key_stream(buffer, std::ios::binary);
                self.putSecKey(storage_key_path, key_stream);
            },
            py::arg("storage_key_path"), py::arg("key_blob"))
        .def(
            "put_pub_key",
            [](KeyManager &self, const std::string &storage_key_path, const py::bytes &key_blob) {
                auto key_stream = bytesToStream(key_blob);
                self.putPubKey(storage_key_path, key_stream);
            },
            py::arg("storage_key_path"), py::arg("key_blob"))
        .def("__repr__", [](const KeyManager &) {
            return std::string("<evi.KeyManager>");
        });
}
