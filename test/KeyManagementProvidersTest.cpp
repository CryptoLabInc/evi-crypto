////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "km/KeyManager.hpp"
#include "km/KeyStorageConfig.hpp"

#include "utils/Exceptions.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

bool envFlag(const char *name) {
    const char *v = std::getenv(name);
    if (!v) {
        return false;
    }
    const std::string s(v);
    return s == "1" || s == "true" || s == "TRUE" || s == "yes" || s == "YES" || s == "on" || s == "ON";
}

std::string envOrEmpty(const char *name) {
    const char *v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

std::optional<std::string> envOpt(const char *name) {
    const char *v = std::getenv(name);
    if (!v || v[0] == '\0') {
        return std::nullopt;
    }
    return std::string(v);
}

std::vector<uint8_t> randomBytes(std::size_t n) {
    std::vector<uint8_t> out(n);
    std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto &b : out) {
        b = static_cast<uint8_t>(dist(rng));
    }
    return out;
}

fs::path writeBinary(const fs::path &path, const std::vector<uint8_t> &bytes) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return path;
}

std::vector<uint8_t> readBinary(const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::string uniqueSuffix() {
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return std::to_string(static_cast<long long>(now));
}

} // namespace

TEST(KeyManagementProvidersTest, VaultCrudRoundTrip) {
    if (!envFlag("EVI_TEST_VAULT_INTEGRATION")) {
        GTEST_SKIP() << "Set EVI_TEST_VAULT_INTEGRATION=1 to enable";
    }

    // Require token; address may come from VAULT_ADDR but meta has a safe default.
    if (!envOpt("VAULT_TOKEN")) {
        GTEST_SKIP() << "VAULT_TOKEN not set";
    }

    const std::string address = envOrEmpty("VAULT_ADDR");
    const std::string kv_mount = envOrEmpty("EVI_TEST_VAULT_KV_MOUNT");

    evi::KeyStorageConfig storage_config =
        evi::KeyStorageConfig::fromConfig("vault", {
                                                       {"address", address.empty() ? "http://127.0.0.1:8200" : address},
                                                       {"token_env", "VAULT_TOKEN"},
                                                       {"kv_mount", kv_mount.empty() ? "secret" : kv_mount},
                                                   });

    evi::KeyManager km = evi::makeKeyManager(storage_config);

    const std::string key_id = "km-vault-" + uniqueSuffix();
    const std::vector<uint8_t> payload = randomBytes(1024);

    const fs::path temp_dir = fs::temp_directory_path() / ("evi_km_vault_" + uniqueSuffix());
    const fs::path in_path = temp_dir / "SecKey.bin";
    const fs::path envelope_path = temp_dir / "SecKey.json";
    const fs::path out_path = temp_dir / "SecKey.out";
    writeBinary(in_path, payload);

    km.wrapSecKey(key_id, in_path.string(), envelope_path.string());

    const std::vector<std::string> keys = km.listKeys();
    auto it = std::find_if(keys.begin(), keys.end(), [&key_id](const std::string &k) {
        return k == (key_id + "/SecKey.json");
    });
    ASSERT_TRUE(it != keys.end()) << "Vault listKeys did not return SecKey.json";

    std::ofstream sec_out(out_path, std::ios::binary);
    km.getSecKey(*it, sec_out);
    sec_out.flush();
    EXPECT_EQ(readBinary(out_path), payload);

    km.deleteSecKey(*it);
    EXPECT_THROW(
        {
            std::ostringstream out(std::ios::binary);
            km.getSecKey(*it, out);
        },
        std::exception);
}

TEST(KeyManagementProvidersTest, AwsS3CrudRoundTrip) {
    if (!envFlag("EVI_TEST_AWS_INTEGRATION")) {
        GTEST_SKIP() << "Set EVI_TEST_AWS_INTEGRATION=1 to enable";
    }

    // Credentials are read from standard env by default.
    if (!envOpt("AWS_ACCESS_KEY_ID") || !envOpt("AWS_SECRET_ACCESS_KEY")) {
        GTEST_SKIP() << "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set";
    }

    const auto region_opt = envOpt("EVI_TEST_AWS_REGION");
    const auto bucket_opt = envOpt("EVI_TEST_AWS_BUCKET");
    if (!region_opt || !bucket_opt) {
        GTEST_SKIP() << "EVI_TEST_AWS_REGION/EVI_TEST_AWS_BUCKET not set";
    }
    const std::string &region = *region_opt;
    const std::string &bucket = *bucket_opt;
    const std::string base_prefix = envOrEmpty("EVI_TEST_AWS_SECRET_PREFIX");
    const std::string endpoint = envOrEmpty("EVI_TEST_AWS_ENDPOINT");
    const std::string force_path_style = envOrEmpty("EVI_TEST_AWS_FORCE_PATH_STYLE");
    const std::string tls_skip_verify = envOrEmpty("EVI_TEST_AWS_TLS_SKIP_VERIFY");

    const std::string secret_prefix =
        base_prefix.empty() ? ("evi-crypto/tests/" + uniqueSuffix()) : (base_prefix + "/" + uniqueSuffix());

    evi::KeyStorageConfig storage_config = evi::KeyStorageConfig::fromConfig(
        "aws", {
                   {"region", region},
                   {"bucket_name", bucket},
                   {"secret_prefix", secret_prefix},
                   {"endpoint", endpoint},
                   {"force_path_style", force_path_style.empty() ? "0" : force_path_style},
                   {"tls_skip_verify", tls_skip_verify.empty() ? "0" : tls_skip_verify},
                   {"access_key_env", "AWS_ACCESS_KEY_ID"},
                   {"secret_key_env", "AWS_SECRET_ACCESS_KEY"},
                   {"session_token_env", "AWS_SESSION_TOKEN"},
               });

    evi::KeyManager km = evi::makeKeyManager(storage_config);

    const std::string key_id = "km-aws-" + uniqueSuffix();
    const std::vector<uint8_t> payload = randomBytes(1024);

    const fs::path temp_dir = fs::temp_directory_path() / ("evi_km_aws_" + uniqueSuffix());
    const fs::path in_path = temp_dir / "EncKey.bin";
    const fs::path envelope_path = temp_dir / "EncKey.json";
    const fs::path out_path = temp_dir / "EncKey.out";
    writeBinary(in_path, payload);

    km.wrapEncKey(key_id, in_path.string(), envelope_path.string());

    const std::vector<std::string> keys = km.listKeys();
    auto it = std::find_if(keys.begin(), keys.end(), [&key_id](const std::string &k) {
        return k == (key_id + "/EncKey.json");
    });
    ASSERT_TRUE(it != keys.end()) << "S3 listKeys did not return EncKey.json";

    std::ofstream enc_out(out_path, std::ios::binary);
    km.getPubKey(*it, enc_out);
    enc_out.flush();
    EXPECT_EQ(readBinary(out_path), payload);

    km.deletePubKey(*it);
    EXPECT_THROW(
        {
            std::ostringstream out(std::ios::binary);
            km.getPubKey(*it, out);
        },
        std::exception);
}

TEST(KeyManagementProvidersTest, GcpGcsCrudRoundTrip) {
    if (!envFlag("EVI_TEST_GCP_INTEGRATION")) {
        GTEST_SKIP() << "Set EVI_TEST_GCP_INTEGRATION=1 to enable";
    }

    // OAuth token must be provided at runtime; tests keep it out of any JSON/envelope.
    if (!envOpt("GCP_OAUTH_TOKEN")) {
        GTEST_SKIP() << "GCP_OAUTH_TOKEN not set";
    }

    const auto bucket_opt = envOpt("EVI_TEST_GCP_BUCKET");
    if (!bucket_opt) {
        GTEST_SKIP() << "EVI_TEST_GCP_BUCKET not set";
    }
    const std::string &bucket = *bucket_opt;
    const std::string base_prefix = envOrEmpty("EVI_TEST_GCP_SECRET_PREFIX");
    const std::string endpoint = envOrEmpty("EVI_TEST_GCP_ENDPOINT");
    const std::string tls_skip_verify = envOrEmpty("EVI_TEST_GCP_TLS_SKIP_VERIFY");

    const std::string secret_prefix =
        base_prefix.empty() ? ("evi-crypto/tests/" + uniqueSuffix()) : (base_prefix + "/" + uniqueSuffix());

    evi::KeyStorageConfig storage_config = evi::KeyStorageConfig::fromConfig(
        "gcp", {
                   {"bucket_name", bucket},
                   {"secret_prefix", secret_prefix},
                   {"oauth_token_env", "GCP_OAUTH_TOKEN"},
                   {"endpoint", endpoint.empty() ? "https://storage.googleapis.com" : endpoint},
                   {"tls_skip_verify", tls_skip_verify.empty() ? "0" : tls_skip_verify},
               });

    evi::KeyManager km = evi::makeKeyManager(storage_config);

    const std::string key_id = "km-gcp-" + uniqueSuffix();
    const std::vector<uint8_t> payload = randomBytes(1024);

    const fs::path temp_dir = fs::temp_directory_path() / ("evi_km_gcp_" + uniqueSuffix());
    const fs::path in_path = temp_dir / "EncKey.bin";
    const fs::path envelope_path = temp_dir / "EncKey.json";
    const fs::path out_path = temp_dir / "EncKey.out";
    writeBinary(in_path, payload);

    km.wrapEncKey(key_id, in_path.string(), envelope_path.string());

    const std::vector<std::string> keys = km.listKeys();
    auto it = std::find_if(keys.begin(), keys.end(), [&key_id](const std::string &k) {
        return k == (key_id + "/EncKey.json");
    });
    ASSERT_TRUE(it != keys.end()) << "GCS listKeys did not return EncKey.json";

    std::ofstream enc_out(out_path, std::ios::binary);
    km.getPubKey(*it, enc_out);
    enc_out.flush();
    EXPECT_EQ(readBinary(out_path), payload);

    km.deletePubKey(*it);
    EXPECT_THROW(
        {
            std::ostringstream out(std::ios::binary);
            km.getPubKey(*it, out);
        },
        std::exception);
}
