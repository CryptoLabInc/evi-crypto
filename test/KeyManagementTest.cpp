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

#include "km/KeyManager.hpp"
#include "km/KeyStorageConfig.hpp"
#include "km/impl/KeyManagerCommon.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include "EVI/Const.hpp"
#include "EVI/Context.hpp"
#include "EVI/KeyGenerator.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "EVI/Utils.hpp"
#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include "utils/crypto/AES.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <memory>
#include <numeric>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;

using json = nlohmann::json;

namespace {

json loadEnvelope(const fs::path &path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Failed to open sealed file: " + path.string());
    }
    json envelope;
    in >> envelope;
    return envelope;
}

std::vector<uint8_t> decryptMetadataKey(const json &envelope, const std::vector<uint8_t> &kek) {
    const auto &entries = envelope.at("entries");
    auto meta_it = std::find_if(entries.begin(), entries.end(), [](const json &entry) {
        return entry.is_object() && entry.value("usage", "") == "metadata";
    });
    if (meta_it == entries.end()) {
        return {};
    }

    const std::string edk_b64 = meta_it->at("key_data").get<std::string>();
    const std::string iv_b64 = meta_it->at("iv").get<std::string>();
    const std::string tag_b64 = meta_it->at("tag").get<std::string>();

    std::vector<uint8_t> ciphertext = evi::detail::utils::decodeBase64(edk_b64);
    std::vector<uint8_t> iv = evi::detail::utils::decodeBase64(iv_b64);
    std::vector<uint8_t> tag = evi::detail::utils::decodeBase64(tag_b64);

    std::vector<uint8_t> plaintext;
    if (!AES::decryptAESGCM(ciphertext, kek, iv, plaintext, tag)) {
        throw std::runtime_error("Failed to decrypt metadata key from envelope");
    }
    return plaintext;
}

std::string encode(const std::vector<uint8_t> &bytes) {
    return evi::detail::utils::encodeToBase64(bytes);
}

std::string entryPayloadHash(const json &entry) {
    const std::vector<uint8_t> payload = evi::detail::utils::decodeBase64(entry.at("key_data").get<std::string>());
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (SHA256(reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), digest.data()) == nullptr) {
        throw std::runtime_error("Failed to compute entry payload hash");
    }
    return encode(std::vector<uint8_t>(digest.begin(), digest.end()));
}

template <typename Fn>
std::string captureInvalidInputMessage(Fn &&fn) {
    try {
        fn();
    } catch (const evi::InvalidInputError &err) {
        return err.what();
    }
    return {};
}

std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256File(const fs::path &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open file for hashing: " + path.string());
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to allocate SHA-256 context");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize SHA-256 context");
    }

    std::vector<unsigned char> buffer(64 * 1024 * 1024);
    while (in) {
        in.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = in.gcount();
        if (count > 0) {
            if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(count)) != 1) {
                throw std::runtime_error("Failed to update SHA-256 digest");
            }
        }
    }
    if (!in.eof() && in.fail()) {
        throw std::runtime_error("Failed to read file for hashing: " + path.string());
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1) {
        throw std::runtime_error("Failed to finalize SHA-256 digest");
    }
    return digest;
}

std::optional<evi::EvalMode> parseEvalMode(const std::string &value) {
    if (value == "RMP") {
        return evi::EvalMode::RMP;
    }
    if (value == "FLAT") {
        return evi::EvalMode::FLAT;
    }
    if (value == "MM") {
        return evi::EvalMode::MM;
    }
    if (value == "SINGLE") {
        return evi::EvalMode::SINGLE;
    }
    if (value == "RMS") {
        return evi::EvalMode::RMS;
    }
    if (value == "MS") {
        return evi::EvalMode::MS;
    }
    return std::nullopt;
}

std::vector<uint8_t> defaultAesKek() {
    return {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
}

} // namespace

class KeyManagementTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
        temp_dir_ = fs::temp_directory_path() / ("evi_key_mgmt_test_" + std::to_string(unique));
        fs::create_directories(temp_dir_);

        evi::ParameterPreset preset = evi::ParameterPreset::IP0;
        std::vector<evi::Context> contexts = evi::makeMultiContext(preset, evi::DeviceType::CPU, evi::EvalMode::RMP);
        evi::SealInfo s_info(evi::SealMode::NONE);
        fs::path generator_dir = temp_dir_ / "generated_keys";
        evi::MultiKeyGenerator keygen(contexts, generator_dir.string(), s_info);

        std::stringstream sec_ss;
        std::stringstream enc_ss;
        std::stringstream eval_ss;
        keygen.generateKeys(sec_ss, enc_ss, eval_ss);

        sec_payload_ = streamToBytes(sec_ss);
        enc_payload_ = streamToBytes(enc_ss);
        eval_payload_ = streamToBytes(eval_ss);

        std::error_code ec;
        fs::remove_all(generator_dir, ec);
    }

    void TearDown() override {
        if (!temp_dir_.empty() && fs::exists(temp_dir_)) {
            std::error_code ec;
            fs::remove_all(temp_dir_, ec);
        }
    }

    std::vector<uint8_t> streamToBytes(std::stringstream &stream) {
        const std::string data = stream.str();
        return std::vector<uint8_t>(data.begin(), data.end());
    }

    fs::path writeBinary(const std::string &name, const std::vector<uint8_t> &bytes) const {
        fs::path path = temp_dir_ / name;
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        return path;
    }

    static std::vector<uint8_t> readBinary(const fs::path &path) {
        std::ifstream in(path, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    evi::KeyManager manager_{evi::makeKeyManager()};
    evi::detail::KeyProvider provider_{};
    fs::path temp_dir_;
    std::vector<uint8_t> sec_payload_;
    std::vector<uint8_t> enc_payload_;
    std::vector<uint8_t> eval_payload_;
};

TEST_F(KeyManagementTest, WrapSecKeyProducesExpectedEnvelope) {
    const std::vector<uint8_t> bytes = sec_payload_;
    const fs::path key_path = writeBinary("SecKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "SecKey.json";

    manager_.wrapSecKey("sec-key-id", key_path.string(), sealed_path.string());

    const json envelope = loadEnvelope(sealed_path);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "sec-key-id");
    EXPECT_EQ(envelope.at("usage").get<std::string>(), "vector_search");
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    const json &entry = envelope.at("entries").front();
    EXPECT_EQ(entry.at("name").get<std::string>(), "seckey");
    EXPECT_EQ(entry.at("role").get<std::string>(), "decryption key");
    EXPECT_EQ(entry.at("key_data").get<std::string>(), encode(bytes));
    ASSERT_TRUE(entry.at("hash").is_object());
    EXPECT_EQ(entry.at("hash").at("type").get<std::string>(), "SHA256");
    EXPECT_FALSE(entry.at("hash").at("value").get<std::string>().empty());
}

TEST_F(KeyManagementTest, MetadataStringAesGcmRoundTrip) {
    const std::string metadata_text =
        "meta-key-1|usage=metadata|preset=IP0|Q=1|P=2|nested.name=kms|nested.enabled=true";
    const std::vector<uint8_t> key = evi::Utils::generateRandomBytes(evi::AES256_KEY_SIZE);
    const std::vector<uint8_t> aad = {'k', 'm', '-', 'm', 'e', 't', 'a'};

    const std::string encrypted = evi::Utils::encryptMetadata(metadata_text, key, aad);
    const json encrypted_json = json::parse(encrypted);
    ASSERT_TRUE(encrypted_json.contains("iv"));
    ASSERT_TRUE(encrypted_json.contains("tag"));
    ASSERT_TRUE(encrypted_json.contains("encrypted_data"));

    const std::string decrypted = evi::Utils::decryptMetadata(encrypted, key, aad);
    EXPECT_EQ(decrypted, metadata_text);
}

TEST_F(KeyManagementTest, WrapEncKeyProducesExpectedEnvelope) {
    const std::vector<uint8_t> bytes = enc_payload_;
    const fs::path key_path = writeBinary("EncKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EncKey.json";

    manager_.wrapEncKey("enc-key-id", key_path.string(), sealed_path.string());

    const json envelope = loadEnvelope(sealed_path);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "enc-key-id");
    EXPECT_EQ(envelope.at("usage").get<std::string>(), "vector_search");
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    const json &entry = envelope.at("entries").front();
    EXPECT_EQ(entry.at("name").get<std::string>(), "enckey");
    EXPECT_EQ(entry.at("role").get<std::string>(), "encryption key");
    EXPECT_EQ(entry.at("key_data").get<std::string>(), encode(bytes));
    ASSERT_TRUE(entry.at("hash").is_object());
    EXPECT_EQ(entry.at("hash").at("type").get<std::string>(), "SHA256");
    EXPECT_FALSE(entry.at("hash").at("value").get<std::string>().empty());
}

TEST_F(KeyManagementTest, WrapEvalKeyProducesExpectedEnvelope) {
    const std::vector<uint8_t> bytes = eval_payload_;
    const fs::path key_path = writeBinary("EvalKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EvalKey.json";

    manager_.wrapEvalKey("eval-key-id", key_path.string(), sealed_path.string());

    const json envelope = loadEnvelope(sealed_path);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "eval-key-id");
    EXPECT_EQ(envelope.at("usage").get<std::string>(), "vector_search");
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    const json &entry = envelope.at("entries").front();
    EXPECT_EQ(entry.at("name").get<std::string>(), "evalkey");
    EXPECT_EQ(entry.at("role").get<std::string>(), "evaluation key");
    EXPECT_EQ(entry.at("key_data").get<std::string>(), encode(bytes));
    ASSERT_TRUE(entry.at("hash").is_object());
    EXPECT_EQ(entry.at("hash").at("type").get<std::string>(), "SHA256");
    EXPECT_FALSE(entry.at("hash").at("value").get<std::string>().empty());
}

TEST_F(KeyManagementTest, WrapAndUnwrapEncKeyRoundTripsBytes) {
    const std::vector<uint8_t> bytes = enc_payload_;
    const fs::path key_path = writeBinary("EncKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EncKey.json";
    const fs::path restored_path = temp_dir_ / "EncKey.out";

    manager_.wrapEncKey("enc-key-id", key_path.string(), sealed_path.string());
    manager_.unwrapEncKey(sealed_path.string(), restored_path.string());

    const std::vector<uint8_t> decoded = readBinary(restored_path);
    EXPECT_EQ(decoded, bytes);
}

TEST_F(KeyManagementTest, WrapAndUnwrapEvalKeyRoundTripsBytes) {
    const std::vector<uint8_t> bytes = eval_payload_;
    const fs::path key_path = writeBinary("EvalKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EvalKey.json";
    const fs::path restored_path = temp_dir_ / "EvalKey.out";

    manager_.wrapEvalKey("eval-key-id", key_path.string(), sealed_path.string());
    manager_.unwrapEvalKey(sealed_path.string(), restored_path.string());

    const std::vector<uint8_t> decoded = readBinary(restored_path);
    EXPECT_EQ(decoded, bytes);
}

TEST_F(KeyManagementTest, WrapAndUnwrapMetadataKeyRoundTripsBytes) {
    std::vector<uint8_t> bytes = evi::Utils::generateRandomBytes(256);

    const fs::path key_path = writeBinary("MetadataKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "MetadataKey.json";
    const fs::path restored_path = temp_dir_ / "MetadataKey.out";

    manager_.wrapMetadataKey("metadata-key-id", key_path.string(), sealed_path.string());
    manager_.unwrapMetadataKey(sealed_path.string(), restored_path.string());

    const std::vector<uint8_t> decoded = readBinary(restored_path);
    EXPECT_EQ(decoded, bytes);
}

TEST_F(KeyManagementTest, WrapAndUnwrapMetadataKeyWithAesKekRoundTripsBytes) {
    const std::vector<uint8_t> kek = defaultAesKek();
    const evi::SealInfo seal_info(evi::SealMode::AES_KEK, kek);
    const std::vector<uint8_t> bytes = evi::Utils::generateRandomBytes(evi::AES256_KEY_SIZE);

    const fs::path key_path = writeBinary("MetadataKey_kek.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "MetadataKey_kek.json";
    const fs::path restored_path = temp_dir_ / "MetadataKey_kek.out";

    manager_.wrapMetadataKey("metadata-key-kek-id", key_path.string(), sealed_path.string(), seal_info);

    const json envelope = loadEnvelope(sealed_path);
    ASSERT_TRUE(envelope.contains("entries"));
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    const json &entry = envelope.at("entries").front();
    EXPECT_EQ(entry.at("name").get<std::string>(), "metadatakey");
    ASSERT_TRUE(entry.contains("alg"));
    ASSERT_TRUE(entry.contains("iv"));
    ASSERT_TRUE(entry.contains("tag"));
    EXPECT_EQ(entry.at("alg").get<std::string>(), "AES-256-GCM");
    EXPECT_FALSE(entry.at("iv").get<std::string>().empty());
    EXPECT_FALSE(entry.at("tag").get<std::string>().empty());

    manager_.unwrapMetadataKey(sealed_path.string(), restored_path.string(), seal_info);

    const std::vector<uint8_t> decoded = readBinary(restored_path);
    EXPECT_EQ(decoded, bytes);
}

TEST_F(KeyManagementTest, WrappedEncKeyDecapsulatesThroughStreamProvider) {
    const std::vector<uint8_t> bytes = enc_payload_;
    const fs::path key_path = writeBinary("EncKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EncKeyStream.json";

    manager_.wrapEncKey("enc-key-id", key_path.string(), sealed_path.string());

    std::ifstream envelope_file(sealed_path);
    ASSERT_TRUE(envelope_file);
    std::stringstream envelope_stream;
    envelope_stream << envelope_file.rdbuf();
    envelope_stream.seekg(0);

    std::ostringstream out_stream(std::ios::binary);
    provider_.decapEncKey(envelope_stream, out_stream);

    const std::string decoded = out_stream.str();
    std::vector<uint8_t> decoded_bytes(decoded.begin(), decoded.end());
    EXPECT_EQ(decoded_bytes, bytes);
}

TEST_F(KeyManagementTest, WrappedEvalKeyDecapsulatesThroughStreamProvider) {
    const std::vector<uint8_t> bytes = eval_payload_;
    const fs::path key_path = writeBinary("EvalKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EvalKeyStream.json";

    manager_.wrapEvalKey("eval-key-id", key_path.string(), sealed_path.string());

    std::ifstream envelope_file(sealed_path);
    ASSERT_TRUE(envelope_file);
    std::stringstream envelope_stream;
    envelope_stream << envelope_file.rdbuf();
    envelope_stream.seekg(0);

    std::ostringstream out_stream(std::ios::binary);
    provider_.decapEvalKey(envelope_stream, out_stream);

    const std::string decoded = out_stream.str();
    std::vector<uint8_t> decoded_bytes(decoded.begin(), decoded.end());
    EXPECT_EQ(decoded_bytes, bytes);
}

TEST_F(KeyManagementTest, DecapEvalKeyHandlesLargeBase64Payload) {
    const size_t payload_size = 4 * 1024 * 1024;
    std::vector<uint8_t> bytes(payload_size);
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(i % 251);
    }

    const std::string key_data = encode(bytes);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> key_digest{};
    if (SHA256(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), key_digest.data()) == nullptr) {
        throw std::runtime_error("Failed to compute SHA-256 digest");
    }
    const std::string key_hash = encode(std::vector<uint8_t>(key_digest.begin(), key_digest.end()));

    const std::string kid = "eval-large";
    const std::string usage = "vector_search";
    const std::string created_at = "2026-01-01T00:00:00Z";
    const std::string expires_at = "2036-01-01T00:00:00Z";
    const json requester = json::object();
    const json aad_payload = {{"kid", kid},
                              {"usage", usage},
                              {"requester", requester},
                              {"created_at", created_at},
                              {"expires_at", expires_at}};
    const std::string aad_context = aad_payload.dump();
    std::array<unsigned char, SHA256_DIGEST_LENGTH> aad_digest{};
    if (SHA256(reinterpret_cast<const unsigned char *>(aad_context.data()), aad_context.size(), aad_digest.data()) ==
        nullptr) {
        throw std::runtime_error("Failed to compute SHA-256 digest");
    }
    const std::string aad_value = encode(std::vector<uint8_t>(aad_digest.begin(), aad_digest.end()));

    const json envelope = {
        {"format_version", 1},
        {"kid", kid},
        {"usage", usage},
        {"requester", requester},
        {"created_at", created_at},
        {"expires_at", expires_at},
        {"aad", {{"type", "SHA256"}, {"value", aad_value}}},
        {"state", {{"value", "active"}, {"updated_at", created_at}}},
        {"entries", json::array({{{"key_data", key_data}, {"hash", {{"type", "SHA256"}, {"value", key_hash}}}}})}};

    const std::string envelope_text = envelope.dump();
    std::istringstream in_stream(envelope_text);
    std::ostringstream out_stream(std::ios::binary);
    provider_.decapEvalKey(in_stream, out_stream);

    const std::string decoded = out_stream.str();
    std::vector<uint8_t> decoded_bytes(decoded.begin(), decoded.end());
    EXPECT_EQ(decoded_bytes, bytes);
}

TEST_F(KeyManagementTest, WrapUnwrapEvalKeyWithRealIP1File) {
    const char *eval_path_env = std::getenv("EVI_TEST_IP1_EVALKEY_PATH");
    if (!eval_path_env || std::string(eval_path_env).empty()) {
        GTEST_SKIP() << "EVI_TEST_IP1_EVALKEY_PATH not set";
    }

    fs::path eval_path(eval_path_env);
    if (!fs::exists(eval_path)) {
        GTEST_SKIP() << "IP1 eval key file does not exist: " << eval_path.string();
    }

    const fs::path wrapped_path = temp_dir_ / "EvalKeyIP1.json";
    const fs::path unwrapped_path = temp_dir_ / "EvalKeyIP1.bin";

    manager_.wrapEvalKey("eval-key-ip1", eval_path.string(), wrapped_path.string());
    manager_.unwrapEvalKey(wrapped_path.string(), unwrapped_path.string());

    const auto original_digest = sha256File(eval_path);
    const auto unwrapped_digest = sha256File(unwrapped_path);
    EXPECT_EQ(original_digest, unwrapped_digest);

    const char *mode_env = std::getenv("EVI_TEST_IP1_EVAL_MODE");
    const char *rank_env = std::getenv("EVI_TEST_IP1_RANK");
    if (!mode_env || !rank_env) {
        GTEST_SKIP() << "EVI_TEST_IP1_EVAL_MODE and EVI_TEST_IP1_RANK required to load KeyPack";
    }

    auto mode = parseEvalMode(mode_env);
    if (!mode) {
        GTEST_SKIP() << "Unsupported eval mode: " << mode_env;
    }

    char *end = nullptr;
    const uint64_t rank = std::strtoull(rank_env, &end, 10);
    if (!end || *end != '\0' || rank == 0) {
        GTEST_SKIP() << "Invalid EVI_TEST_IP1_RANK value: " << rank_env;
    }

    evi::Context context = makeContext(evi::ParameterPreset::IP1, evi::DeviceType::CPU, rank, *mode);
    evi::KeyPack pack = makeKeyPack(context);
    pack.loadEvalKey(unwrapped_path.string());
}

// ---------------------------------------------------------------------------
// Tests for object-based overloads (previously untested, contained defects)
// ---------------------------------------------------------------------------

TEST_F(KeyManagementTest, WrapSecKeyViaSecretKeyObjectRoundTrips) {
    // Load a SecretKey from the generated key bytes
    std::istringstream sec_in(std::string(sec_payload_.begin(), sec_payload_.end()), std::ios::binary);
    evi::SecretKey seckey = evi::makeSecKey(sec_in);

    // Wrap using the SecretKey object overload (was infinite recursion before fix)
    std::ostringstream wrap_out;
    manager_.wrapSecKey("sec-obj-roundtrip", seckey, wrap_out);

    const std::string envelope_str = wrap_out.str();
    ASSERT_FALSE(envelope_str.empty());

    // Verify envelope structure
    const json envelope = json::parse(envelope_str);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "sec-obj-roundtrip");
    EXPECT_EQ(envelope.at("usage").get<std::string>(), "vector_search");

    // Unwrap back to raw bytes via stream overload and compare with original
    std::istringstream envelope_in(envelope_str);
    std::ostringstream raw_out(std::ios::binary);
    manager_.unwrapSecKey(envelope_in, raw_out);

    const std::string unwrapped = raw_out.str();
    const std::vector<uint8_t> unwrapped_bytes(unwrapped.begin(), unwrapped.end());
    EXPECT_EQ(unwrapped_bytes, sec_payload_);
}

TEST_F(KeyManagementTest, WrapAndUnwrapEncKeyViaKeyPackRoundTrips) {
    // Create a KeyPack and load the generated enc key
    evi::Context context =
        evi::makeMultiContext(evi::ParameterPreset::IP0, evi::DeviceType::CPU, evi::EvalMode::RMP).front();
    evi::KeyPack pack = evi::makeKeyPack(context);

    std::istringstream enc_in(std::string(enc_payload_.begin(), enc_payload_.end()), std::ios::binary);
    pack.loadEncKey(enc_in);

    // Save canonical enc key bytes through KeyPack serialization
    std::ostringstream orig_enc_out;
    pack.saveEncKey(orig_enc_out);
    const std::string orig_enc_bytes = orig_enc_out.str();
    ASSERT_FALSE(orig_enc_bytes.empty());

    // Wrap using KeyPack object overload
    std::ostringstream wrap_out;
    manager_.wrapEncKey("enc-obj-roundtrip", pack, wrap_out);

    const std::string envelope_str = wrap_out.str();
    ASSERT_FALSE(envelope_str.empty());
    const json envelope = json::parse(envelope_str);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "enc-obj-roundtrip");

    // Unwrap into a new KeyPack (was routing to decapSecKey before fix)
    evi::KeyPack pack_out = evi::makeKeyPack(context);
    std::istringstream envelope_in(envelope_str);
    manager_.unwrapEncKey(envelope_in, pack_out);

    // Save restored enc key and compare
    std::ostringstream restored_enc_out;
    pack_out.saveEncKey(restored_enc_out);
    EXPECT_EQ(restored_enc_out.str(), orig_enc_bytes);
}

TEST_F(KeyManagementTest, UnwrapEncKeyStreamRejectsUsageMismatch) {
    const fs::path enc_path = writeBinary("EncKey.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_for_enc_stream.json";
    manager_.wrapEncKey("enc-for-enc-stream", enc_path.string(), sealed_path.string());

    json envelope = loadEnvelope(sealed_path);
    envelope["usage"] = "tampered_usage";

    std::stringstream envelope_stream;
    envelope_stream << envelope.dump();
    envelope_stream.seekg(0);

    std::ostringstream out_stream(std::ios::binary);
    EXPECT_THROW(manager_.unwrapEncKey(envelope_stream, out_stream), evi::InvalidInputError);
}

TEST_F(KeyManagementTest, UnwrapEncKeyPathRejectsUsageMismatch) {
    const fs::path enc_path = writeBinary("EncKey.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_for_enc_path.json";
    manager_.wrapEncKey("enc-for-enc-path", enc_path.string(), sealed_path.string());

    json envelope = loadEnvelope(sealed_path);
    envelope["usage"] = "tampered_usage";
    std::ofstream out(sealed_path);
    ASSERT_TRUE(out.good());
    out << envelope.dump();
    out.close();

    const fs::path output_path = temp_dir_ / "EncKey_from_tampered.bin";
    EXPECT_THROW(manager_.unwrapEncKey(sealed_path.string(), output_path.string()), evi::InvalidInputError);
}

TEST_F(KeyManagementTest, UnwrapEncKeyKeyPackRejectsUsageMismatch) {
    const fs::path enc_path = writeBinary("EncKey.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_for_enc_keypack.json";
    manager_.wrapEncKey("enc-for-enc-keypack", enc_path.string(), sealed_path.string());

    json envelope = loadEnvelope(sealed_path);
    envelope["usage"] = "tampered_usage";

    std::stringstream envelope_stream;
    envelope_stream << envelope.dump();
    envelope_stream.seekg(0);

    evi::Context context =
        evi::makeMultiContext(evi::ParameterPreset::IP0, evi::DeviceType::CPU, evi::EvalMode::RMP).front();
    evi::KeyPack pack = evi::makeKeyPack(context);

    EXPECT_THROW(manager_.unwrapEncKey(envelope_stream, pack), evi::InvalidInputError);
}

TEST_F(KeyManagementTest, UnwrapSecKeyWithAesKekViaSecretKeyObjectRoundTrips) {
    const std::vector<uint8_t> kek = defaultAesKek();
    const evi::SealInfo seal_info(evi::SealMode::AES_KEK, kek);

    // Wrap sec key with AES-KEK
    const fs::path key_path = writeBinary("SecKey.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_aes_kek_object.json";
    manager_.wrapSecKey("sec-aes-kek-object", key_path.string(), sealed_path.string(), seal_info);

    // Read sealed envelope into a stream
    std::ifstream envelope_file(sealed_path);
    ASSERT_TRUE(envelope_file.good());
    std::stringstream envelope_stream;
    envelope_stream << envelope_file.rdbuf();
    envelope_stream.seekg(0);

    // Create destination SecretKey and unwrap with AES-KEK
    evi::Context context =
        evi::makeMultiContext(evi::ParameterPreset::IP0, evi::DeviceType::CPU, evi::EvalMode::RMP).front();
    evi::SecretKey seckey = evi::makeSecKey(context);
    manager_.unwrapSecKey(envelope_stream, seckey, seal_info);

    std::ostringstream rewrap_stream;
    manager_.wrapSecKey("sec-aes-kek-object-rewrap", seckey, rewrap_stream);

    std::istringstream rewrap_in(rewrap_stream.str());
    std::ostringstream out_stream(std::ios::binary);
    manager_.unwrapSecKey(rewrap_in, out_stream);

    const std::string out = out_stream.str();
    const std::vector<uint8_t> out_bytes(out.begin(), out.end());
    EXPECT_EQ(out_bytes, sec_payload_);
}

TEST_F(KeyManagementTest, UnwrapSecKeyFilePathWithAesKekRoundTrips) {
    const std::vector<uint8_t> kek = defaultAesKek();
    const evi::SealInfo seal_info(evi::SealMode::AES_KEK, kek);

    const fs::path key_path = writeBinary("SecKey.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_aes_kek_file.json";
    manager_.wrapSecKey("sec-aes-kek-file", key_path.string(), sealed_path.string(), seal_info);

    const fs::path output_path = temp_dir_ / "SecKey_aes_kek_file.out";

    manager_.unwrapSecKey(sealed_path.string(), output_path.string(), seal_info);
    const std::vector<uint8_t> decoded = readBinary(output_path);
    EXPECT_EQ(decoded, sec_payload_);
}

TEST_F(KeyManagementTest, UnwrapSecKeyStreamWithAesKekRoundTrips) {
    const std::vector<uint8_t> kek = defaultAesKek();
    const evi::SealInfo seal_info(evi::SealMode::AES_KEK, kek);

    const fs::path key_path = writeBinary("SecKey.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_aes_kek_stream.json";
    manager_.wrapSecKey("sec-aes-kek-stream", key_path.string(), sealed_path.string(), seal_info);

    std::ifstream envelope_file(sealed_path);
    ASSERT_TRUE(envelope_file.good());
    std::stringstream envelope_stream;
    envelope_stream << envelope_file.rdbuf();
    envelope_stream.seekg(0);

    std::ostringstream out_stream(std::ios::binary);
    manager_.unwrapSecKey(envelope_stream, out_stream, seal_info);
    const std::string out = out_stream.str();
    const std::vector<uint8_t> out_bytes(out.begin(), out.end());
    EXPECT_EQ(out_bytes, sec_payload_);
}

TEST_F(KeyManagementTest, RotateSecKeyUpdatesWrappedPayloadAndStateTimestamp) {
    const std::vector<uint8_t> old_kek = defaultAesKek();
    const std::vector<uint8_t> new_kek = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, old_kek);
    const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, new_kek);

    const fs::path key_path = writeBinary("SecKey_rotate.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_rotate.json";
    manager_.wrapSecKey("sec-key-rotate", key_path.string(), sealed_path.string(), old_seal_info);

    json original = loadEnvelope(sealed_path);
    original["state"]["updated_at"] = "2000-01-01T00:00:00Z";
    {
        std::ofstream out(sealed_path);
        ASSERT_TRUE(out.good());
        out << original.dump();
    }

    const json original_entry = original.at("entries").front();
    const std::string original_updated_at = original.at("state").at("updated_at").get<std::string>();
    const std::string original_key_version = original.at("key_version").get<std::string>();
    const std::string original_key_data = original_entry.at("key_data").get<std::string>();
    const std::string original_iv = original_entry.at("iv").get<std::string>();
    const std::string original_tag = original_entry.at("tag").get<std::string>();

    manager_.rotateSecKey(sealed_path.string(), old_seal_info, new_seal_info);

    const json rotated = loadEnvelope(sealed_path);
    const json &rotated_entry = rotated.at("entries").front();
    EXPECT_NE(rotated_entry.at("key_data").get<std::string>(), original_key_data);
    EXPECT_NE(rotated_entry.at("iv").get<std::string>(), original_iv);
    EXPECT_NE(rotated_entry.at("tag").get<std::string>(), original_tag);
    EXPECT_EQ(rotated_entry.at("hash").at("value").get<std::string>(), entryPayloadHash(rotated_entry));
    EXPECT_EQ(rotated.at("key_version").get<std::string>(), std::to_string(std::stoul(original_key_version) + 1UL));
    EXPECT_NE(rotated.at("state").at("updated_at").get<std::string>(), original_updated_at);
    EXPECT_EQ(rotated.at("created_at").get<std::string>(), original.at("created_at").get<std::string>());
    EXPECT_EQ(rotated.at("expires_at").get<std::string>(), original.at("expires_at").get<std::string>());

    const fs::path output_path = temp_dir_ / "SecKey_rotate.out";
    manager_.unwrapSecKey(sealed_path.string(), output_path.string(), new_seal_info);
    EXPECT_EQ(readBinary(output_path), sec_payload_);

    const fs::path should_fail_path = temp_dir_ / "SecKey_rotate_fail.out";
    EXPECT_THROW(manager_.unwrapSecKey(sealed_path.string(), should_fail_path.string(), old_seal_info),
                 evi::InvalidInputError);
}

TEST_F(KeyManagementTest, RotateMetadataKeyUpdatesWrappedPayloadAndStateTimestamp) {
    const std::vector<uint8_t> old_kek = defaultAesKek();
    const std::vector<uint8_t> new_kek = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, old_kek);
    const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, new_kek);
    const std::vector<uint8_t> metadata_bytes = evi::Utils::generateRandomBytes(evi::AES256_KEY_SIZE);

    const fs::path key_path = writeBinary("MetadataKey_rotate.bin", metadata_bytes);
    const fs::path sealed_path = temp_dir_ / "MetadataKey_rotate.json";
    manager_.wrapMetadataKey("metadata-key-rotate", key_path.string(), sealed_path.string(), old_seal_info);

    json original = loadEnvelope(sealed_path);
    original["state"]["updated_at"] = "2000-01-01T00:00:00Z";
    {
        std::ofstream out(sealed_path);
        ASSERT_TRUE(out.good());
        out << original.dump();
    }

    const json original_entry = original.at("entries").front();
    const std::string original_updated_at = original.at("state").at("updated_at").get<std::string>();
    const std::string original_key_version = original.at("key_version").get<std::string>();
    const std::string original_key_data = original_entry.at("key_data").get<std::string>();
    const std::string original_iv = original_entry.at("iv").get<std::string>();
    const std::string original_tag = original_entry.at("tag").get<std::string>();

    manager_.rotateSecKey(sealed_path.string(), old_seal_info, new_seal_info);

    const json rotated = loadEnvelope(sealed_path);
    const json &rotated_entry = rotated.at("entries").front();
    EXPECT_NE(rotated_entry.at("key_data").get<std::string>(), original_key_data);
    EXPECT_NE(rotated_entry.at("iv").get<std::string>(), original_iv);
    EXPECT_NE(rotated_entry.at("tag").get<std::string>(), original_tag);
    EXPECT_EQ(rotated_entry.at("hash").at("value").get<std::string>(), entryPayloadHash(rotated_entry));
    EXPECT_EQ(rotated.at("key_version").get<std::string>(), std::to_string(std::stoul(original_key_version) + 1UL));
    EXPECT_NE(rotated.at("state").at("updated_at").get<std::string>(), original_updated_at);
    EXPECT_EQ(rotated.at("created_at").get<std::string>(), original.at("created_at").get<std::string>());
    EXPECT_EQ(rotated.at("expires_at").get<std::string>(), original.at("expires_at").get<std::string>());

    const fs::path output_path = temp_dir_ / "MetadataKey_rotate.out";
    manager_.unwrapMetadataKey(sealed_path.string(), output_path.string(), new_seal_info);
    EXPECT_EQ(readBinary(output_path), metadata_bytes);

    const fs::path should_fail_path = temp_dir_ / "MetadataKey_rotate_fail.out";
    EXPECT_THROW(manager_.unwrapMetadataKey(sealed_path.string(), should_fail_path.string(), old_seal_info),
                 evi::InvalidInputError);
}

TEST_F(KeyManagementTest, RotateSecKeyAcceptsIntegerKeyVersionAndNormalizesToString) {
    const std::vector<uint8_t> old_kek = defaultAesKek();
    const std::vector<uint8_t> new_kek = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, old_kek);
    const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, new_kek);

    const fs::path key_path = writeBinary("SecKey_rotate_int_version.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_rotate_int_version.json";
    manager_.wrapSecKey("sec-key-rotate-int-version", key_path.string(), sealed_path.string(), old_seal_info);

    json original = loadEnvelope(sealed_path);
    original["key_version"] = 7;
    {
        std::ofstream out(sealed_path);
        ASSERT_TRUE(out.good());
        out << original.dump();
    }

    manager_.rotateSecKey(sealed_path.string(), old_seal_info, new_seal_info);

    const json rotated = loadEnvelope(sealed_path);
    ASSERT_TRUE(rotated.at("key_version").is_string());
    EXPECT_EQ(rotated.at("key_version").get<std::string>(), "8");
}

TEST_F(KeyManagementTest, RotateSecKeyRejectsDeactivatedEnvelopeBeforeCrypto) {
    const std::vector<uint8_t> old_kek = defaultAesKek();
    const std::vector<uint8_t> new_kek = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, old_kek);
    const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, new_kek);

    const fs::path key_path = writeBinary("SecKey_rotate_deactivated.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_rotate_deactivated.json";
    manager_.wrapSecKey("sec-key-rotate-deactivated", key_path.string(), sealed_path.string(), old_seal_info);
    manager_.deactivateSecKey(sealed_path.string(), "rotation blocked");

    const std::string message = captureInvalidInputMessage([&] {
        manager_.rotateSecKey(sealed_path.string(), old_seal_info, new_seal_info);
    });
    EXPECT_NE(message.find("only 'active' keys can be rotated"), std::string::npos);
    EXPECT_NE(message.find("deactivated"), std::string::npos);
}

TEST_F(KeyManagementTest, RotateSecKeyRejectsDestroyedEnvelopeBeforeCrypto) {
    const std::vector<uint8_t> old_kek = defaultAesKek();
    const std::vector<uint8_t> new_kek = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, old_kek);
    const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, new_kek);

    const fs::path key_path = writeBinary("SecKey_rotate_destroyed.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_rotate_destroyed.json";
    manager_.wrapSecKey("sec-key-rotate-destroyed", key_path.string(), sealed_path.string(), old_seal_info);
    manager_.deactivateSecKey(sealed_path.string(), "ready to destroy");
    manager_.destroySecKey(sealed_path.string(), "destroyed");

    const std::string message = captureInvalidInputMessage([&] {
        manager_.rotateSecKey(sealed_path.string(), old_seal_info, new_seal_info);
    });
    EXPECT_NE(message.find("only 'active' keys can be rotated"), std::string::npos);
    EXPECT_NE(message.find("destroyed"), std::string::npos);
}

// ---------------------------------------------------------------------------
// AES-GCM AAD binding tests (GAP-003 + GAP-015)
// ---------------------------------------------------------------------------

TEST(AesGcmAadTest, RoundTripWithAad) {
    std::vector<uint8_t> key(32);
    ASSERT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);

    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    std::vector<uint8_t> aad = {'k', 'i', 'd', ':', 't', 'e', 's', 't', '-', '1'};

    std::vector<uint8_t> iv, ciphertext, tag;
    ASSERT_TRUE(AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag, aad));
    EXPECT_EQ(iv.size(), evi::detail::AES256_IV_SIZE);
    EXPECT_EQ(tag.size(), evi::detail::AES256_TAG_SIZE);

    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(AES::decryptAESGCM(ciphertext, key, iv, decrypted, tag, aad));
    EXPECT_EQ(decrypted, plaintext);
}

TEST(AesGcmAadTest, WrongAadFails) {
    std::vector<uint8_t> key(32);
    ASSERT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);

    std::vector<uint8_t> plaintext = {'s', 'e', 'c', 'r', 'e', 't'};
    std::vector<uint8_t> aad = {'c', 'o', 'r', 'r', 'e', 'c', 't'};
    std::vector<uint8_t> wrong_aad = {'w', 'r', 'o', 'n', 'g'};

    std::vector<uint8_t> iv, ciphertext, tag;
    ASSERT_TRUE(AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag, aad));

    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(AES::decryptAESGCM(ciphertext, key, iv, decrypted, tag, wrong_aad));
}

TEST(AesGcmAadTest, MissingAadFails) {
    std::vector<uint8_t> key(32);
    ASSERT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);

    std::vector<uint8_t> plaintext = {'d', 'a', 't', 'a'};
    std::vector<uint8_t> aad = {'b', 'i', 'n', 'd'};

    std::vector<uint8_t> iv, ciphertext, tag;
    ASSERT_TRUE(AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag, aad));

    // Decrypt without AAD should fail
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(AES::decryptAESGCM(ciphertext, key, iv, decrypted, tag));
}

TEST(AesGcmAadTest, EmptyAadBackwardCompat) {
    std::vector<uint8_t> key(32);
    ASSERT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};

    // Encrypt with default (empty) AAD
    std::vector<uint8_t> iv, ciphertext, tag;
    ASSERT_TRUE(AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag));

    // Decrypt with default (empty) AAD
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(AES::decryptAESGCM(ciphertext, key, iv, decrypted, tag));
    EXPECT_EQ(decrypted, plaintext);
}

// ---------------------------------------------------------------------------
// S-6: Empty plaintext + non-empty AAD (GCM authentication-only mode)
// ---------------------------------------------------------------------------

TEST(AesGcmAadTest, EmptyPlaintextWithAad) {
    std::vector<uint8_t> key(32);
    ASSERT_EQ(RAND_bytes(key.data(), static_cast<int>(key.size())), 1);

    std::vector<uint8_t> plaintext; // empty
    std::vector<uint8_t> aad = {'a', 'u', 't', 'h', '-', 'o', 'n', 'l', 'y'};

    std::vector<uint8_t> iv, ciphertext, tag;
    ASSERT_TRUE(AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag, aad));
    EXPECT_TRUE(ciphertext.empty());
    EXPECT_EQ(tag.size(), evi::detail::AES256_TAG_SIZE);

    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(AES::decryptAESGCM(ciphertext, key, iv, decrypted, tag, aad));
    EXPECT_TRUE(decrypted.empty());

    // Tampered AAD must fail even with empty plaintext
    std::vector<uint8_t> bad_aad = {'t', 'a', 'm', 'p', 'e', 'r', 'e', 'd'};
    std::vector<uint8_t> decrypted2;
    EXPECT_FALSE(AES::decryptAESGCM(ciphertext, key, iv, decrypted2, tag, bad_aad));
}

// ---------------------------------------------------------------------------
// S-5: Canonicalized envelope output (key ordering, compact format)
//
// canonicalizeJson and sortJsonKeys live in an anonymous namespace inside
// KeyManagerImpl.cpp so they cannot be tested directly.  Instead we verify
// observable behavior: wrap produces key-sorted, compact JSON output.
// ---------------------------------------------------------------------------

TEST_F(KeyManagementTest, WrapProducesCanonicalizedEnvelopeOutput) {
    const fs::path key_path = writeBinary("EncKey.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_canonical.json";

    manager_.wrapEncKey("canonical-test", key_path.string(), sealed_path.string());

    // Read raw JSON text from disk
    std::ifstream in(sealed_path);
    ASSERT_TRUE(in.good());
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    // Compact: no newlines or indentation
    EXPECT_EQ(raw.find('\n'), std::string::npos) << "Envelope should be compact (single line)";

    // Key ordering: verify top-level keys appear in sorted order.
    // Canonical order: "aad" < "created_at" < "entries" < "kid" < "usage"
    auto pos_aad = raw.find("\"aad\"");
    auto pos_created = raw.find("\"created_at\"");
    auto pos_entries = raw.find("\"entries\"");
    auto pos_kid = raw.find("\"kid\"");
    auto pos_usage = raw.find("\"usage\"");

    // All keys must be present
    ASSERT_NE(pos_aad, std::string::npos);
    ASSERT_NE(pos_created, std::string::npos);
    ASSERT_NE(pos_entries, std::string::npos);
    ASSERT_NE(pos_kid, std::string::npos);
    ASSERT_NE(pos_usage, std::string::npos);

    // Keys must appear in lexicographic order
    EXPECT_LT(pos_aad, pos_created) << "aad must precede created_at";
    EXPECT_LT(pos_created, pos_entries) << "created_at must precede entries";
    EXPECT_LT(pos_entries, pos_kid) << "entries must precede kid";
    EXPECT_LT(pos_kid, pos_usage) << "kid must precede usage";

    // Round-trip: unwrap should succeed (proves the canonicalized output is valid)
    std::ifstream envelope_stream(sealed_path, std::ios::binary);
    ASSERT_TRUE(envelope_stream.good());
    std::stringstream unwrapped;
    manager_.unwrapEncKey(envelope_stream, unwrapped);
    std::vector<uint8_t> recovered(std::istreambuf_iterator<char>(unwrapped), {});
    EXPECT_EQ(recovered, enc_payload_);
}

TEST_F(KeyManagementTest, DeactivatePubKeyTransitionsEnvelopeToDeactivatedAndBlocksUnwrap) {
    const fs::path key_path = writeBinary("EncKey_lifecycle.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_lifecycle.json";
    const fs::path restored_path = temp_dir_ / "EncKey_lifecycle.out";

    manager_.wrapEncKey("enc-lifecycle", key_path.string(), sealed_path.string());
    manager_.deactivatePubKey(sealed_path.string(), "key compromise suspected");

    const json envelope = loadEnvelope(sealed_path);
    ASSERT_TRUE(envelope.contains("state"));
    EXPECT_EQ(envelope.at("state").at("value").get<std::string>(), "deactivated");
    EXPECT_EQ(envelope.at("state").at("reason").get<std::string>(), "key compromise suspected");
    EXPECT_FALSE(envelope.at("state").at("updated_at").get<std::string>().empty());

    const std::string error = captureInvalidInputMessage([&] {
        manager_.unwrapEncKey(sealed_path.string(), restored_path.string());
    });
    EXPECT_NE(error.find("deactivated"), std::string::npos);
    EXPECT_NE(error.find("unwrap is not allowed"), std::string::npos);
}

TEST_F(KeyManagementTest, DestroyPubKeyRequiresDeactivatedStateAndPreservesEnvelopeMetadata) {
    const fs::path key_path = writeBinary("EvalKey_lifecycle.bin", eval_payload_);
    const fs::path sealed_path = temp_dir_ / "EvalKey_lifecycle.json";
    const fs::path restored_path = temp_dir_ / "EvalKey_lifecycle.out";

    manager_.wrapEvalKey("eval-lifecycle", key_path.string(), sealed_path.string());
    manager_.deactivatePubKey(sealed_path.string(), "rotation complete");
    manager_.destroyPubKey(sealed_path.string(), "retention expired");

    const json envelope = loadEnvelope(sealed_path);
    ASSERT_TRUE(envelope.contains("state"));
    EXPECT_EQ(envelope.at("state").at("value").get<std::string>(), "destroyed");
    EXPECT_EQ(envelope.at("state").at("reason").get<std::string>(), "retention expired");
    ASSERT_TRUE(envelope.contains("entries"));
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    EXPECT_TRUE(envelope.at("entries").front().contains("key_data"));
    EXPECT_TRUE(envelope.at("entries").front().contains("hash"));

    const std::string error = captureInvalidInputMessage([&] {
        manager_.unwrapEvalKey(sealed_path.string(), restored_path.string());
    });
    EXPECT_NE(error.find("destroyed"), std::string::npos);
    EXPECT_NE(error.find("unwrap is not allowed"), std::string::npos);
}

TEST_F(KeyManagementTest, DeactivateAndDestroySecKeyHappyPathUpdatesStateAndBlocksUnseal) {
    const fs::path key_path = writeBinary("SecKey_lifecycle.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_lifecycle.json";
    const fs::path restored_path = temp_dir_ / "SecKey_lifecycle.out";

    manager_.wrapSecKey("sec-lifecycle", key_path.string(), sealed_path.string());
    manager_.deactivateSecKey(sealed_path.string(), "rotation complete");

    {
        const json revoked = loadEnvelope(sealed_path);
        ASSERT_TRUE(revoked.contains("state"));
        EXPECT_EQ(revoked.at("state").at("value").get<std::string>(), "deactivated");
        EXPECT_EQ(revoked.at("state").at("reason").get<std::string>(), "rotation complete");
    }

    const std::string revoked_error = captureInvalidInputMessage([&] {
        manager_.unwrapSecKey(sealed_path.string(), restored_path.string());
    });
    EXPECT_NE(revoked_error.find("deactivated"), std::string::npos);
    EXPECT_NE(revoked_error.find("unwrap is not allowed"), std::string::npos);

    manager_.destroySecKey(sealed_path.string(), "retention expired");

    const json destroyed = loadEnvelope(sealed_path);
    ASSERT_TRUE(destroyed.contains("state"));
    EXPECT_EQ(destroyed.at("state").at("value").get<std::string>(), "destroyed");
    EXPECT_EQ(destroyed.at("state").at("reason").get<std::string>(), "retention expired");
    ASSERT_TRUE(destroyed.contains("entries"));
    ASSERT_TRUE(destroyed.at("entries").is_array());
    ASSERT_FALSE(destroyed.at("entries").empty());
    EXPECT_FALSE(destroyed.at("entries").front().contains("key_data"));

    const std::string destroyed_error = captureInvalidInputMessage([&] {
        manager_.unwrapSecKey(sealed_path.string(), restored_path.string());
    });
    EXPECT_NE(destroyed_error.find("destroyed"), std::string::npos);
    EXPECT_NE(destroyed_error.find("unwrap is not allowed"), std::string::npos);
}

TEST_F(KeyManagementTest, DestroySecKeyRejectsInvalidTransitionFromActive) {
    const fs::path key_path = writeBinary("SecKey_transition.bin", sec_payload_);
    const fs::path sealed_path = temp_dir_ / "SecKey_transition.json";

    manager_.wrapSecKey("sec-transition", key_path.string(), sealed_path.string());

    const std::string error = captureInvalidInputMessage([&] {
        manager_.destroySecKey(sealed_path.string(), "skip deactivate");
    });
    EXPECT_NE(error.find("Cannot transition key"), std::string::npos);
    EXPECT_NE(error.find("'active'"), std::string::npos);
    EXPECT_NE(error.find("'destroyed'"), std::string::npos);
    EXPECT_NE(error.find("'deactivated'"), std::string::npos);
}

TEST_F(KeyManagementTest, DeactivatePubKeyRejectsEmptyReason) {
    const fs::path key_path = writeBinary("EncKey_reason.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_reason.json";

    manager_.wrapEncKey("enc-empty-reason", key_path.string(), sealed_path.string());

    const std::string error = captureInvalidInputMessage([&] {
        manager_.deactivatePubKey(sealed_path.string(), "   ");
    });
    EXPECT_NE(error.find("State transition reason must not be empty"), std::string::npos);
}

TEST_F(KeyManagementTest, UnwrapRejectsInvalidEnvelopeStateValue) {
    const fs::path key_path = writeBinary("EncKey_invalid_state.bin", enc_payload_);
    const fs::path sealed_path = temp_dir_ / "EncKey_invalid_state.json";
    const fs::path restored_path = temp_dir_ / "EncKey_invalid_state.out";

    manager_.wrapEncKey("enc-invalid-state", key_path.string(), sealed_path.string());
    json envelope = loadEnvelope(sealed_path);
    envelope["state"]["value"] = "suspended";
    std::ofstream out(sealed_path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.good());
    out << envelope.dump();
    out.close();

    const std::string error = captureInvalidInputMessage([&] {
        manager_.unwrapEncKey(sealed_path.string(), restored_path.string());
    });
    EXPECT_NE(error.find("Invalid key state 'suspended'"), std::string::npos);
}

TEST(KeyManagerCommonTest, DetectsVersionRecordPathBySuffix) {
    EXPECT_TRUE(evi::detail::common::isVersionRecordPath("tenant/key/metadata/SecKey.json"));
    EXPECT_FALSE(evi::detail::common::isVersionRecordPath("tenant/key/SecKey.json"));
    EXPECT_FALSE(evi::detail::common::isVersionRecordPath("tenant/key/versions/SecKey.json"));
    EXPECT_FALSE(evi::detail::common::isVersionRecordPath("tenant/key/metadata/SecKey.txt"));
}
