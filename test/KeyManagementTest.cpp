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
#include "km/KeyManager.hpp"
#include "km/ProviderMeta.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include "EVI/Context.hpp"
#include "EVI/KeyGenerator.hpp"
#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "nlohmann/json.hpp"
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

} // namespace

class KeyManagementTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
        temp_dir_ = fs::temp_directory_path() / ("evi_key_mgmt_test_" + std::to_string(unique));
        fs::create_directories(temp_dir_);

        manager_ = evi::makeKeyManager();

        evi::LocalProviderMeta provider_meta;
        provider_ = evi::detail::KeyProvider(std::make_shared<evi::detail::LocalKeyProvider>(provider_meta));

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
    };

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

    evi::KeyManager manager_;
    evi::detail::KeyProvider provider_{std::shared_ptr<evi::detail::KeyProviderInterface>()};
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
    EXPECT_FALSE(entry.at("hash").get<std::string>().empty());
    EXPECT_EQ(envelope.at("provider_meta").at("type").get<std::string>(), "LOCAL");
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
    EXPECT_FALSE(entry.at("hash").get<std::string>().empty());
    EXPECT_EQ(envelope.at("provider_meta").at("type").get<std::string>(), "LOCAL");
}

TEST_F(KeyManagementTest, WrapEvalKeyProducesExpectedEnvelope) {
    const std::vector<uint8_t> bytes = eval_payload_;
    const fs::path key_path = writeBinary("EvalKey.bin", bytes);
    const fs::path sealed_path = temp_dir_ / "EvalKey.json";

    manager_.wrapEvalKey("eval-key-id", key_path.string(), sealed_path.string());

    const json envelope = loadEnvelope(sealed_path);
    EXPECT_EQ(envelope.at("kid").get<std::string>(), "eval-key-id");
    EXPECT_EQ(envelope.at("usage").get<std::string>(), "evaluation");
    ASSERT_TRUE(envelope.at("entries").is_array());
    ASSERT_FALSE(envelope.at("entries").empty());
    const json &entry = envelope.at("entries").front();
    EXPECT_EQ(entry.at("name").get<std::string>(), "evalkey");
    EXPECT_EQ(entry.at("role").get<std::string>(), "evaluation key");
    EXPECT_EQ(entry.at("key_data").get<std::string>(), encode(bytes));
    EXPECT_FALSE(entry.at("hash").get<std::string>().empty());
    EXPECT_EQ(envelope.at("provider_meta").at("type").get<std::string>(), "LOCAL");
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
    provider_->decapEncKey(envelope_stream, out_stream);

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
    provider_->decapEvalKey(envelope_stream, out_stream);

    const std::string decoded = out_stream.str();
    std::vector<uint8_t> decoded_bytes(decoded.begin(), decoded.end());
    EXPECT_EQ(decoded_bytes, bytes);
}
