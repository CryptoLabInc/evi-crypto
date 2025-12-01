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

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <string>

#include "EVI/Const.hpp"
#include "EVI/impl/DecryptorImpl.hpp"
#include "EVI/impl/EncryptorImpl.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "utils.hpp"
#include "utils/SealInfo.hpp"
#include "utils/Utils.hpp"

using namespace evi::detail;
namespace fs = std::filesystem;

constexpr double MAX_ERROR = 1.0 / 64.0;
constexpr int TEST_DEVICE_NUM = 0;

class EnDecryptTest : public ::testing::Test {
protected:
    static void SetUpTestCase() {
        srand(time(NULL));
        rank = rand() % (4096 - 32 + 1) + 32;
        std::cout << "RANK : " << rank << std::endl;
        preset = evi::ParameterPreset::IP0;
        test_key_path = "tests_keys/";
        test_pcmm_key_path = "tests_pcmm_keys/";
        auto evi_preset = evi::detail::setPreset(preset);
        std::cout << "Testing parameter : " << getParamToString(preset) << std::endl;
        db_scale = static_cast<double>(evi_preset->getPrimeP());
    }

    static void TearDownTestCase() {
        try {
            if (fs::exists(test_key_path)) {
                fs::remove_all(test_key_path);
                std::cout << "Deleted test_key_path directory: " << test_key_path << std::endl;
            }
            if (fs::exists(test_pcmm_key_path)) {
                fs::remove_all(test_pcmm_key_path);
                std::cout << "Deleted test_pcmm_key_path directory: " << test_pcmm_key_path << std::endl;
            }
        } catch (const std::exception &e) {
            std::cerr << "Failed to delete test_pcmm_key_path: " << e.what() << std::endl;
        }
    }

    static u32 rank;
    static evi::ParameterPreset preset;
    static double db_scale;
    static std::string test_key_path;
    static std::string test_pcmm_key_path;
};

u32 EnDecryptTest::rank = 0;
evi::ParameterPreset EnDecryptTest::preset;
double EnDecryptTest::db_scale = 0.0;
std::string EnDecryptTest::test_key_path = "";
std::string EnDecryptTest::test_pcmm_key_path = "";
evi::DeviceType device_type = evi::DeviceType::CPU;

TEST_F(EnDecryptTest, BaseQueryEncDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::FLAT);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sec_key = keygen->genSecKey();

    keygen->genPubKeys(sec_key);

    Encryptor enc = makeEncryptor(context, pack);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0);
    randomFaces(msg.data(), -1, 1, 1, rank);

    auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
    auto dmsg = dec->decrypt(query, sec_key);

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);

    query = enc->encrypt(msg, evi::EncodeType::QUERY);
    dmsg = dec->decrypt(query, sec_key);

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, RMPQueryEncDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::RMP);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sec_key = keygen->genSecKey();

    keygen->genPubKeys(sec_key);

    Encryptor enc = makeEncryptor(context, pack);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0);
    randomFaces(msg.data(), -1, 1, 1, rank);

    auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
    auto dmsg = dec->decrypt(query, sec_key);

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);

    query = enc->encrypt(msg, evi::EncodeType::QUERY);
    dmsg = dec->decrypt(query, sec_key);

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, RMPBulkEncDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::RMP);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sec_key = keygen->genSecKey();

    keygen->genPubKeys(sec_key);

    Encryptor enc = makeEncryptor(context, pack);
    Decryptor dec = makeDecryptor(context);
    std::random_device rd;                       // Declare the random device
    std::mt19937 gen(rd());                      // Mersenne Twister random number engine
    std::uniform_int_distribution<> dis(1, 128); // Range [1, 128]
    int random_number = dis(gen);

    std::vector<std::vector<float>> msg;
    for (int i = 0; i < random_number; ++i) {
        msg.emplace_back(std::vector<float>(DEGREE, 0));
        randomFaces(msg[i].data(), -1, 1, 1, rank);
    }
    auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
    int idx = 0;
    for (int q = 0; q < query.size(); ++q) {
        for (int i = 0; i < query[q][0]->n; ++i) {
            auto dmsg = dec->decrypt(i, query[q], sec_key);
            EXPECT_LE(maxError(msg[idx++], dmsg), MAX_ERROR);
        }
    }
}

TEST_F(EnDecryptTest, StreamKeyEncDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::FLAT);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sec_key = keygen->genSecKey();
    keygen->genPubKeys(sec_key);

    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0);
    randomFaces(msg.data(), -1, 1, 1, rank);

    std::ostringstream enc_key_buffer(std::ios::binary | std::ios::out);
    pack->getEncKeyBuffer(enc_key_buffer);
    const std::string enc_blob = enc_key_buffer.str();

    std::ostringstream sec_key_buffer(std::ios::binary | std::ios::out);
    sec_key->saveSecKey(sec_key_buffer);
    const std::string sec_blob = sec_key_buffer.str();

    std::istringstream enc_stream(enc_blob, std::ios::binary | std::ios::in);
    auto query = enc->encrypt(msg, enc_stream, evi::EncodeType::ITEM, 0, std::nullopt);
    std::istringstream sec_stream(sec_blob, std::ios::binary | std::ios::in);
    auto dmsg = dec->decrypt(query, sec_stream, std::nullopt);
    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);

    std::istringstream enc_stream2(enc_blob, std::ios::binary | std::ios::in);
    auto query2 = enc->encrypt(msg, enc_stream2, evi::EncodeType::QUERY, 0, std::nullopt);
    std::istringstream sec_stream2(sec_blob, std::ios::binary | std::ios::in);
    auto dmsg2 = dec->decrypt(query2, sec_stream2, std::nullopt);
    EXPECT_LE(maxError(dmsg2, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, MultiKeyGenSeDeserializeEnDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::RMP);
    SealInfo s_info(evi::SealMode::NONE);
    std::vector<Context> contexts = {context};
    std::string key_dir = "stream_key/";

    MultiKeyGenerator keygen(contexts, key_dir, s_info);
    std::ostringstream key_streams(std::ios::binary);
    auto sec_key = keygen.generateKeys(key_streams);

    KeyPack restored_pack = makeKeyPack(context);
    SecretKey restored_sec = makeSecKey(context);
    std::istringstream serialized_key(key_streams.str(), std::ios::binary);
    utils::deserializeKeyFiles(serialized_key, restored_sec, restored_pack);

    Encryptor enc = makeEncryptor(context, restored_pack);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0.0f);
    randomFaces(msg.data(), -1, 1, 1, rank);

    auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
    auto dmsg = dec->decrypt(query, restored_sec);
    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);

    query = enc->encrypt(msg, evi::EncodeType::QUERY);
    dmsg = dec->decrypt(query, restored_sec);
    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, InvalidKeyDecryptionTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::FLAT);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    // gen seckey
    auto sec_key_a = keygen->genSecKey();
    keygen->genPubKeys(sec_key_a);

    Encryptor enc = makeEncryptor(context, pack);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0);
    randomFaces(msg.data(), -1, 1, 1, rank);
    auto ctxt = enc->encrypt(msg, evi::EncodeType::ITEM);

    // gen another seckey
    auto sec_key_b = keygen->genSecKey();
    auto dec_b = dec->decrypt(ctxt, sec_key_b);

    // The result must exceed MAX_ERROR
    EXPECT_GT(maxError(dec_b, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, MultiKeyGeneratorTest) {
    std::vector<Context> contexts;
    preset = evi::ParameterPreset::IP0;

    for (uint32_t r = evi::MIN_CONTEXT_SIZE; r <= evi::DEGREE; r *= 2) {
        contexts.emplace_back(makeContext(preset, evi::DeviceType::CPU, r, evi::EvalMode::FLAT));
    }
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    MultiKeyGenerator keygen(contexts, test_key_path, s_info);
    auto sec_key = keygen.generateKeys();

    Context context = makeContext(preset, device_type, rank, evi::EvalMode::FLAT);
    Encryptor enc = makeEncryptor(context, test_key_path + "EncKey.bin");
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0);
    randomFaces(msg.data(), -1, 1, 1, rank);

    auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
    auto dmsg = dec->decrypt(query, test_key_path + "SecKey.bin");

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);

    query = enc->encrypt(msg, evi::EncodeType::QUERY);
    dmsg = dec->decrypt(query, test_key_path + "SecKey.bin");

    EXPECT_LE(maxError(dmsg, msg), MAX_ERROR);
}

TEST_F(EnDecryptTest, PCMMEncDecTest) {
    int n = 10000;
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    preset = evi::ParameterPreset::IP1;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM);

    std::vector<Context> contexts = {context};
    MultiKeyGenerator keygen(contexts, test_pcmm_key_path, s_info);
    keygen.generateKeys();

    std::string path = test_pcmm_key_path + "EncKey.bin";
    KeyPack pack = makeKeyPack(context, path);

    Encryptor enc = makeEncryptor(context);
    std::vector<std::vector<float>> db_templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; i++) {
        randomFaces(db_templates[i].data(), -1, 1, 1, rank);
    }

    auto ctxts = enc->encrypt(db_templates, pack, evi::EncodeType::ITEM, 0, std::nullopt);

    Decryptor dec = makeDecryptor(context);
    // Decrypt each matrix query and stitch columns into a single message
    Message dmsg(n * rank);
    for (size_t m = 0; m < ctxts.size(); ++m) {
        const auto part = dec->decrypt(ctxts[m], test_pcmm_key_path + "SecKey.bin", std::nullopt);
        const int used_cols = std::min<int>(DEGREE, n - static_cast<int>(m) * static_cast<int>(DEGREE));
        for (int j = 0; j < used_cols; ++j) {
            std::memcpy(dmsg.data() + (m * DEGREE + j) * rank, part.data() + j * rank, sizeof(float) * rank);
        }
    }

    float global_max_error = 0.0f;
    for (int i = 0; i < n; i++) {
        auto original = evi::span<float>(db_templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        float max_error = maxError(original, decoded);
        if (max_error > global_max_error) {
            global_max_error = max_error;
        }
    }
    EXPECT_LE(global_max_error, MAX_ERROR);
}
