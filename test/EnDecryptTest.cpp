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
#include <filesystem>
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
        db_scale = static_cast<double>(deb_prime_at(evi_preset.get(), 1));
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

TEST_F(EnDecryptTest, SingleEncDecTest) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::SINGLE);
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
}

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

// =============================================================================
// RMP inner-rank / padRank dimension coverage (getInnerRank pad-first fix).
//
// The inner rank for RMP is derived from the dimension PADDED up to the next
// power of two: inner = 2^floor(log2(nextPow2(dim))/2), floored at 32. Over the
// supported range [MIN_CONTEXT_SIZE=32, MAX_CONTEXT_SIZE=4096] this is exactly
// 32 for dim in [32, 2048] and 64 for dim in [2049, 4096] (64 reachable for the
// whole upper band, not only at dim==4096). The eval-key file is named by
// padRank, so before the fix dims in (2048, 4095] generated keys named EVIKeys64
// but were loaded as EVIKeys32 -> FileNotFoundError on the bundle round-trip.
// =============================================================================

// Exhaustive over EVERY dimension in the supported range (context construction
// only, no keygen) so no dimension is skipped: assert the context's padRank is
// the pad-first inner rank. This is the cheap, complete guard on the fix.
TEST_F(EnDecryptTest, RMP_PadRank_AllDims_PadFirstInnerRank) {
    for (int dim = static_cast<int>(evi::MIN_CONTEXT_SIZE); dim <= static_cast<int>(evi::MAX_CONTEXT_SIZE); ++dim) {
        Context context = makeContext(preset, device_type, dim, evi::EvalMode::RMP);
        const uint32_t expected = (dim <= 2048) ? 32u : 64u;
        ASSERT_EQ(context->getPadRank(), expected) << "padRank mismatch at dim=" << dim;
    }
}

// Full keygen -> stream-serialize -> deserialize -> encrypt -> decrypt cycle
// (the path that surfaced the EVIKeys<padRank> load mismatch) with the message
// sized to `dim`, checking the decrypted max error across a dimension sweep that
// covers every power of two, the 2048/2049 inner-rank transition, the
// just-below-power-of-two edges, and dense samples spanning the whole range.
// Flip kExhaustiveDimSweep to run the full cycle on EVERY integer dim (slow:
// one keygen per dim).
TEST_F(EnDecryptTest, RMP_StreamSeDe_EnDec_MaxError_DimSweep) {
    constexpr bool kExhaustiveDimSweep = false;

    std::vector<int> dims;
    if (kExhaustiveDimSweep) {
        for (int d = static_cast<int>(evi::MIN_CONTEXT_SIZE); d <= static_cast<int>(evi::MAX_CONTEXT_SIZE); ++d) {
            dims.push_back(d);
        }
    } else {
        dims = {32,   33,   63,   64,   100,  127,  128,  200,  255,  256,  400,  511,  512,  800, 1000,
                1023, 1024, 1500, 2000, 2047, 2048, 2049, 2050, 2500, 3000, 3500, 4000, 4095, 4096};
    }

    for (int dim : dims) {
        SCOPED_TRACE("dim=" + std::to_string(dim));
        Context context = makeContext(preset, device_type, dim, evi::EvalMode::RMP);

        // Sanity: padRank follows the pad-first inner rank for this dim.
        ASSERT_EQ(context->getPadRank(), (dim <= 2048) ? 32u : 64u);

        SealInfo s_info(evi::SealMode::NONE);
        std::vector<Context> contexts = {context};
        const std::string key_dir = "stream_key_dimsweep/";
        MultiKeyGenerator keygen(contexts, key_dir, s_info);
        std::ostringstream key_streams(std::ios::binary);
        auto sec_key = keygen.generateKeys(key_streams);

        KeyPack restored_pack = makeKeyPack(context);
        SecretKey restored_sec = makeSecKey(context);
        std::istringstream serialized_key(key_streams.str(), std::ios::binary);
        // Before the fix this threw FileNotFoundError(".../dump/EVIKeys32.bin")
        // for dim in (2048, 4095].
        ASSERT_NO_THROW(utils::deserializeKeyFiles(serialized_key, restored_sec, restored_pack))
            << "eval-key load failed at dim=" << dim;

        Encryptor enc = makeEncryptor(context, restored_pack);
        Decryptor dec = makeDecryptor(context);

        // Use the established RMP idiom (cf. MultiKeyGenSeDeserializeEnDecTest /
        // RMPQueryEncDecTest): a DEGREE-sized message with the first `dim` slots
        // populated, compared via maxError. RMP packs/unpacks against the full
        // DEGREE layout, so the decrypted vector aligns element-wise with this
        // DEGREE-sized input; a `dim`-sized input does NOT round-trip to the same
        // linear order (the decoded values land in different positions), which is
        // a property of the packing, not a decryption error.
        std::vector<float> msg(DEGREE, 0.0f);
        randomFaces(msg.data(), -1, 1, 1, dim);

        auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
        auto dmsg = dec->decrypt(query, restored_sec);
        EXPECT_LE(maxError(dmsg, msg), MAX_ERROR) << "ITEM decrypt error too high at dim=" << dim;

        query = enc->encrypt(msg, evi::EncodeType::QUERY);
        dmsg = dec->decrypt(query, restored_sec);
        EXPECT_LE(maxError(dmsg, msg), MAX_ERROR) << "QUERY decrypt error too high at dim=" << dim;
    }
}

TEST_F(EnDecryptTest, DistinctSecretKeysAreGenerated) {
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::FLAT);
    KeyGenerator keygen = makeKeyGenerator(context);

    auto sec_key_a = keygen->genSecKey();
    auto sec_key_b = keygen->genSecKey();

    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    std::vector<float> msg(DEGREE, 0.0f);
    randomFaces(msg.data(), -1, 1, 1, rank);

    auto ctxt = enc->encrypt(msg, sec_key_a, evi::EncodeType::ITEM);
    auto dec_a = dec->decrypt(ctxt, sec_key_a);
    auto dec_b = dec->decrypt(ctxt, sec_key_b);

    EXPECT_LE(maxError(dec_a, msg), MAX_ERROR);
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

TEST_F(EnDecryptTest, PCMMLevelOneEncDecTestUsingIP1) {
    preset = evi::ParameterPreset::IP1;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string level1_pcmm_path = test_pcmm_key_path + "level1/";
    fs::create_directories(level1_pcmm_path);
    MultiKeyGenerator keygen(contexts, level1_pcmm_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, level1_pcmm_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    // round-trip query serialization
    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, level1_pcmm_path + "SecKey.bin", std::nullopt);

    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, PCMMLevelOneItemEncDecTestUsingIP1) {
    preset = evi::ParameterPreset::IP1;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string level1_pcmm_item_path = test_pcmm_key_path + "level1_item/";
    fs::create_directories(level1_pcmm_item_path);
    MultiKeyGenerator keygen(contexts, level1_pcmm_item_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, level1_pcmm_item_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 10;
    std::vector<std::vector<float>> items(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(items[i].data(), -1, 1, 1, rank);
    }

    auto item_queries = enc->encrypt(items, pack, evi::EncodeType::ITEM, /*level=*/1, std::nullopt);
    ASSERT_EQ(item_queries.size(), 1);
    EXPECT_EQ(item_queries.front().front()->getLevel(), 1);

    std::stringstream item_stream;
    evi::detail::utils::serializeQueryTo(item_queries.front(), item_stream);
    evi::detail::Query loaded_item_queries = evi::detail::utils::deserializeQueryFrom(item_stream);

    const auto dmsg = dec->decrypt(loaded_item_queries, level1_pcmm_item_path + "SecKey.bin", std::nullopt);

    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(items[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, IP2_MMS_EncDecTest) {
    preset = evi::ParameterPreset::IP2;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MMS);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip2_mms_path = test_pcmm_key_path + "ip2_mms/";
    fs::create_directories(ip2_mms_path);
    MultiKeyGenerator keygen(contexts, ip2_mms_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip2_mms_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, ip2_mms_path + "SecKey.bin", std::nullopt);

    // IP2 has lower precision (~9.9 bits vs ~15 bits for IP0)
    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP2_MMS] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, IP3_MM_EncDecTest) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_mm_path = test_pcmm_key_path + "ip3_mm/";
    fs::create_directories(ip3_mm_path);
    MultiKeyGenerator keygen(contexts, ip3_mm_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_mm_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP3M').
    constexpr unsigned K_SEED = 0x4950334du;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, ip3_mm_path + "SecKey.bin", std::nullopt);

    // IP3 (30-bit Q/P) has ~10.5-bit precision; well within MAX_ERROR (1/64).
    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP3_MM] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, IP3_MMS_EncDecTest) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MMS);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_mms_path = test_pcmm_key_path + "ip3_mms/";
    fs::create_directories(ip3_mms_path);
    MultiKeyGenerator keygen(contexts, ip3_mms_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_mms_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP3S').
    constexpr unsigned K_SEED = 0x49503353u;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, ip3_mms_path + "SecKey.bin", std::nullopt);

    // IP3 (30-bit Q/P) has ~10.5-bit precision; well within MAX_ERROR (1/64).
    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP3_MMS] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, IP3_MM32_EncDecTest) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM32);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_mm32_path = test_pcmm_key_path + "ip3_mm32/";
    fs::create_directories(ip3_mm32_path);
    MultiKeyGenerator keygen(contexts, ip3_mm32_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_mm32_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP32').
    constexpr unsigned K_SEED = 0x49503332u;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, ip3_mm32_path + "SecKey.bin", std::nullopt);

    // IP3 MM32 (u32 storage path) — same precision as IP3 MM.
    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP3_MM32] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

TEST_F(EnDecryptTest, IP3_MMS32_EncDecTest) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MMS32);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_mms32_path = test_pcmm_key_path + "ip3_mms32/";
    fs::create_directories(ip3_mms32_path);
    MultiKeyGenerator keygen(contexts, ip3_mms32_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_mms32_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP35').
    constexpr unsigned K_SEED = 0x49503533u;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded_queries = evi::detail::utils::deserializeQueryFrom(query_stream);

    const auto dmsg = dec->decrypt(loaded_queries, ip3_mms32_path + "SecKey.bin", std::nullopt);

    // IP3 MMS32 (u32 + shared-A; production hot path) — measured ~5.8e-4 max error.
    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP3_MMS32] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

// Regression (#703 follow-up): decrypting a fresh IP3 typed query directly --
// without the serialize/deserialize round-trip the other IP3 tests perform --
// used to throw InvalidAccessError; it must now succeed and match the round-trip.
TEST_F(EnDecryptTest, IP3_MMS32_DirectDecryptNoRoundTrip) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MMS32);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_path = test_pcmm_key_path + "ip3_mms32_direct/";
    fs::create_directories(ip3_path);
    MultiKeyGenerator keygen(contexts, ip3_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP3R' = direct-decrypt Regression).
    constexpr unsigned K_SEED = 0x49503352u;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    // Sanity: the fresh query really is in typed state (the condition the fix guards).
    ASSERT_NE(queries[0].getTypedDataState(), nullptr);

    // Direct decrypt of the typed query -- must NOT throw and must decode correctly.
    Message dmsg_direct;
    ASSERT_NO_THROW(dmsg_direct = dec->decrypt(queries[0], ip3_path + "SecKey.bin", std::nullopt));

    // Reference: the validated serialize/deserialize round-trip path.
    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    evi::detail::Query loaded = evi::detail::utils::deserializeQueryFrom(query_stream);
    const auto dmsg_ref = dec->decrypt(loaded, ip3_path + "SecKey.bin", std::nullopt);

    // The internal flatten round-trips through the same serializer, so the direct
    // path must equal the reference bit-for-bit across the full payload.
    ASSERT_EQ(dmsg_direct.size(), dmsg_ref.size());
    for (size_t i = 0; i < dmsg_ref.size(); ++i) {
        ASSERT_EQ(dmsg_direct[i], dmsg_ref[i]) << "mismatch at index " << i;
    }

    float max_error = 0.0f;
    for (int i = 0; i < n; ++i) {
        auto original = evi::span<float>(templates[i].data(), rank);
        auto decoded = evi::span<float>(dmsg_direct.data() + i * rank, rank);
        max_error = std::max(max_error, maxError(original, decoded));
    }
    std::cout << "[IP3_MMS32_Direct] max_error=" << max_error << std::endl;
    EXPECT_LE(max_error, MAX_ERROR);
}

// Deserialize a query stream into u32-typed CIPHER blocks (SingleBlock<CIPHER,
// u32>), so the decrypt path takes the u32-native branch (isU32()==true). This
// mirrors deserializeQueryFrom's outer-stream framing exactly (header,
// query_type, dtype, size) but materializes u32 blocks instead of the default
// u64 ones — letting us decrypt the SAME wire bytes both ways for a bit-equality
// differential.
static evi::detail::Query deserializeQueryAsU32(std::istream &is) {
    namespace ser = evi::detail::serialization;
    auto header = ser::readHeader(is);
    if (header.has_header && header.version != ser::kVersionV1) {
        throw evi::NotSupportedError("Unsupported query serialization version");
    }
    uint8_t query_type_raw = 0;
    is.read(reinterpret_cast<char *>(&query_type_raw), sizeof(query_type_raw));
    if (query_type_raw != static_cast<uint8_t>(evi::QueryType::SINGLE)) {
        throw evi::NotSupportedError("u32 differential helper supports only SINGLE queries");
    }
    evi::DataType t;
    is.read(reinterpret_cast<char *>(&t), 1);
    if (t != evi::DataType::CIPHER) {
        throw evi::NotSupportedError("u32 differential helper supports only CIPHER blocks");
    }
    u32 size = 0;
    is.read(reinterpret_cast<char *>(&size), sizeof(u32));
    evi::detail::Query res;
    for (u32 i = 0; i < size; ++i) {
        res.emplace_back(std::make_shared<evi::detail::SingleBlock<evi::DataType::CIPHER, u32>>(is));
    }
    return res;
}

// #703 differential: ONE fixed-seed IP3 ciphertext, decrypted via BOTH the
// u32-native path (production: SingleBlock<CIPHER,u32>, isU32()==true ->
// debDecryptor32) and the u64-widen path (deserializeQueryFrom ->
// SingleBlock<CIPHER,u64>, isU32()==false -> debDecryptor). Both decode the same
// (a,b) coefficients mod the same prime, so the decoded plaintext must be
// element-wise BIT-IDENTICAL — not merely within a recall/max_err bound. Guards
// against a u32 path that silently diverges from the validated u64 reference.
TEST_F(EnDecryptTest, IP3_U32_vs_U64_Decrypt_BitEqual) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::MM32);
    std::vector<Context> contexts = {context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    const std::string ip3_path = test_pcmm_key_path + "ip3_u32_vs_u64/";
    fs::create_directories(ip3_path);
    MultiKeyGenerator keygen(contexts, ip3_path, s_info);
    keygen.generateKeys();

    KeyPack pack = makeKeyPack(context, ip3_path + "EncKey.bin");
    Encryptor enc = makeEncryptor(context);
    Decryptor dec = makeDecryptor(context);

    const int n = 4096;
    // Fixed seed for reproducibility on CI failure ('IP3D' = u32-vs-u64 Diff).
    constexpr unsigned K_SEED = 0x49503344u;
    std::vector<std::vector<float>> templates(n, std::vector<float>(rank, 0.0f));
    for (int i = 0; i < n; ++i) {
        randomFaces(templates[i].data(), -1, 1, 1, rank, K_SEED + i);
    }

    auto queries = enc->encrypt(templates, pack, evi::EncodeType::QUERY, /*level=*/1, std::nullopt);
    EXPECT_EQ(queries[0].front()->getLevel(), 1);

    // Serialize the IP3 ciphertext ONCE; decode the identical bytes two ways.
    std::stringstream query_stream;
    evi::detail::utils::serializeQueryTo(queries[0], query_stream);
    const std::string wire = query_stream.str();

    std::stringstream u64_stream(wire);
    evi::detail::Query u64_query = evi::detail::utils::deserializeQueryFrom(u64_stream);

    std::stringstream u32_stream(wire);
    evi::detail::Query u32_query = deserializeQueryAsU32(u32_stream);

    // Sanity: the two materializations really exercise the two decrypt branches.
    ASSERT_FALSE(u64_query[0]->isU32());
    ASSERT_TRUE(u32_query[0]->isU32());

    const auto dmsg_u64 = dec->decrypt(u64_query, ip3_path + "SecKey.bin", std::nullopt);
    const auto dmsg_u32 = dec->decrypt(u32_query, ip3_path + "SecKey.bin", std::nullopt);

    // Bit-exact equality (zero tolerance) across the full decoded payload: both
    // paths run the same static_cast<float>(coeff) on identical integer
    // coefficients, so any difference means the u32 path diverged.
    ASSERT_EQ(dmsg_u64.size(), dmsg_u32.size());
    for (size_t i = 0; i < dmsg_u64.size(); ++i) {
        EXPECT_EQ(dmsg_u32[i], dmsg_u64[i]) << "u32/u64 decrypt mismatch at index " << i;
    }
}

// =============================================================================
// Regression test for bindFixedKeyToDebSwkKey UAF with IP1 (GADGET_RANK=2).
//
// The bug: repeated KeyPack creation triggers heap reuse that exposes dangling
// pointers from bindFixedKeyToDebSwkKey. The first KeyPack works "by
// coincidence" (freed memory not yet overwritten); the second KeyPack allocates
// into the freed region and corrupts the first keypack's internal state.
//
// Symptom in production: search scores exceed valid cosine similarity bounds
// (>1.0 for normalized vectors) because relin key data is garbage.
// =============================================================================
TEST_F(EnDecryptTest, IP1_MultipleKeyPacks_EncryptDecryptRoundTrip) {
    preset = evi::ParameterPreset::IP1;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::SINGLE);

    constexpr int NUM_KEYPACKS = 4;
    std::vector<KeyPack> packs;
    std::vector<KeyGenerator> keygens;
    std::vector<evi::detail::SecretKey> sec_keys;
    packs.reserve(NUM_KEYPACKS);
    keygens.reserve(NUM_KEYPACKS);
    sec_keys.reserve(NUM_KEYPACKS);

    // Create multiple KeyPacks in sequence. Heap layout changes across
    // allocations; any UAF in genRelinKey/bindFixedKeyToDebSwkKey corrupts
    // previously-generated keys.
    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        auto pack = makeKeyPack(context);
        auto keygen = makeKeyGenerator(context, pack);
        auto sec_key = keygen->genSecKey();
        keygen->genPubKeys(sec_key);
        packs.push_back(std::move(pack));
        keygens.push_back(std::move(keygen));
        sec_keys.push_back(std::move(sec_key));
    }

    // Verify ALL keypacks still decrypt correctly. If any earlier keypack's
    // keys were corrupted by a later allocation, its decrypt will return
    // garbage and max_error will blow up.
    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        Encryptor enc = makeEncryptor(context, packs[i]);
        Decryptor dec = makeDecryptor(context);

        std::vector<float> msg(DEGREE, 0);
        randomFaces(msg.data(), -1, 1, 1, rank);

        auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
        auto dmsg = dec->decrypt(query, sec_keys[i]);

        const float err = maxError(dmsg, msg);
        EXPECT_LE(err, MAX_ERROR) << "KeyPack " << i << " decrypt failed (error=" << err << "). "
                                  << "Likely UAF in bindFixedKeyToDebSwkKey corrupted earlier keys.";
    }
}

TEST_F(EnDecryptTest, IP2_MultipleKeyPacks_EncryptDecryptRoundTrip) {
    preset = evi::ParameterPreset::IP2;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::SINGLE);

    constexpr int NUM_KEYPACKS = 4;
    std::vector<KeyPack> packs;
    std::vector<KeyGenerator> keygens;
    std::vector<evi::detail::SecretKey> sec_keys;
    packs.reserve(NUM_KEYPACKS);
    keygens.reserve(NUM_KEYPACKS);
    sec_keys.reserve(NUM_KEYPACKS);

    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        auto pack = makeKeyPack(context);
        auto keygen = makeKeyGenerator(context, pack);
        auto sec_key = keygen->genSecKey();
        keygen->genPubKeys(sec_key);
        packs.push_back(std::move(pack));
        keygens.push_back(std::move(keygen));
        sec_keys.push_back(std::move(sec_key));
    }

    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        Encryptor enc = makeEncryptor(context, packs[i]);
        Decryptor dec = makeDecryptor(context);

        std::vector<float> msg(DEGREE, 0);
        randomFaces(msg.data(), -1, 1, 1, rank);

        auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
        auto dmsg = dec->decrypt(query, sec_keys[i]);

        const float err = maxError(dmsg, msg);
        EXPECT_LE(err, MAX_ERROR) << "KeyPack " << i << " decrypt failed (error=" << err << "). "
                                  << "Likely UAF in syncVarKeyToDebSwkKey corrupted earlier keys.";
    }
}

TEST_F(EnDecryptTest, IP3_MultipleKeyPacks_EncryptDecryptRoundTrip) {
    preset = evi::ParameterPreset::IP3;
    Context context = makeContext(preset, device_type, rank, evi::EvalMode::SINGLE);

    constexpr int NUM_KEYPACKS = 4;
    std::vector<KeyPack> packs;
    std::vector<KeyGenerator> keygens;
    std::vector<evi::detail::SecretKey> sec_keys;
    packs.reserve(NUM_KEYPACKS);
    keygens.reserve(NUM_KEYPACKS);
    sec_keys.reserve(NUM_KEYPACKS);

    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        auto pack = makeKeyPack(context);
        auto keygen = makeKeyGenerator(context, pack);
        auto sec_key = keygen->genSecKey();
        keygen->genPubKeys(sec_key);
        packs.push_back(std::move(pack));
        keygens.push_back(std::move(keygen));
        sec_keys.push_back(std::move(sec_key));
    }

    for (int i = 0; i < NUM_KEYPACKS; ++i) {
        Encryptor enc = makeEncryptor(context, packs[i]);
        Decryptor dec = makeDecryptor(context);

        std::vector<float> msg(DEGREE, 0);
        randomFaces(msg.data(), -1, 1, 1, rank);

        auto query = enc->encrypt(msg, evi::EncodeType::ITEM);
        auto dmsg = dec->decrypt(query, sec_keys[i]);

        const float err = maxError(dmsg, msg);
        EXPECT_LE(err, MAX_ERROR) << "KeyPack " << i << " decrypt failed (error=" << err << "). "
                                  << "Likely UAF in syncVarKeyToDebSwkKey corrupted earlier keys.";
    }
}
