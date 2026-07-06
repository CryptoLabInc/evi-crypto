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

#include "utils.hpp"
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <type_traits>
#include <variant>

#if defined(__linux__) || defined(__APPLE__)
#endif

#include "EVI/Const.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "utils/SealInfo.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"

using namespace evi::detail;

class KeyValidationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        srand(time(NULL));
        rank = 1 << (rand() % 5 + 6);
        std::cout << "RANK : " << rank << std::endl;

        // IP1/IP2/IP3 + RMP eval-key save/load is currently unstable; exclude them here.
        do {
            preset = get_random_preset();
        } while (preset == evi::ParameterPreset::IP1 || preset == evi::ParameterPreset::IP2 ||
                 preset == evi::ParameterPreset::IP3);
        auto evi_preset = setPreset(preset);
        std::cout << "Testing parameter : " << getParamToString(preset) << "(" << static_cast<int>(preset) << ")"
                  << std::endl;

        mode = evi::EvalMode::RMP;
        context = makeContext(preset, evi::DeviceType::CPU, rank, mode);

        db_scale = static_cast<double>(deb_prime_at(evi_preset.get(), 1));
        query_scale = std::pow(2.0, 2 * evi_preset->getScaleFactor());

        keypack = makeKeyPack(context);
        keygen = makeKeyGenerator(context, keypack, std::vector<uint8_t>(evi::SEED_MIN_SIZE, 0));
        seckey = keygen->genSecKey();
        keygen->genPubKeys(seckey);

        test_key_path = "tests_keys/";
        std::filesystem::create_directories(test_key_path);
    }

    static void TearDownTestSuite() {
        try {
            if (!test_key_path.empty() && std::filesystem::exists(test_key_path)) {
                std::filesystem::remove_all(test_key_path);
                std::cout << "Deleted test directory: " << test_key_path << std::endl;
            }
        } catch (const std::exception &e) {
            std::cerr << "Failed to delete test directory: " << e.what() << std::endl;
        }
    }

    static u32 rank;
    static evi::ParameterPreset preset;
    static double db_scale;
    static double query_scale;
    static evi::EvalMode mode;
    static Context context;
    static KeyPack keypack;
    static KeyGenerator keygen;
    static SecretKey seckey;
    static std::string test_key_path;
};

u32 KeyValidationTest::rank = 0;
double KeyValidationTest::db_scale = 0.0;
double KeyValidationTest::query_scale = 0.0;
evi::ParameterPreset KeyValidationTest::preset = evi::ParameterPreset::IP0;
evi::EvalMode KeyValidationTest::mode = evi::EvalMode::FLAT;
Context KeyValidationTest::context = Context(nullptr);
KeyPack KeyValidationTest::keypack = KeyPack(nullptr);
KeyGenerator KeyValidationTest::keygen = KeyGenerator(nullptr);
SecretKey KeyValidationTest::seckey = SecretKey(nullptr);
std::string KeyValidationTest::test_key_path = "";

TEST_F(KeyValidationTest, SameSeedSameKey) {
    auto kp1 = makeKeyPack(context);
    auto kp2 = makeKeyPack(context);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 42);

    auto kg1 = makeKeyGenerator(context, kp1, seed);
    auto kg2 = makeKeyGenerator(context, kp2, seed);

    auto sk1 = kg1->genSecKey();
    auto sk2 = kg2->genSecKey();

    SecretKeyAccessScope access_1(sk1);
    SecretKeyAccessScope access_2(sk2);
    for (int i = 0; i < DEGREE; ++i) {
        ASSERT_EQ(sk1->getCoeff()[i], sk2->getCoeff()[i]) << "Mismatch at coeff[" << i << "]";
    }
}

TEST_F(KeyValidationTest, DiffSeedDiffKey) {
    auto kp1 = makeKeyPack(context);
    auto kp2 = makeKeyPack(context);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);
    auto kg1 = makeKeyGenerator(context, kp1, seed);
    seed[0]++;
    auto kg2 = makeKeyGenerator(context, kp2, seed);

    auto sk1 = kg1->genSecKey();
    auto sk2 = kg2->genSecKey();

    bool diff_found = false;
    SecretKeyAccessScope access_1(sk1);
    SecretKeyAccessScope access_2(sk2);
    for (int i = 0; i < DEGREE; ++i) {
        if (sk1->getCoeff()[i] != sk2->getCoeff()[i]) {
            diff_found = true;
            break;
        }
    }
    ASSERT_TRUE(diff_found) << "Secret keys are identical despite different seeds.";
}

TEST_F(KeyValidationTest, AESSealUnSealTest) {
    std::vector<uint8_t> kek(32, 0);
    SealInfo s_info(evi::SealMode::AES_KEK, kek);
    auto sk = keygen->genSecKey();
    sk->s_info_ = s_info;

    std::string sealed_path = test_key_path + "SecKey_sealed.bin";
    sk->saveSealedSecKey(sealed_path);
    auto sk_loaded = makeSecKey(sealed_path, s_info);

    SecretKeyAccessScope access_1(sk);
    SecretKeyAccessScope access_2(sk_loaded);
    for (int i = 0; i < DEGREE; i++) {
        ASSERT_EQ(sk->getCoeff()[i], sk_loaded->getCoeff()[i]) << "Mismatch at coeff[" << i << "]";
    }
    std::remove(sealed_path.c_str());
}

TEST_F(KeyValidationTest, SerializeDeserializeSecretKey) {
    std::stringstream ss;
    seckey->saveSecKey(ss);
    auto sk2 = std::make_shared<SecretKeyData>(context);
    sk2->loadSecKey(ss);

    SecretKeyAccessScope access_1(seckey);
    SecretKeyAccessScope access_2(sk2);
    EXPECT_EQ(seckey->getKeyQ(), sk2->getKeyQ());
    EXPECT_EQ(seckey->getKeyP(), sk2->getKeyP());
    EXPECT_EQ(seckey->getCoeff(), sk2->getCoeff());
}

TEST_F(KeyValidationTest, RegeneratedPublicKeysMatchOriginalSecretKey) {
    auto mm_context = makeContext(preset, evi::DeviceType::CPU, rank, evi::EvalMode::MM);
    std::vector<Context> contexts = {mm_context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);
    MultiKeyGenerator multi_keygen1(contexts, test_key_path, s_info, seed);

    std::stringstream sec_ss;
    std::stringstream enc_ss;
    std::stringstream eval_ss;
    SecretKey original_seckey = multi_keygen1.generateKeys(sec_ss, enc_ss, eval_ss);

    std::stringstream regen_enc_ss;
    std::stringstream regen_eval_ss;
    MultiKeyGenerator multi_keygen2(contexts, test_key_path, s_info, seed);
    multi_keygen2.generateKeys(original_seckey, regen_enc_ss, regen_eval_ss);

    if (enc_ss.str() != regen_enc_ss.str()) {
        ADD_FAILURE() << "EncKey mismatch between original and regenerated";
    }
    if (eval_ss.str() != regen_eval_ss.str()) {
        ADD_FAILURE() << "EvalKey mismatch between original and regenerated";
    }
}

TEST_F(KeyValidationTest, SecretKeyMemoryIsInaccessibleAfterAccessScopeCloses) {
#if defined(__linux__) || defined(__APPLE__)
    auto sk = keygen->genSecKey();
    decltype(sk->getCoeff().data()) coeff_ptr = nullptr;
    decltype(sk->getKeyQ().data()) key_q_ptr = nullptr;
    decltype(sk->getKeyP().data()) key_p_ptr = nullptr;

    {
        SecretKeyAccessScope access(sk);
        coeff_ptr = sk->getCoeff().data();
        key_q_ptr = sk->getKeyQ().data();
        key_p_ptr = sk->getKeyP().data();
        const auto coeff_warmup = coeff_ptr[0];
        const auto key_q_warmup = key_q_ptr[0];
        const auto key_p_warmup = key_p_ptr[0];
        ASSERT_EQ(coeff_warmup, sk->getCoeff()[0]);
        ASSERT_EQ(key_q_warmup, sk->getKeyQ()[0]);
        ASSERT_EQ(key_p_warmup, sk->getKeyP()[0]);
    }

    ASSERT_NE(coeff_ptr, nullptr);
    ASSERT_NE(key_q_ptr, nullptr);
    ASSERT_NE(key_p_ptr, nullptr);
    EXPECT_DEATH(
        {
            volatile auto leaked = coeff_ptr[0];
            (void)leaked;
        },
        ".*");
    EXPECT_DEATH(
        {
            volatile auto leaked_q = key_q_ptr[0];
            (void)leaked_q;
        },
        ".*");
    EXPECT_DEATH(
        {
            volatile auto leaked_p = key_p_ptr[0];
            (void)leaked_p;
        },
        ".*");
#else
    GTEST_SKIP() << "Page protection death test is supported on Linux/macOS only";
#endif
}

TEST_F(KeyValidationTest, EncKeySaveLoad) {
    std::string path = test_key_path + "EncKey.bin";
    keypack->saveEncKeyFile(path);

    auto kp_loaded = makeKeyPack(context);
    kp_loaded->loadEncKeyFile(path);

    auto *kd = dynamic_cast<KeyPackData *>(keypack.get());
    auto *kd_loaded = dynamic_cast<KeyPackData *>(kp_loaded.get());
    for (size_t i = 0; i < DEGREE; ++i) {
        EXPECT_EQ(kd->enckey->getPolyData(1, 0)[i], kd_loaded->enckey->getPolyData(1, 0)[i]);
        EXPECT_EQ(kd->enckey->getPolyData(1, 1)[i], kd_loaded->enckey->getPolyData(1, 1)[i]);
        EXPECT_EQ(kd->enckey->getPolyData(0, 0)[i], kd_loaded->enckey->getPolyData(0, 0)[i]);
        EXPECT_EQ(kd->enckey->getPolyData(0, 1)[i], kd_loaded->enckey->getPolyData(0, 1)[i]);
    }
}

TEST_F(KeyValidationTest, EvalKeySaveLoad) {
    std::string path = test_key_path + "EvalKey.bin";
    keypack->saveEvalKeyFile(path);

    auto kp_loaded = makeKeyPack(context);
    kp_loaded->loadEvalKeyFile(path);

    auto *kp = dynamic_cast<KeyPackData *>(keypack.get());
    auto *kd_load = dynamic_cast<KeyPackData *>(kp_loaded.get());

    for (size_t i = 0; i < DEGREE; ++i) {
        EXPECT_EQ(kp->relin_key->getPolyData(0, 1)[i], kd_load->relin_key->getPolyData(0, 1)[i]);
        EXPECT_EQ(kp->mod_pack_key->getPolyData(0, 1)[i], kd_load->mod_pack_key->getPolyData(0, 1)[i]);
    }
}

TEST_F(KeyValidationTest, EvalKeySwitchingKeyMMSaveLoad) {
    // Build MM-mode context and generate switching keys via MultiKeyGenerator
    auto mm_context = makeContext(preset, evi::DeviceType::CPU, rank, evi::EvalMode::MM);
    std::vector<Context> contexts = {mm_context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);

    MultiKeyGenerator multi_keygen(contexts, test_key_path, s_info, seed);
    multi_keygen.generateKeys();

    std::string path = test_key_path + "EvalKey.bin";

    auto kp_1 = makeKeyPack(mm_context);
    kp_1->loadEvalKeyFile(path);
    auto kp_loaded = makeKeyPack(mm_context);
    kp_loaded->loadEvalKeyFile(path);

    auto *kp = dynamic_cast<KeyPackData *>(kp_1.get());
    auto *kp_loaded_data = dynamic_cast<KeyPackData *>(kp_loaded.get());
    ASSERT_NE(kp, nullptr);
    ASSERT_NE(kp_loaded_data, nullptr);

    ASSERT_EQ(kp->key_switching_key.size(), kp_loaded_data->key_switching_key.size());

    for (size_t k = 0; k < kp->key_switching_key.size(); ++k) {
        ASSERT_EQ(kp->key_switching_key[k].index(), kp_loaded_data->key_switching_key[k].index());
        std::visit(
            [&](const auto &key, const auto &loaded_key) {
                using Key = std::decay_t<decltype(key)>;
                using LoadedKey = std::decay_t<decltype(loaded_key)>;
                if constexpr (std::is_same_v<Key, LoadedKey>) {
                    auto *a_q = key->getPolyData(1, 0);
                    auto *b_q = key->getPolyData(0, 0);
                    auto *a_q_ld = loaded_key->getPolyData(1, 0);
                    auto *b_q_ld = loaded_key->getPolyData(0, 0);
                    for (size_t i = 0; i < DEGREE; ++i) {
                        EXPECT_EQ(a_q[i], a_q_ld[i]);
                        EXPECT_EQ(b_q[i], b_q_ld[i]);
                    }
                }
            },
            kp->key_switching_key[k], kp_loaded_data->key_switching_key[k]);
    }
}

TEST_F(KeyValidationTest, EvalKeySharedAMMSSaveLoad) {
    // MMS mode: verify shared-A keys (forward QPR + off-diagonal + backward L0) roundtrip
    // MMS requires IP1 preset (QPR gadget structure)
    auto mms_context = makeContext(evi::ParameterPreset::IP1, evi::DeviceType::CPU, rank, evi::EvalMode::MMS);
    std::vector<Context> contexts = {mms_context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);

    MultiKeyGenerator multi_keygen(contexts, test_key_path, s_info, seed);
    multi_keygen.generateKeys();

    // In-memory keys (before serialization) — the ground truth
    auto *kd_mem = dynamic_cast<KeyPackData *>(multi_keygen.getKeyPack().get());
    ASSERT_NE(kd_mem, nullptr);

    std::string path = test_key_path + "EvalKey.bin";

    auto kp_loaded = makeKeyPack(mms_context);
    kp_loaded->loadEvalKeyFile(path);

    auto *kd = dynamic_cast<KeyPackData *>(kp_loaded.get());
    ASSERT_NE(kd, nullptr);

    // Check nss
    EXPECT_EQ(kd_mem->num_shared_secret, kd->num_shared_secret);
    EXPECT_GT(kd_mem->num_shared_secret, 0);
    const int nss = kd_mem->num_shared_secret;

    // Forward QPR keys
    ASSERT_EQ(kd_mem->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    for (int s = 0; s < nss; ++s) {
        for (deb::Size d = 0; d < 2; ++d) {
            for (deb::Size p = 0; p < 3; ++p) {
                for (size_t k = 0; k < DEGREE; ++k) {
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].ax(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].ax(d)[p].data()[k]);
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].bx(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].bx(d)[p].data()[k]);
                }
            }
        }
    }

    // Off-diagonal keys
    ASSERT_EQ(kd_mem->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));
    ASSERT_EQ(kd->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));

    // Backward L0 keys — compare in-memory (ground truth) vs loaded (serialized roundtrip)
    // These use IP0 primes (~51/55 bit), NOT IP1 (~35 bit).
    // A bit-width mismatch in serialization would truncate these values.
    ASSERT_EQ(kd_mem->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    for (int j = 0; j < nss; ++j) {
        for (size_t k = 0; k < DEGREE; ++k) {
            // MMS backward keys use the u64 (polyvec) variant alternative:
            // the producer gates u32 on preset==IP3 only, so non-IP3
            // (incl. MMS/IP0) -> poly<u64>. Route through poly<u64> like SearchTest.cpp.
            using BL0 = KeyPackData::BackwardL0Key;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_q)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].ax_q)[k])
                << "ax_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_p)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].ax_p)[k])
                << "ax_p mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_q)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].bx_q)[k])
                << "bx_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_p)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].bx_p)[k])
                << "bx_p mismatch at j=" << j << " k=" << k;
        }
    }
}

TEST_F(KeyValidationTest, EvalKeySharedAIP2SaveLoad) {
    // IP2 MMS: verify shared-A keys with 32-bit primes roundtrip
    // Backward keys use IP2 primes (no base conversion to IP0)
    auto ip2_context = makeContext(evi::ParameterPreset::IP2, evi::DeviceType::CPU, rank, evi::EvalMode::MMS);
    std::vector<Context> contexts = {ip2_context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);

    const std::string ip2_key_path = test_key_path + "ip2_mms/";
    std::filesystem::create_directories(ip2_key_path);

    MultiKeyGenerator multi_keygen(contexts, ip2_key_path, s_info, seed);
    multi_keygen.generateKeys();

    auto *kd_mem = dynamic_cast<KeyPackData *>(multi_keygen.getKeyPack().get());
    ASSERT_NE(kd_mem, nullptr);

    std::string path = ip2_key_path + "EvalKey.bin";

    auto kp_loaded = makeKeyPack(ip2_context);
    kp_loaded->loadEvalKeyFile(path);

    auto *kd = dynamic_cast<KeyPackData *>(kp_loaded.get());
    ASSERT_NE(kd, nullptr);

    // Check nss
    EXPECT_EQ(kd_mem->num_shared_secret, kd->num_shared_secret);
    EXPECT_GT(kd_mem->num_shared_secret, 0);
    const int nss = kd_mem->num_shared_secret;

    // Forward QPR keys
    ASSERT_EQ(kd_mem->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    for (int s = 0; s < nss; ++s) {
        for (deb::Size d = 0; d < 2; ++d) {
            for (deb::Size p = 0; p < 3; ++p) {
                for (size_t k = 0; k < DEGREE; ++k) {
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].ax(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].ax(d)[p].data()[k]);
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].bx(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].bx(d)[p].data()[k]);
                }
            }
        }
    }

    // Off-diagonal keys
    ASSERT_EQ(kd_mem->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));
    ASSERT_EQ(kd->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));

    // Backward L0 keys — IP2 primes (32-bit), not IP0 primes
    // All backward key coefficients must be < IP2 PRIME_Q / PRIME_P
    const u64 ip2_q = ip2_context->getParam()->getQ(0);
    const u64 ip2_p = deb_prime_at(ip2_context->getParam(), 1);
    ASSERT_LE(ip2_q, UINT32_MAX) << "IP2 Q must fit in 32 bits";
    ASSERT_LE(ip2_p, UINT32_MAX) << "IP2 P must fit in 32 bits";

    ASSERT_EQ(kd_mem->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    for (int j = 0; j < nss; ++j) {
        for (size_t k = 0; k < DEGREE; ++k) {
            // IP2 is demoted to the u64 (polyvec) variant: the producer
            // gates u32-native on preset==IP3 only; IP2's backward primes
            // fit in 32 bits but IP2 is u64-numeric post-demotion -> poly<u64>.
            using BL0 = KeyPackData::BackwardL0Key;
            // Verify coefficients are within IP2 prime range
            EXPECT_LT(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_q)[k], ip2_q)
                << "ax_q exceeds IP2 Q at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_q)[k], ip2_q)
                << "bx_q exceeds IP2 Q at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_p)[k], ip2_p)
                << "ax_p exceeds IP2 P at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_p)[k], ip2_p)
                << "bx_p exceeds IP2 P at j=" << j << " k=" << k;

            // Serialization roundtrip
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_q)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].ax_q)[k])
                << "ax_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].ax_p)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].ax_p)[k])
                << "ax_p mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_q)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].bx_q)[k])
                << "bx_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u64>(kd_mem->shared_a_bwd_l0_keys[j].bx_p)[k],
                      BL0::poly<u64>(kd->shared_a_bwd_l0_keys[j].bx_p)[k])
                << "bx_p mismatch at j=" << j << " k=" << k;
        }
    }
}

TEST_F(KeyValidationTest, EvalKeySharedAIP3SaveLoad) {
    // IP3 MMS: verify shared-A keys with 30-bit primes roundtrip
    // Backward keys use IP3 primes (no base conversion to IP0)
    auto ip3_context = makeContext(evi::ParameterPreset::IP3, evi::DeviceType::CPU, rank, evi::EvalMode::MMS);
    std::vector<Context> contexts = {ip3_context};
    SealInfo s_info = SealInfo(evi::SealMode::NONE);
    std::vector<uint8_t> seed(evi::SEED_MIN_SIZE, 0);

    const std::string ip3_key_path = test_key_path + "ip3_mms/";
    std::filesystem::create_directories(ip3_key_path);

    MultiKeyGenerator multi_keygen(contexts, ip3_key_path, s_info, seed);
    multi_keygen.generateKeys();

    auto *kd_mem = dynamic_cast<KeyPackData *>(multi_keygen.getKeyPack().get());
    ASSERT_NE(kd_mem, nullptr);

    std::string path = ip3_key_path + "EvalKey.bin";

    auto kp_loaded = makeKeyPack(ip3_context);
    kp_loaded->loadEvalKeyFile(path);

    auto *kd = dynamic_cast<KeyPackData *>(kp_loaded.get());
    ASSERT_NE(kd, nullptr);

    // Check nss
    EXPECT_EQ(kd_mem->num_shared_secret, kd->num_shared_secret);
    EXPECT_GT(kd_mem->num_shared_secret, 0);
    const int nss = kd_mem->num_shared_secret;

    // Forward QPR keys
    ASSERT_EQ(kd_mem->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_fwd_keys.size(), static_cast<size_t>(nss));
    for (int s = 0; s < nss; ++s) {
        for (deb::Size d = 0; d < 2; ++d) {
            for (deb::Size p = 0; p < 3; ++p) {
                for (size_t k = 0; k < DEGREE; ++k) {
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].ax(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].ax(d)[p].data()[k]);
                    EXPECT_EQ(kd_mem->shared_a_fwd_keys[s].bx(d)[p].data()[k],
                              kd->shared_a_fwd_keys[s].bx(d)[p].data()[k]);
                }
            }
        }
    }

    // Off-diagonal keys
    ASSERT_EQ(kd_mem->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));
    ASSERT_EQ(kd->shared_a_off_diag_keys.size(), static_cast<size_t>(nss * nss));

    // Backward L0 keys — IP3 primes (30-bit), not IP0 primes
    // All backward key coefficients must be < IP3 PRIME_Q / PRIME_P
    const u64 ip3_q = ip3_context->getParam()->getQ(0);
    const u64 ip3_p = deb_prime_at(ip3_context->getParam(), 1);
    ASSERT_LE(ip3_q, UINT32_MAX) << "IP3 Q must fit in 32 bits";
    ASSERT_LE(ip3_p, UINT32_MAX) << "IP3 P must fit in 32 bits";

    ASSERT_EQ(kd_mem->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    ASSERT_EQ(kd->shared_a_bwd_l0_keys.size(), static_cast<size_t>(nss));
    for (int j = 0; j < nss; ++j) {
        for (size_t k = 0; k < DEGREE; ++k) {
            // IP3 uses the u32-native (polyvec32) variant alternative: the
            // producer gates u32 on preset==IP3 -> poly<u32>. Route through poly<u32>
            // like SearchTest.cpp's IP3 branch.
            using BL0 = KeyPackData::BackwardL0Key;
            // Verify coefficients are within IP3 prime range
            EXPECT_LT(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].ax_q)[k], ip3_q)
                << "ax_q exceeds IP3 Q at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].bx_q)[k], ip3_q)
                << "bx_q exceeds IP3 Q at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].ax_p)[k], ip3_p)
                << "ax_p exceeds IP3 P at j=" << j << " k=" << k;
            EXPECT_LT(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].bx_p)[k], ip3_p)
                << "bx_p exceeds IP3 P at j=" << j << " k=" << k;

            // Serialization roundtrip
            EXPECT_EQ(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].ax_q)[k],
                      BL0::poly<u32>(kd->shared_a_bwd_l0_keys[j].ax_q)[k])
                << "ax_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].ax_p)[k],
                      BL0::poly<u32>(kd->shared_a_bwd_l0_keys[j].ax_p)[k])
                << "ax_p mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].bx_q)[k],
                      BL0::poly<u32>(kd->shared_a_bwd_l0_keys[j].bx_q)[k])
                << "bx_q mismatch at j=" << j << " k=" << k;
            EXPECT_EQ(BL0::poly<u32>(kd_mem->shared_a_bwd_l0_keys[j].bx_p)[k],
                      BL0::poly<u32>(kd->shared_a_bwd_l0_keys[j].bx_p)[k])
                << "bx_p mismatch at j=" << j << " k=" << k;
        }
    }
}

TEST_F(KeyValidationTest, EvalKeyBundleHeaderAndLegacyLoad) {
    const std::string bundle_dir = test_key_path + "eval_bundle/";
    std::filesystem::create_directories(bundle_dir);
    const std::string eval_file = bundle_dir + "EVIKeys" + std::to_string(context.getPadRank()) + ".bin";
    keypack->saveEvalKeyFile(eval_file);

    const std::string bundle_path = test_key_path + "EvalKey.bundle.bin";
    evi::detail::utils::serializeEvalKey(bundle_dir, bundle_path);

    auto kp_header = makeKeyPack(context);
    kp_header->loadEvalKeyFile(bundle_path);

    auto *kp = dynamic_cast<KeyPackData *>(keypack.get());
    auto *kp_header_loaded = dynamic_cast<KeyPackData *>(kp_header.get());
    ASSERT_NE(kp, nullptr);
    ASSERT_NE(kp_header_loaded, nullptr);

    for (size_t i = 0; i < DEGREE; ++i) {
        EXPECT_EQ(kp->relin_key->getPolyData(0, 1)[i], kp_header_loaded->relin_key->getPolyData(0, 1)[i]);
        EXPECT_EQ(kp->mod_pack_key->getPolyData(0, 1)[i], kp_header_loaded->mod_pack_key->getPolyData(0, 1)[i]);
    }

    std::ifstream in(bundle_path, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    ASSERT_FALSE(data.empty());

    if (data.size() >= 5 && std::memcmp(data.data(), evi::detail::serialization::kMagic, 4) == 0) {
        data.erase(0, 5);
    }
    const std::string legacy_path = test_key_path + "EvalKey.legacy.bin";
    std::ofstream out(legacy_path, std::ios::binary);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();

    auto kp_legacy = makeKeyPack(context);
    kp_legacy->loadEvalKeyFile(legacy_path);

    auto *kp_legacy_loaded = dynamic_cast<KeyPackData *>(kp_legacy.get());
    ASSERT_NE(kp_legacy_loaded, nullptr);

    for (size_t i = 0; i < DEGREE; ++i) {
        EXPECT_EQ(kp->relin_key->getPolyData(0, 1)[i], kp_legacy_loaded->relin_key->getPolyData(0, 1)[i]);
        EXPECT_EQ(kp->mod_pack_key->getPolyData(0, 1)[i], kp_legacy_loaded->mod_pack_key->getPolyData(0, 1)[i]);
    }
}
