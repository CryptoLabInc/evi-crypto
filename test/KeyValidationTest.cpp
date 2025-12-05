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
#include <fstream>
#include <gtest/gtest.h>
#include <random>
#include <string>

#include "EVI/Const.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "utils/SealInfo.hpp"

using namespace evi::detail;

class KeyValidationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        srand(time(NULL));
        rank = 1 << (rand() % 5 + 6);
        std::cout << "RANK : " << rank << std::endl;

        preset = get_random_preset();
        auto evi_preset = setPreset(preset);
        std::cout << "Testing parameter : " << getParamToString(preset) << "(" << static_cast<int>(preset) << ")"
                  << std::endl;

        mode = evi::EvalMode::RMP;
        context = makeContext(preset, evi::DeviceType::CPU, rank, mode);

        db_scale = static_cast<double>(evi_preset->getPrimeP());
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

    for (int i = 0; i < DEGREE; ++i) {
        ASSERT_EQ(sk1->sec_coeff_[i], sk2->sec_coeff_[i]) << "Mismatch at coeff[" << i << "]";
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
    for (int i = 0; i < DEGREE; ++i) {
        if (sk1->sec_coeff_[i] != sk2->sec_coeff_[i]) {
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

    for (int i = 0; i < DEGREE; i++) {
        ASSERT_EQ(sk->sec_coeff_[i], sk_loaded->sec_coeff_[i]) << "Mismatch at coeff[" << i << "]";
    }
    std::remove(sealed_path.c_str());
}

TEST_F(KeyValidationTest, SerializeDeserializeSecretKey) {
    std::stringstream ss;
    seckey->saveSecKey(ss);
    auto sk2 = std::make_shared<SecretKeyData>(context);
    sk2->loadSecKey(ss);

    EXPECT_EQ(seckey->sec_key_q_, sk2->sec_key_q_);
    EXPECT_EQ(seckey->sec_key_p_, sk2->sec_key_p_);
    EXPECT_EQ(seckey->sec_coeff_, sk2->sec_coeff_);
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
