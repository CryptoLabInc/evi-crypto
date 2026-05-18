////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Reproducer: use-after-free in bindFixedKeyToDebSwkKey with IP1            //
//                                                                            //
//  The aligned_alloc buffer owned by deb::SwitchKey's Polynomial             //
//  (dealloc_ptr_) is freed when bindFixedKeyToDebSwkKey calls setData on     //
//  each PolyUnit. genMultKeyInplace then writes to PolyUnits whose           //
//  data pointers still reference the freed buffer.                           //
//                                                                            //
//  Trigger condition: GADGET_RANK >= 2 (IP1, IP2).                           //
//  IP0 (GADGET_RANK=1) is unaffected.                                        //
//                                                                            //
//  Run: valgrind --tool=memcheck ./test/SyncKeyUAFTest                       //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <gtest/gtest.h>
#include <iostream>

#include "EVI/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "utils.hpp"
#include "utils/DebUtils.hpp"

using namespace evi::detail;

TEST(SyncKeyUAF, IP1_GenPubKeys_SingleKeyPack) {
    // Minimal reproducer: single KeyPack + genPubKeys with IP1.
    // The deb key must own its buffers; aliasing FixedKey memory caused UAF.
    auto preset = evi::ParameterPreset::IP1;
    evi::detail::setPreset(preset);

    Context context = makeContext(preset, evi::DeviceType::CPU, 128, evi::EvalMode::SINGLE);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sk = keygen->genSecKey();
    keygen->genPubKeys(sk); // triggers bindFixedKeyToDebSwkKey UAF

    auto *pack_data = dynamic_cast<KeyPackData *>(pack.get());
    ASSERT_NE(pack_data, nullptr);
    const auto deb_preset = evi::detail::utils::getDebPreset(context);
    const auto gadget_rank = deb::get_gadget_rank(deb_preset);
    const auto num_secret = deb::get_num_secret(deb_preset);
    EXPECT_EQ(pack_data->deb_relin_key.axSize(), gadget_rank);
    EXPECT_EQ(pack_data->deb_relin_key.bxSize(), gadget_rank * num_secret);
    EXPECT_EQ(pack_data->deb_enc_key.axSize(), 1);
    EXPECT_EQ(pack_data->deb_enc_key.bxSize(), num_secret);
    EXPECT_EQ(pack_data->deb_enc_key.ax(0)[0].data(), pack_data->enckey->getPolyData(1, 0));
    EXPECT_EQ(pack_data->deb_enc_key.ax(0)[1].data(), pack_data->enckey->getPolyData(1, 1));
    EXPECT_EQ(pack_data->deb_enc_key.bx(0)[0].data(), pack_data->enckey->getPolyData(0, 0));
    EXPECT_EQ(pack_data->deb_enc_key.bx(0)[1].data(), pack_data->enckey->getPolyData(0, 1));
    EXPECT_NE(pack_data->deb_enc_key.ax(0)[2].data(), pack_data->enckey->getPolyData(1, 1));
    EXPECT_NE(pack_data->deb_enc_key.bx(0)[2].data(), pack_data->enckey->getPolyData(0, 1));

    std::cout << "genPubKeys completed (check valgrind for UAF)" << std::endl;
}

TEST(SyncKeyUAF, IP2_GenPubKeys_SingleKeyPack) {
    auto preset = evi::ParameterPreset::IP2;
    evi::detail::setPreset(preset);

    Context context = makeContext(preset, evi::DeviceType::CPU, 128, evi::EvalMode::SINGLE);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sk = keygen->genSecKey();
    keygen->genPubKeys(sk);

    auto *pack_data = dynamic_cast<KeyPackData *>(pack.get());
    ASSERT_NE(pack_data, nullptr);
    const auto deb_preset = evi::detail::utils::getDebPreset(context);
    const auto gadget_rank = deb::get_gadget_rank(deb_preset);
    const auto num_secret = deb::get_num_secret(deb_preset);
    EXPECT_EQ(pack_data->deb_relin_key.axSize(), gadget_rank);
    EXPECT_EQ(pack_data->deb_relin_key.bxSize(), gadget_rank * num_secret);
}

TEST(SyncKeyUAF, IP3_GenPubKeys_SingleKeyPack) {
    auto preset = evi::ParameterPreset::IP3;
    evi::detail::setPreset(preset);

    Context context = makeContext(preset, evi::DeviceType::CPU, 128, evi::EvalMode::SINGLE);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sk = keygen->genSecKey();
    keygen->genPubKeys(sk);

    auto *pack_data = dynamic_cast<KeyPackData *>(pack.get());
    ASSERT_NE(pack_data, nullptr);
    const auto deb_preset = evi::detail::utils::getDebPreset(context);
    const auto gadget_rank = deb::get_gadget_rank(deb_preset);
    const auto num_secret = deb::get_num_secret(deb_preset);
    EXPECT_EQ(pack_data->deb_relin_key.axSize(), gadget_rank);
    EXPECT_EQ(pack_data->deb_relin_key.bxSize(), gadget_rank * num_secret);
}

TEST(SyncKeyUAF, IP1_GenPubKeys_TwoKeyPacks_Crash) {
    // Two KeyPacks: the second allocation exposes the dangling pointer
    // from the first genPubKeys, causing glibc to detect heap corruption.
    auto preset = evi::ParameterPreset::IP1;
    evi::detail::setPreset(preset);

    Context context = makeContext(preset, evi::DeviceType::CPU, 128, evi::EvalMode::SINGLE);

    // First KeyPack + genPubKeys → UAF in bindFixedKeyToDebSwkKey
    KeyPack pack1 = makeKeyPack(context);
    KeyGenerator keygen1 = makeKeyGenerator(context, pack1);
    auto sk1 = keygen1->genSecKey();
    keygen1->genPubKeys(sk1);

    // Second KeyPack → heap allocation reuses freed region → corruption
    KeyPack pack2 = makeKeyPack(context);
    KeyGenerator keygen2 = makeKeyGenerator(context, pack2);
    auto sk2 = keygen2->genSecKey();

    std::cout << "Two KeyPacks completed (may crash without valgrind)" << std::endl;
}

TEST(SyncKeyUAF, IP0_GenPubKeys_Clean) {
    // IP0 (GADGET_RANK=1): no reallocation in SwitchKey → clean.
    auto preset = evi::ParameterPreset::IP0;
    evi::detail::setPreset(preset);

    Context context = makeContext(preset, evi::DeviceType::CPU, 128, evi::EvalMode::SINGLE);
    KeyPack pack = makeKeyPack(context);
    KeyGenerator keygen = makeKeyGenerator(context, pack);

    auto sk = keygen->genSecKey();
    keygen->genPubKeys(sk);

    std::cout << "IP0 genPubKeys clean" << std::endl;
}
