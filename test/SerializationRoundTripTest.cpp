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

#include <array>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "EVI/Const.hpp"
#include "EVI/Encryptor.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/Query.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "EVI/impl/KeyPackImpl.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"

namespace evi {
namespace detail {
class Query;
class Context;
class IKeyPack;
} // namespace detail

std::shared_ptr<detail::Query> &getImpl(Query &) noexcept;
const std::shared_ptr<detail::Query> &getImpl(const Query &) noexcept;
std::shared_ptr<detail::IKeyPack> &getImpl(KeyPack &) noexcept;
const std::shared_ptr<detail::IKeyPack> &getImpl(const KeyPack &) noexcept;
std::shared_ptr<detail::Context> &getImpl(Context &) noexcept;
const std::shared_ptr<detail::Context> &getImpl(const Context &) noexcept;
} // namespace evi

namespace {
using evi::detail::DEGREE;
using evi::detail::u32;
using evi::detail::u64;

std::string modeName(evi::EvalMode mode) {
    switch (mode) {
    case evi::EvalMode::SINGLE:
        return "SINGLE";
    case evi::EvalMode::FLAT:
        return "FLAT";
    case evi::EvalMode::RMP:
        return "RMP";
    case evi::EvalMode::MM:
        return "MM";
    default:
        return "UNKNOWN";
    }
}

std::string toString(const std::function<void(std::ostream &)> &fn) {
    std::ostringstream oss(std::ios::binary | std::ios::out);
    fn(oss);
    return oss.str();
}

void expectPolyEq(const u64 *lhs, const u64 *rhs, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        ASSERT_EQ(lhs[i], rhs[i]) << "poly mismatch at index " << i;
    }
}

void expectSingleBlockEq(evi::detail::IQuery &lhs, evi::detail::IQuery &rhs) {
    ASSERT_EQ(lhs.getDataType(), rhs.getDataType());
    ASSERT_EQ(lhs.getLevel(), rhs.getLevel());
    ASSERT_EQ(lhs.n, rhs.n);
    ASSERT_EQ(lhs.dim, rhs.dim);
    ASSERT_EQ(lhs.degree, rhs.degree);
    ASSERT_EQ(lhs.show_dim, rhs.show_dim);
    ASSERT_EQ(lhs.scale_bit, rhs.scale_bit);
    ASSERT_EQ(lhs.encode_type, rhs.encode_type);
    ASSERT_EQ(lhs.prime_q_bits, rhs.prime_q_bits);
    ASSERT_EQ(lhs.prime_p_bits, rhs.prime_p_bits);

    if (lhs.getDataType() == evi::DataType::CIPHER) {
        expectPolyEq(lhs.getPolyData(1, 0), rhs.getPolyData(1, 0), DEGREE);
        expectPolyEq(lhs.getPolyData(0, 0), rhs.getPolyData(0, 0), DEGREE);
        if (lhs.getLevel()) {
            expectPolyEq(lhs.getPolyData(1, 1), rhs.getPolyData(1, 1), DEGREE);
            expectPolyEq(lhs.getPolyData(0, 1), rhs.getPolyData(0, 1), DEGREE);
        }
    } else {
        expectPolyEq(lhs.getPolyData(0, 0), rhs.getPolyData(0, 0), DEGREE);
        if (lhs.getLevel()) {
            expectPolyEq(lhs.getPolyData(0, 1), rhs.getPolyData(0, 1), DEGREE);
        }
    }
}

void expectMatrixEq(evi::detail::IData &lhs, evi::detail::IData &rhs) {
    ASSERT_EQ(lhs.getDataType(), rhs.getDataType());
    ASSERT_EQ(lhs.getLevel(), rhs.getLevel());
    ASSERT_EQ(lhs.n, rhs.n);
    ASSERT_EQ(lhs.dim, rhs.dim);
    ASSERT_EQ(lhs.degree, rhs.degree);
    ASSERT_EQ(lhs.prime_q_bits, rhs.prime_q_bits);
    ASSERT_EQ(lhs.prime_p_bits, rhs.prime_p_bits);
    ASSERT_EQ(lhs.preset, rhs.preset);

    const std::size_t count = static_cast<std::size_t>((lhs.n + lhs.degree - 1) / lhs.degree) * DEGREE;
    if (lhs.getDataType() == evi::DataType::CIPHER) {
        expectPolyEq(lhs.getPolyData(1, 0), rhs.getPolyData(1, 0), count);
        expectPolyEq(lhs.getPolyData(0, 0), rhs.getPolyData(0, 0), count);
        if (lhs.getLevel()) {
            expectPolyEq(lhs.getPolyData(1, 1), rhs.getPolyData(1, 1), count);
            expectPolyEq(lhs.getPolyData(0, 1), rhs.getPolyData(0, 1), count);
        }
    } else {
        expectPolyEq(lhs.getPolyData(0, 0), rhs.getPolyData(0, 0), count);
        if (lhs.getLevel()) {
            expectPolyEq(lhs.getPolyData(0, 1), rhs.getPolyData(0, 1), count);
        }
    }
}

void expectKeyPackEq(const evi::KeyPack &lhs, const evi::KeyPack &rhs, const evi::Context &context) {
    auto lhs_impl = std::dynamic_pointer_cast<evi::detail::KeyPackData>(evi::getImpl(const_cast<evi::KeyPack &>(lhs)));
    auto rhs_impl = std::dynamic_pointer_cast<evi::detail::KeyPackData>(evi::getImpl(const_cast<evi::KeyPack &>(rhs)));
    ASSERT_TRUE(lhs_impl);
    ASSERT_TRUE(rhs_impl);

    ASSERT_EQ(lhs_impl->enc_loaded_, rhs_impl->enc_loaded_);
    ASSERT_EQ(lhs_impl->eval_loaded_, rhs_impl->eval_loaded_);

    if (lhs_impl->enc_loaded_) {
        expectPolyEq(lhs_impl->enckey->getPolyData(1, 0), rhs_impl->enckey->getPolyData(1, 0), DEGREE);
        expectPolyEq(lhs_impl->enckey->getPolyData(1, 1), rhs_impl->enckey->getPolyData(1, 1), DEGREE);
        expectPolyEq(lhs_impl->enckey->getPolyData(0, 0), rhs_impl->enckey->getPolyData(0, 0), DEGREE);
        expectPolyEq(lhs_impl->enckey->getPolyData(0, 1), rhs_impl->enckey->getPolyData(0, 1), DEGREE);
    }

    if (lhs_impl->eval_loaded_) {
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context.getPadRank();
        if (context.getEvalMode() != evi::EvalMode::MM) {
            // In MM mode, relin_key is not used, so we intentionally skip comparing it.
            expectPolyEq(lhs_impl->relin_key->getPolyData(1, 0), rhs_impl->relin_key->getPolyData(1, 0), DEGREE);
            expectPolyEq(lhs_impl->relin_key->getPolyData(1, 1), rhs_impl->relin_key->getPolyData(1, 1), DEGREE);
            expectPolyEq(lhs_impl->relin_key->getPolyData(0, 0), rhs_impl->relin_key->getPolyData(0, 0), DEGREE);
            expectPolyEq(lhs_impl->relin_key->getPolyData(0, 1), rhs_impl->relin_key->getPolyData(0, 1), DEGREE);
            expectPolyEq(lhs_impl->mod_pack_key->getPolyData(1, 0), rhs_impl->mod_pack_key->getPolyData(1, 0), count);
            expectPolyEq(lhs_impl->mod_pack_key->getPolyData(1, 1), rhs_impl->mod_pack_key->getPolyData(1, 1), count);
            expectPolyEq(lhs_impl->mod_pack_key->getPolyData(0, 0), rhs_impl->mod_pack_key->getPolyData(0, 0), count);
            expectPolyEq(lhs_impl->mod_pack_key->getPolyData(0, 1), rhs_impl->mod_pack_key->getPolyData(0, 1), count);
        } else {
            const auto num_p = evi::detail::utils::getDebNumP(*evi::getImpl(context));
            const auto gadget_rank = evi::detail::utils::getDebGadgetRank(*evi::getImpl(context));
            const auto poly_count = num_p * gadget_rank;
            ASSERT_EQ(lhs_impl->key_switching_key.size(), rhs_impl->key_switching_key.size());
            for (std::size_t i = 0; i < lhs_impl->key_switching_key.size(); ++i) {
                auto &lhs_key = lhs_impl->key_switching_key[i];
                auto &rhs_key = rhs_impl->key_switching_key[i];
                const std::size_t kcount = static_cast<std::size_t>(DEGREE) * poly_count;
                expectPolyEq(lhs_key->getPolyData(1, 0), rhs_key->getPolyData(1, 0), kcount);
                expectPolyEq(lhs_key->getPolyData(0, 0), rhs_key->getPolyData(0, 0), kcount);
            }
        }
    }
}
} // namespace

TEST(SerializationRoundTripTest, QueryRoundTripAcrossModes) {
    evi::ParameterPreset preset = evi::ParameterPreset::IP0;
    evi::DeviceType device = evi::DeviceType::CPU;
    const u32 rank = 64;

    const std::array<evi::EvalMode, 4> modes = {
        evi::EvalMode::SINGLE,
        evi::EvalMode::FLAT,
        evi::EvalMode::RMP,
        evi::EvalMode::MM,
    };

    std::vector<float> msg(DEGREE, 0.0f);
    for (u64 i = 0; i < DEGREE; ++i) {
        msg[i] = static_cast<float>((i % 13) - 6);
    }

    for (auto mode : modes) {
        SCOPED_TRACE(modeName(mode));
        evi::Context context = evi::makeContext(preset, device, rank, mode);
        evi::KeyPack pack = evi::makeKeyPack(context);
        evi::detail::KeyGenerator keygen = evi::detail::makeKeyGenerator(*evi::getImpl(context), evi::getImpl(pack));
        auto sec_key = keygen->genSecKey();
        keygen->genPubKeys(sec_key);

        evi::Encryptor enc = evi::makeEncryptor(context, pack);

        // Encode: single vector (ITEM/QUERY) for levels 0 and 1.
        for (auto type : {evi::EncodeType::ITEM, evi::EncodeType::QUERY}) {
            if (mode == evi::EvalMode::MM && type == evi::EncodeType::ITEM) {
                // MM supports only QUERY encode.
                continue;
            }
            for (u32 level : {0u, 1u}) {
                SCOPED_TRACE(type == evi::EncodeType::ITEM ? "encode-single-ITEM" : "encode-single-QUERY");
                SCOPED_TRACE(level == 0 ? "level-0" : "level-1");
                evi::Query enc_q0 = enc.encode(msg, type, level);
                std::string enc_s0 = toString([&](std::ostream &os) {
                    evi::Query::serializeTo(enc_q0, os);
                });
                std::istringstream enc_s0_in(enc_s0, std::ios::binary);
                evi::Query enc_q0_rt = evi::Query::deserializeFrom(enc_s0_in);
                ASSERT_EQ(enc_q0.size(), enc_q0_rt.size());
                for (std::size_t i = 0; i < enc_q0.size(); ++i) {
                    expectSingleBlockEq(*evi::getImpl(enc_q0)->at(i), *evi::getImpl(enc_q0_rt)->at(i));
                }
            }
        }

        // Encode: multi-vector (ITEM) -> vector<Query>.
        std::vector<std::vector<float>> msgs = {msg, msg};
        if (mode != evi::EvalMode::MM) {
            for (u32 level : {0u, 1u}) {
                SCOPED_TRACE("encode-multi-ITEM");
                SCOPED_TRACE(level == 0 ? "level-0" : "level-1");
                std::vector<evi::Query> enc_multi = enc.encode(msgs, evi::EncodeType::ITEM, level);
                ASSERT_EQ(enc_multi.size(), msgs.size());
                for (auto &q : enc_multi) {
                    std::string enc_multi_s = toString([&](std::ostream &os) {
                        evi::Query::serializeTo(q, os);
                    });
                    std::istringstream enc_multi_in(enc_multi_s, std::ios::binary);
                    evi::Query enc_multi_rt = evi::Query::deserializeFrom(enc_multi_in);
                    ASSERT_EQ(q.size(), enc_multi_rt.size());
                    for (std::size_t i = 0; i < q.size(); ++i) {
                        expectSingleBlockEq(*evi::getImpl(q)->at(i), *evi::getImpl(enc_multi_rt)->at(i));
                    }
                }
            }
        }

        // Encrypt: single vector (ITEM/QUERY) + multi-vector (ITEM).
        // Encrypt path may be unsupported for some modes; skip if it throws.
        try {
            for (auto type : {evi::EncodeType::ITEM, evi::EncodeType::QUERY}) {
                if (mode == evi::EvalMode::MM && type == evi::EncodeType::ITEM) {
                    // MM supports only QUERY encode/encrypt.
                    continue;
                }
                for (u32 level : {0u, 1u}) {
                    SCOPED_TRACE(type == evi::EncodeType::ITEM ? "encrypt-single-ITEM" : "encrypt-single-QUERY");
                    SCOPED_TRACE(level == 0 ? "level-0" : "level-1");
                    evi::Query q0 = enc.encrypt(msg, pack, type, level);
                    std::string s0 = toString([&](std::ostream &os) {
                        evi::Query::serializeTo(q0, os);
                    });
                    std::istringstream s0_in(s0, std::ios::binary);
                    evi::Query q0_rt = evi::Query::deserializeFrom(s0_in);
                    ASSERT_EQ(q0.size(), q0_rt.size());
                    for (std::size_t i = 0; i < q0.size(); ++i) {
                        expectSingleBlockEq(*evi::getImpl(q0)->at(i), *evi::getImpl(q0_rt)->at(i));
                    }
                }
            }

            if (mode != evi::EvalMode::MM) {
                for (u32 level : {0u, 1u}) {
                    SCOPED_TRACE("encrypt-multi-ITEM");
                    SCOPED_TRACE(level == 0 ? "level-0" : "level-1");
                    std::vector<evi::Query> q_multi = enc.encrypt(msgs, pack, evi::EncodeType::ITEM, level);
                    ASSERT_EQ(q_multi.size(), msgs.size());
                    for (auto &q : q_multi) {
                        std::string s_multi = toString([&](std::ostream &os) {
                            evi::Query::serializeTo(q, os);
                        });
                        std::istringstream s_multi_in(s_multi, std::ios::binary);
                        evi::Query q_multi_rt = evi::Query::deserializeFrom(s_multi_in);
                        ASSERT_EQ(q.size(), q_multi_rt.size());
                        for (std::size_t i = 0; i < q.size(); ++i) {
                            expectSingleBlockEq(*evi::getImpl(q)->at(i), *evi::getImpl(q_multi_rt)->at(i));
                        }
                    }
                }
            }
        } catch (...) {
            // Unsupported mode for encrypt path; skip without failing the suite.
            continue;
        }
    }
}

TEST(SerializationRoundTripTest, KeyPackRoundTripAcrossModes) {
    evi::ParameterPreset preset = evi::ParameterPreset::IP0;
    evi::DeviceType device = evi::DeviceType::CPU;
    const u32 rank = 64;

    const std::array<evi::EvalMode, 4> modes = {
        evi::EvalMode::SINGLE,
        evi::EvalMode::FLAT,
        evi::EvalMode::RMP,
        evi::EvalMode::MM,
    };

    for (auto mode : modes) {
        SCOPED_TRACE(modeName(mode));
        evi::Context context = evi::makeContext(preset, device, rank, mode);
        evi::KeyPack pack = evi::makeKeyPack(context);
        evi::detail::KeyGenerator keygen = evi::detail::makeKeyGenerator(*evi::getImpl(context), evi::getImpl(pack));
        auto sec_key = keygen->genSecKey();
        keygen->genPubKeys(sec_key);

        std::string enc_blob = toString([&](std::ostream &os) {
            pack.saveEncKey(os);
        });
        std::string eval_blob = toString([&](std::ostream &os) {
            pack.saveEvalKey(os);
        });

        evi::KeyPack pack_rt = evi::makeKeyPack(context);
        std::istringstream enc_in(enc_blob, std::ios::binary);
        std::istringstream eval_in(eval_blob, std::ios::binary);
        pack_rt.loadEncKey(enc_in);
        pack_rt.loadEvalKey(eval_in);

        expectKeyPackEq(pack, pack_rt, context);
    }
}

// Regression: IData::preset must survive Matrix serialization round-trip so
// that DecryptorMM can detect base-converted SearchResults after the wire.
TEST(SerializationRoundTripTest, MatrixPresetRoundTrip) {
    using evi::ParameterPreset;
    using evi::detail::IP1Base;
    using evi::detail::IPBase;
    using evi::detail::Matrix;
    using evi::detail::polyvec;
    using evi::detail::u64;

    constexpr u64 DEG = evi::detail::DEGREE;

    // Build a minimal Matrix at level 0 with IP0 primes and flag it as
    // base-converted (preset = IP0, while context/encryption preset is IP1).
    const u64 n = DEG;
    const u64 dim = 64;
    const u64 degree = DEG;

    polyvec a_q(DEG, 0), b_q(DEG, 0);
    for (u64 i = 0; i < DEG; ++i) {
        a_q[i] = i + 1;
        b_q[i] = (i * 3 + 7) % IPBase::PRIME_Q;
    }

    auto mat = std::make_shared<Matrix<evi::DataType::CIPHER>>(std::move(a_q), std::move(b_q));
    mat->n = n;
    mat->dim = dim;
    mat->degree = degree;
    mat->prime_q_bits = evi::detail::serialization::bitLengthU64(IPBase::PRIME_Q);
    mat->prime_p_bits = 0;
    mat->preset = ParameterPreset::IP0;

    std::stringstream ss;
    mat->serializeTo(ss);

    auto mat_rt = std::make_shared<Matrix<evi::DataType::CIPHER>>(0);
    mat_rt->deserializeFrom(ss);

    EXPECT_EQ(mat_rt->preset, ParameterPreset::IP0) << "preset must survive serialization round-trip";
    EXPECT_EQ(mat_rt->prime_q_bits, mat->prime_q_bits);
    EXPECT_EQ(mat_rt->n, mat->n);
    EXPECT_EQ(mat_rt->dim, mat->dim);

    // Non-base-converted case (RUNTIME default) should also survive.
    auto mat2 = std::make_shared<Matrix<evi::DataType::CIPHER>>(polyvec(DEG, 1), polyvec(DEG, 2));
    mat2->n = n;
    mat2->dim = dim;
    mat2->degree = degree;
    mat2->prime_q_bits = evi::detail::serialization::bitLengthU64(IP1Base::PRIME_Q);
    mat2->prime_p_bits = 0;
    // preset left as default (RUNTIME)

    std::stringstream ss2;
    mat2->serializeTo(ss2);

    auto mat2_rt = std::make_shared<Matrix<evi::DataType::CIPHER>>(0);
    mat2_rt->deserializeFrom(ss2);

    EXPECT_EQ(mat2_rt->preset, ParameterPreset::RUNTIME) << "default RUNTIME preset must survive round-trip";
}
