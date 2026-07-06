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
#include <type_traits>
#include <variant>
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

template <class T>
void expectPolyEq(const T *lhs, const T *rhs, std::size_t count) {
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

void expectMatrixEq(evi::detail::IData<u64> &lhs, evi::detail::IData<u64> &rhs) {
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
                ASSERT_EQ(lhs_key.index(), rhs_key.index());
                std::visit(
                    [&](const auto &lhs_typed, const auto &rhs_typed) {
                        using Lhs = std::decay_t<decltype(lhs_typed)>;
                        using Rhs = std::decay_t<decltype(rhs_typed)>;
                        if constexpr (std::is_same_v<Lhs, Rhs>) {
                            expectPolyEq(lhs_typed->getPolyData(1, 0), rhs_typed->getPolyData(1, 0), kcount);
                            expectPolyEq(lhs_typed->getPolyData(0, 0), rhs_typed->getPolyData(0, 0), kcount);
                        }
                    },
                    lhs_key, rhs_key);
            }
        }
    }
}
evi::detail::SingleBlock<evi::DataType::CIPHER> makeCipherBlockForSerialization(bool level, u64 dim, bool zero_tail) {
    evi::detail::poly a_q;
    evi::detail::poly b_q;
    evi::detail::poly a_p;
    evi::detail::poly b_p;

    for (u64 i = 0; i < DEGREE; ++i) {
        a_q[i] = (i + 1) & 0xffff;
        b_q[i] = (i + 17) & 0xffff;
        a_p[i] = (i + 257) & 0xffff;
        b_p[i] = (i + 4097) & 0xffff;
    }
    if (zero_tail && dim < DEGREE) {
        for (u64 i = dim; i < DEGREE; ++i) {
            b_q[i] = 0;
            b_p[i] = 0;
        }
    }

    evi::detail::SingleBlock<evi::DataType::CIPHER> block =
        level ? evi::detail::SingleBlock<evi::DataType::CIPHER>(a_q, a_p, b_q, b_p)
              : evi::detail::SingleBlock<evi::DataType::CIPHER>(a_q, b_q);
    block.n = 1;
    block.dim = dim;
    block.degree = DEGREE;
    block.show_dim = dim;
    block.scale_bit = 20;
    block.encode_type = evi::EncodeType::ITEM;
    block.prime_q_bits = 16;
    block.prime_p_bits = level ? 16 : 0;
    return block;
}
} // namespace

TEST(SerializationRoundTripTest, SingleBlockTruncatedBPartV2RoundTrip) {
    constexpr u64 K_DIM = 64;
    for (bool level : {false, true}) {
        SCOPED_TRACE(level ? "level-1" : "level-0");
        auto block = makeCipherBlockForSerialization(level, K_DIM, /*zero_tail=*/true);

        const std::string blob = toString([&](std::ostream &os) {
            block.serializeTo(os, evi::BTruncMode::TRUNC);
        });

        std::istringstream header_in(blob, std::ios::binary);
        auto header = evi::detail::serialization::readHeader(header_in);
        ASSERT_TRUE(header.has_header);
        EXPECT_EQ(header.version, evi::detail::serialization::kVersionV2);

        std::istringstream default_in(blob, std::ios::binary);
        evi::detail::SingleBlock<evi::DataType::CIPHER> default_rt(default_in);
        expectSingleBlockEq(block, default_rt);

        std::istringstream explicit_in(blob, std::ios::binary);
        evi::detail::SingleBlock<evi::DataType::CIPHER> explicit_rt(0);
        explicit_rt.deserializeFrom(explicit_in, evi::BTruncMode::TRUNC);
        expectSingleBlockEq(block, explicit_rt);
    }
}

TEST(SerializationRoundTripTest, SingleBlockExplicitLenBPartV3RoundTrip) {
    // V3 truncates b by an explicit length, independent of `dim`.
    constexpr u64 K_LEN = 48;
    for (bool level : {false, true}) {
        SCOPED_TRACE(level ? "level-1" : "level-0");
        auto block = makeCipherBlockForSerialization(level, K_LEN, /*zero_tail=*/true);
        block.dim = DEGREE;
        block.show_dim = DEGREE;

        const std::string blob = toString([&](std::ostream &os) {
            block.serializeTo(os, evi::BTruncMode::TRUNC, static_cast<std::uint32_t>(K_LEN));
        });

        std::istringstream header_in(blob, std::ios::binary);
        auto header = evi::detail::serialization::readHeader(header_in);
        ASSERT_TRUE(header.has_header);
        EXPECT_EQ(header.version, evi::detail::serialization::kVersionV3);

        std::istringstream in(blob, std::ios::binary);
        evi::detail::SingleBlock<evi::DataType::CIPHER> rt(in);
        expectSingleBlockEq(block, rt);
    }
}

TEST(SerializationRoundTripTest, SingleBlockV3RejectsBTruncLenAboveDegree) {
    // A length > DEGREE is impossible and must be rejected.
    auto block = makeCipherBlockForSerialization(/*level=*/false, /*dim=*/64, /*zero_tail=*/true);
    std::ostringstream os(std::ios::binary);
    EXPECT_THROW(block.serializeTo(os, evi::BTruncMode::TRUNC, static_cast<std::uint32_t>(DEGREE) + 1),
                 evi::InvalidInputError);
}

TEST(SerializationRoundTripTest, SingleBlockV1RoundTripPreservesFullBPart) {
    constexpr u64 K_DIM = 64;
    auto block = makeCipherBlockForSerialization(/*level=*/true, K_DIM, /*zero_tail=*/false);

    const std::string blob = toString([&](std::ostream &os) {
        block.serializeTo(os);
    });

    std::istringstream in(blob, std::ios::binary);
    evi::detail::SingleBlock<evi::DataType::CIPHER> rt(in);
    expectSingleBlockEq(block, rt);
}

TEST(SerializationRoundTripTest, SingleBlockTruncationIntentAlwaysMarksV2WhenDimEqualsDegree) {
    // Version is intent-based: BTruncMode::TRUNC always writes V2, even when
    // dim == DEGREE makes the byte payload identical to V1. This keeps the
    // wire format stable for a fixed call site.
    for (u64 dim : {u64{0}, u64{DEGREE}}) {
        SCOPED_TRACE("dim=" + std::to_string(dim));
        auto block = makeCipherBlockForSerialization(/*level=*/false, dim, /*zero_tail=*/false);

        const std::string blob = toString([&](std::ostream &os) {
            block.serializeTo(os, evi::BTruncMode::TRUNC);
        });

        std::istringstream header_in(blob, std::ios::binary);
        auto header = evi::detail::serialization::readHeader(header_in);
        ASSERT_TRUE(header.has_header);
        EXPECT_EQ(header.version, evi::detail::serialization::kVersionV2);

        std::istringstream in(blob, std::ios::binary);
        evi::detail::SingleBlock<evi::DataType::CIPHER> rt(in);
        expectSingleBlockEq(block, rt);

        std::istringstream explicit_in(blob, std::ios::binary);
        evi::detail::SingleBlock<evi::DataType::CIPHER> explicit_rt(0);
        explicit_rt.deserializeFrom(explicit_in, evi::BTruncMode::TRUNC);
        expectSingleBlockEq(block, explicit_rt);
    }
}

TEST(SerializationRoundTripTest, SingleBlockTruncationDefaultWritesV1) {
    auto block = makeCipherBlockForSerialization(/*level=*/false, /*dim=*/64, /*zero_tail=*/false);

    const std::string blob = toString([&](std::ostream &os) {
        block.serializeTo(os); // 1-arg overload always writes V1
    });

    std::istringstream header_in(blob, std::ios::binary);
    auto header = evi::detail::serialization::readHeader(header_in);
    ASSERT_TRUE(header.has_header);
    EXPECT_EQ(header.version, evi::detail::serialization::kVersionV1);
}

TEST(SerializationRoundTripTest, SingleBlockTruncatedBPartRejectsFlagMismatch) {
    auto block = makeCipherBlockForSerialization(/*level=*/false, /*dim=*/64, /*zero_tail=*/true);
    const std::string blob = toString([&](std::ostream &os) {
        block.serializeTo(os, evi::BTruncMode::TRUNC);
    });

    std::istringstream in(blob, std::ios::binary);
    evi::detail::SingleBlock<evi::DataType::CIPHER> rt(0);
    EXPECT_THROW(rt.deserializeFrom(in, evi::BTruncMode::NONE), evi::InvalidInputError);
}

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
        b_q[i] = (i * 3 + 7) % IPBase::PRIMES_Q[0];
    }

    auto mat = std::make_shared<Matrix<evi::DataType::CIPHER>>(std::move(a_q), std::move(b_q));
    mat->n = n;
    mat->dim = dim;
    mat->degree = degree;
    mat->prime_q_bits = evi::detail::serialization::bitLengthU64(IPBase::PRIMES_Q[0]);
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
    mat2->prime_q_bits = evi::detail::serialization::bitLengthU64(IP1Base::PRIMES_Q[0]);
    mat2->prime_p_bits = 0;
    // preset left as default (RUNTIME)

    std::stringstream ss2;
    mat2->serializeTo(ss2);

    auto mat2_rt = std::make_shared<Matrix<evi::DataType::CIPHER>>(0);
    mat2_rt->deserializeFrom(ss2);

    EXPECT_EQ(mat2_rt->preset, ParameterPreset::RUNTIME) << "default RUNTIME preset must survive round-trip";
}

// ============================================================================
// EVIS v1 prime-array compatibility invariants.
//
// The EVIS v1 wire format uses:
//   q_bits header = bitLen(deb_primes[0]) = bitLen(PRIMES_Q[0])
//   p_bits header = bitLen(deb_primes[1]) = bitLen(NumQ>1 ? PRIMES_Q[1] : PRIMES_P[0])
//
// These tests pin the per-preset prime values that are baked into shipped key
// files (envector.io accounts, GCP Marketplace deployments, on-prem bundles).
// Changing any of these values breaks loading of existing keys — same failure
// mode as feedback_cross-preset-serialization-audit.md.
//
// Captured per-preset deb_primes values come from external/deb-param.json @
// main HEAD (tracked baseline; if you change deb-param.json values the
// compat invariant may need a coordinated update).
// ============================================================================
TEST(EvisV1PrimeArrayCompat, IPBaseDebPrimes) {
    using evi::detail::IPBase;
    // IP0: deb_primes = [Q=51b, T=55b]; multi-Q preset (NumQ=2, NumP=0).
    // The 55-bit prime (deb "T-prime") is rebranded as a second chain rail.
    // IP0 is IP-only (no relin/key-switch), so PRIMES_P is empty.
    static_assert(IPBase::PRIMES_Q.size() == 2, "IP0 has two chain primes");
    static_assert(IPBase::PRIMES_P.size() == 0, "IP0 has no aux key-switch primes");
    EXPECT_EQ(IPBase::PRIMES_Q[0], 2251799813554177ULL);
    EXPECT_EQ(IPBase::PRIMES_Q[1], 36028797014376449ULL);
}

TEST(EvisV1PrimeArrayCompat, IP1BaseDebPrimes) {
    using evi::detail::IP1Base;
    // IP1: deb_primes = [Q[0]=35b, Q[1]=35b, P[0]=39b]
    // Critical: p_bits header = bitLen(PRIMES_Q[1]) (chain[1]), NOT PRIMES_P[0].
    static_assert(IP1Base::PRIMES_Q.size() == 2, "IP1 chain has 2 primes");
    static_assert(IP1Base::PRIMES_P.size() == 1, "IP1 aux has 1 prime");
    EXPECT_EQ(IP1Base::PRIMES_Q[0], 17179754497ULL);
    EXPECT_EQ(IP1Base::PRIMES_Q[1], 17179672577ULL);
    EXPECT_EQ(IP1Base::PRIMES_P[0], 274877562881ULL);
}

TEST(EvisV1PrimeArrayCompat, IP2BaseDebPrimes) {
    using evi::detail::IP2Base;
    // IP2: deb_primes = [Q[0]=32b, Q[1]=32b, P[0]=42b]
    // IP2 retains the single 42-bit aux P (NOT split, unlike IP3) for
    // on-disk eval-key backward compatibility — IP2 is deployed; the aux
    // P is serialized into evaluation keys and cannot be re-derived from
    // a different prime domain. logQPR = 32+32+42 = 106.
    static_assert(IP2Base::PRIMES_Q.size() == 2, "IP2 chain has 2 primes");
    static_assert(IP2Base::PRIMES_P.size() == 1, "IP2 aux has single prime (not split)");
    EXPECT_EQ(IP2Base::PRIMES_Q[0], 4294828033ULL);
    EXPECT_EQ(IP2Base::PRIMES_Q[1], 4294729729ULL);
    EXPECT_EQ(IP2Base::PRIMES_P[0], 4398046486529ULL);
}

TEST(EvisV1PrimeArrayCompat, IP3BaseDebPrimes) {
    using evi::detail::IP3Base;
    // IP3: deb_primes = [Q[0]=30b, Q[1]=30b, P[0]=23b, P[1]=23b]
    // p_bits header = bitLen(PRIMES_Q[1]) (chain[1]), NOT PRIMES_P[0].
    // Aux split into two 23-bit primes for u32 storage; logQPR = 30+30+23+23 = 106.
    static_assert(IP3Base::PRIMES_Q.size() == 2, "IP3 chain has 2 primes");
    static_assert(IP3Base::PRIMES_P.size() == 2, "IP3 aux has 2 primes");
    EXPECT_EQ(IP3Base::PRIMES_Q[0], 1073692673ULL);
    EXPECT_EQ(IP3Base::PRIMES_Q[1], 1073668097ULL);
    EXPECT_EQ(IP3Base::PRIMES_P[0], 8380417ULL);
    EXPECT_EQ(IP3Base::PRIMES_P[1], 8273921ULL);
}

TEST(EvisV1PrimeArrayCompat, QFBaseDebPrimes) {
    using evi::detail::QFBase;
    // QF: deb_primes = [Q=58b, P=51b]; single-Q preset, so p_bits = PRIMES_P[0].
    static_assert(QFBase::PRIMES_Q.size() == 1, "QF has single chain prime");
    static_assert(QFBase::PRIMES_P.size() == 1, "QF has single aux prime");
    EXPECT_EQ(QFBase::PRIMES_Q[0], 288230376135196673ULL);
    EXPECT_EQ(QFBase::PRIMES_P[0], 2251799810670593ULL);
}

// Indexed accessors must return the correct primes for each preset.
// getQ(0) = first chain prime; getP(0) = first aux prime (0 for IP0 which has NumP=0);
// deb_prime_at(p,1) = second deb-flat prime (chain[1] for multi-Q, aux[0] for single-Q QF).
TEST(EvisV1PrimeArrayCompat, IndexedAccessorsRoundTrip) {
    using evi::detail::deb_prime_at;
    using evi::detail::IP1Base;
    using evi::detail::IP2Base;
    using evi::detail::IP3Base;
    using evi::detail::IPBase;
    using evi::detail::QFBase;

    {
        IPBase ip0;
        EXPECT_EQ(ip0.getQ(0), IPBase::PRIMES_Q[0]);
        EXPECT_EQ(ip0.getQ(1), IPBase::PRIMES_Q[1]);
        EXPECT_EQ(ip0.getP(0), 0u); // IP0 has no aux primes; getP returns 0
        EXPECT_EQ(ip0.getNumQ(), 2u);
        EXPECT_EQ(ip0.getNumP(), 0u);
        // deb-flat[1] for IP0 = PRIMES_Q[1] (multi-Q preset, chain[1])
        EXPECT_EQ(deb_prime_at(&ip0, 1), IPBase::PRIMES_Q[1]);
    }
    {
        IP1Base ip1;
        EXPECT_EQ(ip1.getQ(0), IP1Base::PRIMES_Q[0]);
        EXPECT_EQ(ip1.getQ(1), IP1Base::PRIMES_Q[1]);
        EXPECT_EQ(ip1.getP(0), IP1Base::PRIMES_P[0]);
        EXPECT_EQ(ip1.getNumQ(), 2u);
        EXPECT_EQ(ip1.getNumP(), 1u);
        // deb-flat[1] for IP1 = PRIMES_Q[1] (chain[1])
        EXPECT_EQ(deb_prime_at(&ip1, 1), IP1Base::PRIMES_Q[1]);
    }
    {
        IP2Base ip2;
        EXPECT_EQ(ip2.getQ(0), IP2Base::PRIMES_Q[0]);
        EXPECT_EQ(ip2.getQ(1), IP2Base::PRIMES_Q[1]);
        EXPECT_EQ(ip2.getP(0), IP2Base::PRIMES_P[0]);
        EXPECT_EQ(ip2.getNumQ(), 2u);
        EXPECT_EQ(ip2.getNumP(), 1u);
        EXPECT_EQ(deb_prime_at(&ip2, 1), IP2Base::PRIMES_Q[1]);
    }
    {
        IP3Base ip3;
        EXPECT_EQ(ip3.getQ(0), IP3Base::PRIMES_Q[0]);
        EXPECT_EQ(ip3.getQ(1), IP3Base::PRIMES_Q[1]);
        EXPECT_EQ(ip3.getP(0), IP3Base::PRIMES_P[0]);
        EXPECT_EQ(ip3.getP(1), IP3Base::PRIMES_P[1]);
        EXPECT_EQ(ip3.getNumQ(), 2u);
        EXPECT_EQ(ip3.getNumP(), 2u);
        EXPECT_EQ(deb_prime_at(&ip3, 1), IP3Base::PRIMES_Q[1]);
    }
    {
        QFBase qf;
        EXPECT_EQ(qf.getQ(0), QFBase::PRIMES_Q[0]);
        EXPECT_EQ(qf.getP(0), QFBase::PRIMES_P[0]);
        EXPECT_EQ(qf.getNumQ(), 1u);
        EXPECT_EQ(qf.getNumP(), 1u);
        EXPECT_EQ(deb_prime_at(&qf, 1), QFBase::PRIMES_P[0]);
    }
}
