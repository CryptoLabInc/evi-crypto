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

#include "EVI/impl/EncryptorImpl.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/Bitpack.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/Encode.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Profiler.hpp"
#include "utils/Sampler.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <vector>

// deb header
#include <deb/SecretKeyGenerator.hpp>
#include <deb/Serialize.hpp>

namespace evi {
namespace detail {

namespace {

// Output streambuf that appends straight into a destination std::string. Lets a
// serialized row land in its final storage with no std::ostringstream internal
// buffer and no oss.str() copy (C++17 can't move a stringbuf's buffer out). One
// allocation per row instead of two buffers + a ~per-row memcpy.
class StringAppendBuf final : public std::streambuf {
public:
    explicit StringAppendBuf(std::string &dst) : dst_(dst) {}

protected:
    std::streamsize xsputn(const char *p, std::streamsize n) override {
        dst_.append(p, static_cast<std::size_t>(n));
        return n;
    }
    int_type overflow(int_type ch) override {
        if (!traits_type::eq_int_type(ch, traits_type::eof()))
            dst_.push_back(static_cast<char>(traits_type::to_char_type(ch)));
        // not_eof(ch) returns ch for a real char and a non-eof value on eof, so
        // an eof overflow still reports success and never sets the stream badbit.
        return traits_type::not_eof(ch);
    }

private:
    std::string &dst_;
};

// Upper bound on a serialized CIPHER row so the destination string never
// reallocates mid-serialize. Over-reserves with DEGREE for the (possibly
// truncated) b polys; the slack is one row's worth, freed when the row is.
inline std::size_t packedRowReserve(int level, unsigned q_bits, unsigned p_bits) {
    std::size_t words = 2ull * bitpack::words_for(DEGREE, q_bits); // a_q + b_q
    if (level) {
        words += 2ull * bitpack::words_for(DEGREE, p_bits); // a_p + b_p (2nd Q prime)
    }
    return 128 + words * sizeof(u64); // 128: comfortably covers the fixed header
}

inline void setPrimeBits(IQuery &q, const Parameter &param) {
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(param, 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(param, 1));
    q.prime_q_bits = q_bits;
    q.prime_p_bits = (q.getLevel() ? p_bits : 0);
}

inline void setPrimeBits(IData<u64> &d, const Parameter &param) {
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(param, 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(param, 1));
    d.prime_q_bits = q_bits;
    d.prime_p_bits = (d.getLevel() ? p_bits : 0);
}
} // namespace

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed), deb_enc_key_(utils::getDebPreset(context), deb::SWK_ENC) {
    buildU64EncryptorIfNeeded(seed);
}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const KeyPack &keypack,
                                const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed), deb_enc_key_(utils::getDebPreset(context), deb::SWK_ENC) {
    buildU64EncryptorIfNeeded(seed);
    loadEncKey(keypack);
}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const std::string &dir_path,
                                const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed), deb_enc_key_(utils::getDebPreset(context), deb::SWK_ENC) {
    buildU64EncryptorIfNeeded(seed);
    loadEncKey(dir_path);
}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, std::istream &in, const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed), deb_enc_key_(utils::getDebPreset(context), deb::SWK_ENC) {
    buildU64EncryptorIfNeeded(seed);
    loadEncKey(in);
}

template <EvalMode M>
void EncryptorImpl<M>::loadEncKey(const std::string &dir_path) {
    std::ifstream in(dir_path, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load encryption key from file");
    }
    loadEncKey(in);
    in.close();
}

template <EvalMode M>
void EncryptorImpl<M>::loadEncKey(std::istream &in) {
    // TODO: replace bellow with the following deb function
    // deb::deserializeFromStream(in, deb_enc_key_);
    // utils::syncFixedKeyToDebSwkKey(context_, encKey_, deb_enc_key_);
    char preset_buf[4];
    in.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    in.read(preset_buf, sizeof(preset_buf));
    auto header = serialization::readHeader(in);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported encryption key serialization version");
    }
    if (header.has_header) {
        uint8_t q_bits = 0;
        uint8_t p_bits = 0;
        in.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        in.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
        if (utils::isU32NativePreset(context_)) {
            // u32-native (IP3): unpack straight into the u32 enc key. No u64
            // encKey_/deb_enc_key_ is materialized. The packed wire is
            // byte-identical to the u64 path, so q_bits/p_bits are the same.
            deb_enc_key32_.emplace(utils::getDebPreset(context_), deb::SWK_ENC);
            deb_enc_key32_->addAx(2, 1);
            deb_enc_key32_->addBx(2, 1);
            serialization::readPacked<u32>(in, deb_enc_key32_->ax(0)[0].data(), DEGREE, q_bits);
            serialization::readPacked<u32>(in, deb_enc_key32_->ax(0)[1].data(), DEGREE, p_bits);
            serialization::readPacked<u32>(in, deb_enc_key32_->bx(0)[0].data(), DEGREE, q_bits);
            serialization::readPacked<u32>(in, deb_enc_key32_->bx(0)[1].data(), DEGREE, p_bits);
            enc_loaded_ = true;
            return;
        }
        serialization::readPacked<u64>(in, encKey_->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(in, encKey_->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPacked<u64>(in, encKey_->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(in, encKey_->getPolyData(0, 1), DEGREE, p_bits);
    } else {
        in.read(reinterpret_cast<char *>(encKey_->getPolyData(1, 0)), U64_DEGREE);
        in.read(reinterpret_cast<char *>(encKey_->getPolyData(1, 1)), U64_DEGREE);
        in.read(reinterpret_cast<char *>(encKey_->getPolyData(0, 0)), U64_DEGREE);
        in.read(reinterpret_cast<char *>(encKey_->getPolyData(0, 1)), U64_DEGREE);
    }
    utils::syncFixedKeyToDebSwkKey(context_, encKey_, deb_enc_key_);
    deb_enc_key32_.reset(); // rebuilt lazily from the new u64 enc key (IP3)
    enc_loaded_ = true;
}

template <EvalMode M>
void EncryptorImpl<M>::loadEncKey(const KeyPack &kp) {
    auto keypack = std::dynamic_pointer_cast<KeyPackData>(kp);
    if (!keypack) {
        throw std::logic_error("EncryptorImpl::loadEncKey: KeyPack is not KeyPackData");
    }
    enc_loaded_ = keypack->enc_loaded_;
    deb_enc_key32_.reset();
    if (keypack->deb_enc_key32) {
        // u32-native (IP3): take the u32 enc key directly; no u64 key to copy
        // or narrow. ensureU32EncResources sees deb_enc_key32_ set and skips
        // the narrow path.
        deb_enc_key32_ = keypack->deb_enc_key32;
    } else {
        encKey_ = keypack->enckey;
        deb_enc_key_ = keypack->deb_enc_key;
    }
    if constexpr (CHECK_SHARED_A(M)) {
        switch_key_ = keypack->switch_key;
    }
}

/**
 * ===========================
 *           Encrypt
 * ===========================
 */

template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const std::string &enckey_path, const EncodeType type,
                                const std::optional<uint32_t> level, std::optional<float> scale) {
    loadEncKey(enckey_path);
    return encrypt(msg, type, level, scale);
}

template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type,
                                const std::optional<uint32_t> level, std::optional<float> scale) {
    loadEncKey(enckey_stream);
    return encrypt(msg, type, level, scale);
}

template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type,
                                const std::optional<uint32_t> level, std::optional<float> scale) {
    loadEncKey(keypack);
    return encrypt(msg, type, level, scale);
}

// encrypt using secret key
template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type,
                                const std::optional<uint32_t> level, std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    Query res;
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }

    std::array<float, DEGREE> tmp_msg{};
    if (type == EncodeType::ITEM) {
        std::copy_n(msg.begin(), msg.size(), tmp_msg.begin());
    } else {
        u64 pad_size = isPowerOfTwo(msg.size()) ? msg.size() : nextPowerOfTwo(msg.size());
        u64 pad_offset = pad_size - msg.size();
        std::reverse_copy(msg.begin(), msg.end(), tmp_msg.begin() + pad_offset);
    }

    double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));
    Query::SingleQuery s = innerEncrypt(tmp_msg, actual_level, delta, seckey);
    s->n = 1;
    s->dim = msg.size();
    s->show_dim = msg.size();
    s->degree = DEGREE;
    s->encode_type = type;
    res.emplace_back(s);

    return res;
}

// encrypt using multi secret key
template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const MultiSecretKey &seckey, const EncodeType type,
                                const std::optional<uint32_t> level, std::optional<float> scale) {
    if constexpr (!CHECK_SHARED_A(M)) {
        throw InvalidAccessError("Inappropriate API usage");
    }

    poly ctxt_a_q, copy_a_q, ctxt_b_q, ctxt_b_p, ctxt_a_p;

    sampler_.sampleUniformModQ(ctxt_a_q);
    for (u64 i = 0; i < DEGREE; i++) {
        copy_a_q[i] = ctxt_a_q[i];
    }
    context_->nttModQ(ctxt_a_q);
    context_->negateModQ(ctxt_a_q);
    context_->nttModQ(copy_a_q);
    std::vector<polyvec> tmp_res;
    tmp_res.emplace_back(copy_a_q.begin(), copy_a_q.end());

    uint32_t tmp_dim = msg.size();
    uint32_t tmp_rank = getInnerRank(tmp_dim);
    uint32_t item_per_ciphertext = DEGREE / seckey.size();
    uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
    u64 copy_offset = 0;
    for (u64 j = 0; j < num_db; j++) {
        std::array<float, DEGREE> tmp_msg{};
        u64 copy_size = copy_offset + tmp_rank <= msg.size() ? tmp_rank : msg.size() - copy_offset;
        std::copy_n(msg.begin() + copy_offset, copy_size, tmp_msg.begin());
        if (type == EncodeType::QUERY) {
            std::reverse(tmp_msg.begin(), tmp_msg.begin() + tmp_rank);
        }
        copy_offset += copy_size;

        double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));
        sampler_.sampleGaussian(ctxt_b_q);
        for (u64 i = 0; i < item_per_ciphertext; ++i) {
            i128 temp = static_cast<i128>(tmp_msg[i] * delta + (tmp_msg[i] > 0 ? 0.5 : -0.5));
            bool is_positive = temp >= 0;
            temp = is_positive ? temp : -temp;

            u64 value_q = reduceBarrett(context_->getParam()->getQ(0), context_->getParam()->getTwoPrimeQ(0),
                                        context_->getParam()->getTwoTo64Q(0), context_->getParam()->getTwoTo64ShoupQ(0),
                                        context_->getParam()->getBarrRatioQ(0), static_cast<u128>(temp));
            ctxt_b_q[i] += (is_positive ? value_q : (context_->getParam()->getQ(0) - value_q));
            if (ctxt_b_q[i] >= context_->getParam()->getQ(0)) {
                ctxt_b_q[i] -= context_->getParam()->getQ(0);
            }
        }

        context_->nttModQ(ctxt_b_q);
        SecretKeyAccessScope key_access_j(seckey[j]);
        context_->madModQ(ctxt_a_q, seckey[j]->getKeyQ(), ctxt_b_q);
        tmp_res.emplace_back(ctxt_b_q.begin(), ctxt_b_q.end());
    }

    // Shared-a to HERS Query (query unpacking)
    Query res;
    poly up_p;
    context_->modUp(tmp_res[0], up_p);
    for (u64 j = 0; j < num_db; j++) {
        context_->multModQ(tmp_res[0], switch_key_->getPolyData(0, 0) + (j % context_->getPadRank()) * DEGREE,
                           ctxt_b_q);
        context_->multModP(up_p, switch_key_->getPolyData(0, 1) + (j % context_->getPadRank()) * DEGREE, ctxt_b_p);
        context_->multModQ(tmp_res[0], switch_key_->getPolyData(1, 0) + (j % context_->getPadRank()) * DEGREE,
                           ctxt_a_q);
        context_->multModP(up_p, switch_key_->getPolyData(1, 1) + (j % context_->getPadRank()) * DEGREE, ctxt_a_p);
        context_->modDown(ctxt_a_q, ctxt_a_p);
        context_->modDown(ctxt_b_q, ctxt_b_p);
        context_->addModQ(ctxt_b_q, tmp_res[j + 1], ctxt_b_q);
        res.push_back(std::make_shared<SingleBlock<DataType::CIPHER>>(ctxt_a_q, ctxt_b_q));
        setPrimeBits(*res.back(), context_->getParam());
        res.back()->n = 1;
        res.back()->degree = DEGREE;
        res.back()->dim = context_->getPadRank();
        res.back()->show_dim = msg.size();
        res.back()->encode_type = type;
    }

    return res;
}

// encrypt using encryption key
template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const EncodeType type, const std::optional<uint32_t> level,
                                std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    if constexpr (CHECK_SHARED_A(M) || CHECK_MM(M)) {
        throw evi::NotSupportedError("Encryption is not supported in the current EvalMode shared-a or MM");
    }
    if (!enc_loaded_) {
        throw evi::EncryptionError("Encryption key is not loaded for encryption");
    }
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }
    double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));

    Query res;
    if constexpr (!CHECK_RMP(M)) {
        std::array<float, DEGREE> tmp_msg{};
        if (type == EncodeType::ITEM) {
            std::copy_n(msg.begin(), msg.size(), tmp_msg.begin());
        } else {
            u64 pad_size = isPowerOfTwo(msg.size()) ? msg.size() : nextPowerOfTwo(msg.size());
            u64 pad_offset = pad_size - msg.size();
            std::reverse_copy(msg.begin(), msg.end(), tmp_msg.begin() + pad_offset);
        }

        auto s = innerEncrypt(tmp_msg, actual_level, delta);
        s->n = 1;
        s->dim = msg.size();
        s->show_dim = msg.size();
        s->degree = DEGREE;
        s->encode_type = type;
        res.emplace_back(s);
    } else {
        uint32_t tmp_dim = msg.size();
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
        u64 copy_offset = 0;
        for (u64 j = 0; j < num_db; j++) {
            std::array<float, DEGREE> tmp_msg{};
            u64 copy_size = copy_offset + tmp_rank <= msg.size() ? tmp_rank : msg.size() - copy_offset;
            std::copy_n(msg.begin() + copy_offset, copy_size, tmp_msg.begin());
            if (type == EncodeType::QUERY) {
                std::reverse(tmp_msg.begin(), tmp_msg.begin() + tmp_rank);
            }
            copy_offset += copy_size;
            auto tmp = innerEncrypt(tmp_msg, actual_level, delta);
            tmp->n = 1;
            tmp->dim = tmp_rank;
            tmp->show_dim = msg.size();
            tmp->degree = DEGREE;
            tmp->encode_type = type;
            res.push_back(tmp);
        }
    }
    return res;
}

// batch encrypt using encryption key

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, const KeyPack &keypack,
                                             const EncodeType type, const std::optional<uint32_t> level,
                                             std::optional<float> scale) {
    loadEncKey(keypack);
    if constexpr (CHECK_MM(M)) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                                             const EncodeType type, const std::optional<uint32_t> level,
                                             std::optional<float> scale) {
    loadEncKey(enckey_path);
    if (CHECK_MM(context_->getEvalMode())) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                                             const EncodeType type, const std::optional<uint32_t> level,
                                             std::optional<float> scale) {
    loadEncKey(enckey_stream);
    if (CHECK_MM(context_->getEvalMode())) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, const EncodeType type,
                                             const std::optional<uint32_t> level, std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    if (!enc_loaded_) {
        throw evi::EncryptionError("Encryption key is not loaded for encryption");
    }
    if (!msg.size()) {
        throw evi::EncryptionError("Nothing to encrypt! Input message must has its size");
    }

    if constexpr (CHECK_RMP(M)) {
        if (type == EncodeType::QUERY) {
            throw evi::NotSupportedError("EncodeType::QUERY is not supported for batch encryption");
        }
        uint32_t tmp_dim = msg[0].size();
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;

        uint32_t total_items = msg.size();
        uint32_t num_item_per_ctxt = DEGREE / tmp_rank;
        std::vector<Query> res;
        uint32_t num_clean_batch_query = total_items / num_item_per_ctxt;
        uint32_t num_query = num_clean_batch_query;
        std::vector<u32> log_items(std::log2(num_item_per_ctxt) + 1, 0);
        {
            uint32_t num_left = total_items % num_item_per_ctxt;
            for (uint32_t i = 1, j = 0; i <= num_left; i = 2 * i, j++) {
                log_items[j] = 1;
                num_left -= i;
                num_query++;
            }
            int loop = 0;
            while (num_left > 0) {
                if (num_left & 1) {
                    log_items[loop] += 1;
                    num_query++;
                }
                num_left >>= 1;
                loop++;
            }
        }
        res.reserve(num_query);

        double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));

        // for full slot items.
        for (u32 query_idx = 0; query_idx < num_clean_batch_query; query_idx++) {
            res.emplace_back();
            res.back().reserve(num_db);
            for (u32 db_idx = 0; db_idx < num_db; ++db_idx) {
                polyvec a_q, b_q;
                std::optional<polyvec> a_p, b_p;

                std::array<float, DEGREE> inner_msg{};
                for (int i = query_idx * num_item_per_ctxt; i < (query_idx + 1) * num_item_per_ctxt; i++) {
                    auto copy_size = std::min(int32_t(msg[i].size()) - int32_t(db_idx * tmp_rank), int32_t(tmp_rank));
                    if (copy_size < 0) {
                        copy_size = 0;
                    }
                    std::copy_n(msg[i].begin() + db_idx * tmp_rank, copy_size,
                                inner_msg.begin() + (i % num_item_per_ctxt) * tmp_rank);
                }

                Query::SingleQuery tmp = innerEncrypt(inner_msg, actual_level, delta);
                tmp->n = num_item_per_ctxt;
                tmp->dim = tmp_rank;
                tmp->show_dim = msg[0].size();
                tmp->degree = DEGREE;
                tmp->encode_type = type;
                res.back().emplace_back(tmp);
            }
        }

        // not a full slot items.
        for (u32 item_idx = 0, item_size = 1, start_idx = num_clean_batch_query * num_item_per_ctxt;
             item_idx < log_items.size(); item_idx++, item_size *= 2) {
            for (u32 j = 0; j < log_items[item_idx]; j++) {
                res.emplace_back();
                res.back().reserve(num_db);
                for (u32 db_idx = 0; db_idx < num_db; ++db_idx) {

                    std::array<float, DEGREE> inner_msg{};
                    for (int i = start_idx; i < start_idx + item_size; i++) {
                        auto copy_size =
                            std::min(int32_t(msg[i].size()) - int32_t(db_idx * tmp_rank), int32_t(tmp_rank));
                        if (copy_size < 0) {
                            copy_size = 0;
                        }
                        std::copy_n(msg[i].begin() + db_idx * tmp_rank, copy_size,
                                    inner_msg.begin() + (i - start_idx) * tmp_rank);
                    }

                    Query::SingleQuery tmp = innerEncrypt(inner_msg, actual_level, delta);
                    tmp->n = item_size;
                    tmp->dim = tmp_rank;
                    tmp->show_dim = msg[0].size();
                    tmp->degree = DEGREE;
                    tmp->encode_type = type;
                    res.back().emplace_back(tmp);
                }
                start_idx += item_size;
            }
        }
        return res;
    } else if constexpr (M == EvalMode::FLAT) {
        std::vector<Query> res;
        res.reserve(msg.size());
        for (const auto &item : msg) {
            res.emplace_back(encrypt(evi::span<float>(item), type, actual_level, scale));
        }
        return res;
    } else {
        throw evi::NotSupportedError("Batch encryption is not supported for this evaluation mode");
    }
}

template <EvalMode M>
std::vector<std::string> EncryptorImpl<M>::encryptRow(const std::vector<std::vector<float>> &msg, const EncodeType type,
                                                      const std::optional<uint32_t> level, std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    if constexpr (!CHECK_MM(M)) {
        throw evi::NotSupportedError("Batch encryption is only supported for MM mode");
    }

    double delta = 0.0;
    double scale_bits = 0.0;
    if (type == EncodeType::QUERY) {
        scale_bits = context_->getParam()->getScaleFactor();
    } else {
        scale_bits = actual_level ? context_->getParam()->getDBScaleFactor() : context_->getParam()->getScaleFactor();
    }
    delta = scale.value_or(std::pow(2.0, scale_bits));

    const bool use_u32 = utils::isU32NativePreset(context_);
    std::vector<std::string> res;
    for (int i = 0; i < msg.size(); i++) {

        // Row-storage truncation is valid only because b stays in coefficient domain.
        if (use_u32) {
            // u32-native: encrypt into u32 buffers and pack the row directly via
            // serializeCipherBlockRow<u32> (byte-identical to the u64
            // SingleBlock::serializeTo TRUNC, values < 2^32). No u64 SingleBlock,
            // no u32->u64->u32 round-trip.
            deb::CoeffMessage deb_msg(DEGREE);
            for (size_t j = 0; j < DEGREE; ++j) {
                deb_msg[j] = (j < msg[i].size()) ? static_cast<double>(msg[i][j]) : 0.0;
            }
            poly32 a_q{}, b_q{}, a_p{}, b_p{};
            innerEncryptInto<u32>(deb_msg, actual_level, delta, /*ntt_val=*/false, std::nullopt, a_q.data(), b_q.data(),
                                  actual_level ? a_p.data() : nullptr, actual_level ? b_p.data() : nullptr);

            SingleBlock<DataType::CIPHER> meta(static_cast<int>(actual_level));
            meta.n = 1;
            meta.dim = context_->getRank();
            meta.show_dim = context_->getShowRank();
            meta.degree = DEGREE;
            meta.encode_type = type;
            meta.scale_bit = std::log2(delta);
            setPrimeBits(meta, context_->getParam());

            // Serialize straight into the row's final storage (no ostringstream,
            // no str() copy).
            res.emplace_back();
            std::string &dst = res.back();
            dst.reserve(packedRowReserve(static_cast<int>(actual_level), meta.prime_q_bits, meta.prime_p_bits));
            StringAppendBuf sbuf(dst);
            std::ostream os(&sbuf);
            serializeCipherBlockRow<u32>(os, meta, a_q.data(), b_q.data(), a_p.data(), b_p.data(),
                                         evi::BTruncMode::TRUNC, meta.prime_q_bits, meta.prime_p_bits);
            continue;
        }

        Query::SingleQuery single_query = innerEncrypt(msg[i], actual_level, delta, std::nullopt, /*is_ntt=*/false);

        single_query->n = 1;
        single_query->dim = context_->getRank();
        single_query->show_dim = context_->getShowRank();
        single_query->degree = DEGREE;
        single_query->encode_type = type;
        single_query->scale_bit = std::log2(delta);

        // dynamic_pointer_cast guards against silently-UB downcasts. innerEncrypt
        // is expected to return a SingleBlock<CIPHER> here, but a type-tag-only
        // check is too cheap to skip given the consequences of a wrong cast.
        auto block = std::dynamic_pointer_cast<SingleBlock<DataType::CIPHER>>(single_query);
        if (!block) {
            throw evi::InvalidInputError("EncryptorImpl::encryptRow: query is not SingleBlock<CIPHER>");
        }
        // Serialize straight into the row's final storage (no ostringstream copy).
        res.emplace_back();
        StringAppendBuf sbuf(res.back());
        std::ostream os(&sbuf);
        block->serializeTo(os, evi::BTruncMode::TRUNC);
    }
    return res;
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encryptMM(const std::vector<std::vector<float>> &msg, const EncodeType type,
                                               const std::optional<uint32_t> level, std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    if (!msg.size()) {
        throw evi::EncryptionError("EncryptorImpl<M>::encryptMM Nothing to encrypt! Input message must has its size");
    }
    if constexpr (!CHECK_MM(M)) {
        throw evi::NotSupportedError("Batch encryption is only supported for MM mode");
    }

    double delta = 0.0;
    double scale_bits = 0.0;
    if (type == EncodeType::QUERY) {
        scale_bits = context_->getParam()->getScaleFactor();
    } else {
        scale_bits = actual_level ? context_->getParam()->getDBScaleFactor() : context_->getParam()->getScaleFactor();
    }
    delta = scale.value_or(std::pow(2.0, scale_bits));

    int rows = msg[0].size();
    int cols = DEGREE;
    int batch = (msg.size() + DEGREE - 1) / DEGREE;

    std::vector<Query> queries;
    queries.reserve(batch);
    const bool use_u32 = utils::isU32NativePreset(context_);

    for (int b = 0; b < batch; b++) {
        const size_t col_offset = static_cast<size_t>(b) * static_cast<size_t>(cols);
        const size_t remaining_cols = col_offset < msg.size() ? (msg.size() - col_offset) : 0;
        const u32 col_base = static_cast<u32>(std::min(static_cast<size_t>(cols), remaining_cols));

        Query q;
        q.setItemCount(col_base);
        q.reserve(use_u32 ? 1 : rows);
        std::shared_ptr<Matrix<DataType::CIPHER, u32>> typed;
        if (use_u32) {
            typed = std::make_shared<Matrix<DataType::CIPHER, u32>>(static_cast<int>(actual_level));
            typed->setSize(rows * DEGREE);
        }
        for (u64 i = 0; i < static_cast<u64>(rows); ++i) {

            std::array<float, DEGREE> coeff_msg{};
            for (u64 j = 0; j < static_cast<u64>(col_base); ++j) {
                coeff_msg[j] = static_cast<float>(msg[col_offset + j][i]);
            }
            if (use_u32) {
                // u32-native: encrypt straight into the typed Matrix<CIPHER,u32>
                // row. No u64 SingleBlock, no u32->u64->u32 round-trip.
                deb::CoeffMessage deb_msg(DEGREE);
                for (size_t j = 0; j < DEGREE; ++j) {
                    deb_msg[j] = static_cast<double>(coeff_msg[j]);
                }
                const std::size_t offset = static_cast<std::size_t>(i) * DEGREE;
                innerEncryptInto<u32>(deb_msg, actual_level, delta, /*ntt_val=*/false, std::nullopt,
                                      typed->getPolyData(1, 0) + offset, typed->getPolyData(0, 0) + offset,
                                      actual_level ? typed->getPolyData(1, 1) + offset : nullptr,
                                      actual_level ? typed->getPolyData(0, 1) + offset : nullptr);
                if (q.empty()) {
                    // serializeQueryTo/setMatrix read only metadata from query[0]
                    // for IP3 (polys come from the typed state), so a
                    // metadata-only block suffices — no ciphertext widen.
                    auto meta = std::make_shared<SingleBlock<DataType::CIPHER>>(static_cast<int>(actual_level));
                    meta->n = col_base;
                    meta->dim = static_cast<u64>(rows);
                    meta->show_dim = static_cast<u64>(rows);
                    meta->degree = DEGREE;
                    meta->encode_type = type;
                    meta->scale_bit = std::log2(delta);
                    q.push_back(std::move(meta));
                }
            } else {
                Query::SingleQuery tmp = innerEncrypt(coeff_msg, actual_level, delta, std::nullopt, /*is_ntt*/ false);
                tmp->n = col_base;
                tmp->dim = static_cast<u64>(rows);
                tmp->show_dim = static_cast<u64>(rows);
                tmp->degree = DEGREE;
                tmp->encode_type = type;
                tmp->scale_bit = std::log2(delta);
                q.push_back(tmp);
            }
        }
        if (typed) {
            typed->n = col_base;
            typed->dim = static_cast<u64>(rows);
            typed->degree = DEGREE;
            typed->scale_bit = static_cast<u64>(std::log2(delta));
            typed->preset = ParameterPreset::IP3;
            typed->prime_q_bits = serialization::bitLengthU64(context_->getParam()->getQ(0));
            typed->prime_p_bits = actual_level ? serialization::bitLengthU64(context_->getParam()->getQ(1)) : 0;
            q.setTypedDataState(std::move(typed), rows);
        }
        queries.emplace_back(std::move(q));
    }
    return queries;
}

template <EvalMode M>
void EncryptorImpl<M>::buildU64EncryptorIfNeeded(const std::optional<std::vector<u8>> &seed) {
    if (!utils::isU32NativePreset(context_) && !deb_encryptor_) {
        deb_encryptor_.emplace(utils::getDebPreset(context_), utils::convertDebSeed(seed));
    }
}

template <EvalMode M>
void EncryptorImpl<M>::ensureU32EncResources() {
    if (!deb_encryptor32_) {
        // Runtime-preset u32 encryptor (EncryptorT<PRESET_EMPTY,u32>); reads
        // IP3 constants/primes at runtime. Randomized encryption -> no seed
        // needed for correctness.
        deb_encryptor32_.emplace(utils::getDebPreset(context_));
    }
    // Build the u32 enc key from the loaded u64 enc key (lossless narrow:
    // IP3 limbs < 2^32), copying NTT state per polyunit so deb's u32 encrypt
    // sees the identical key representation as the u64 path. Skipped entirely
    // when the key was loaded straight into u32 (deb_enc_key32_ already set) —
    // the u32-native path keeps no u64 enc key to narrow from.
    if (enc_loaded_ && !deb_enc_key32_) {
        deb_enc_key32_.emplace(utils::getDebPreset(context_), deb::SWK_ENC);
        deb_enc_key32_->addAx(2, 1);
        deb_enc_key32_->addBx(2, 1);
        auto narrow_unit = [](const deb::PolyUnit &src, deb::PolyUnit32 &dst) {
            std::copy_n(src.data(), DEGREE, dst.data());
            if (src.isNTT()) {
                dst.setNTT(src.getNTTType(), src.getNTTRootType());
            } else {
                dst.setNTT(deb::utils::NTTType::NONNTT);
            }
        };
        for (deb::Size q = 0; q < 2; ++q) {
            narrow_unit(deb_enc_key_.ax(0)[q], deb_enc_key32_->ax(0)[q]);
            narrow_unit(deb_enc_key_.bx(0)[q], deb_enc_key32_->bx(0)[q]);
        }
    }
}

template <EvalMode M>
template <typename U>
void EncryptorImpl<M>::innerEncryptInto(const deb::CoeffMessage &deb_msg, const uint32_t level, const double scale,
                                        const bool ntt_val, const std::optional<const SecretKey> &seckey, U *a_q,
                                        U *b_q, U *a_p, U *b_p) {
    // deb writes the ciphertext (width U) in-place into the caller-owned limb
    // buffers. No SingleBlock, no widen — u32 callers (encryptMM typed Matrix,
    // encryptRow packed row) point these at their u32 destination directly.
    deb::CiphertextT<U> ctxt = level ? utils::convertPointerToDebCipher<U>(context_, a_q, b_q, a_p, b_p)
                                     : utils::convertPointerToDebCipher<U>(context_, a_q, b_q, nullptr, nullptr);
    const auto opt = deb::EncryptOptions().Scale(scale).Level(level).NttOut(ntt_val);

    if constexpr (std::is_same_v<U, u32>) {
        ensureU32EncResources();
        if (seckey.has_value()) {
            SecretKeyAccessScope key_access(*seckey);
            deb_encryptor32_->encrypt(deb_msg, (*seckey)->getDebSecKey32(utils::getDebPreset(context_)), ctxt, opt);
        } else {
            deb_encryptor32_->encrypt(deb_msg, *deb_enc_key32_, ctxt, opt);
        }
    } else {
        if (seckey.has_value()) {
            SecretKeyAccessScope key_access(*seckey);
            deb_encryptor_->encrypt(deb_msg, (*seckey)->getDebSecKey(), ctxt, opt);
        } else {
            deb_encryptor_->encrypt(deb_msg, deb_enc_key_, ctxt, opt);
        }
    }
}

template <EvalMode M>
template <typename U>
Query::SingleQuery EncryptorImpl<M>::innerEncryptT(const deb::CoeffMessage &deb_msg, const uint32_t level,
                                                   const double scale, const bool ntt_val,
                                                   const std::optional<const SecretKey> &seckey) {
    AlignedArray<U, DEGREE> a_q{}, b_q{}, a_p{}, b_p{};
    innerEncryptInto<U>(deb_msg, level, scale, ntt_val, seckey, a_q.data(), b_q.data(), level ? a_p.data() : nullptr,
                        level ? b_p.data() : nullptr);

    auto make_block = [&](const poly_t<U> &qa, const poly_t<U> &qb, const poly_t<U> *pa,
                          const poly_t<U> *pb) -> Query::SingleQuery {
        auto res = pa ? std::make_shared<SingleBlock<DataType::CIPHER, U>>(qa, *pa, qb, *pb)
                      : std::make_shared<SingleBlock<DataType::CIPHER, U>>(qa, qb);
        setPrimeBits(*res, context_->getParam());
        return res;
    };

    if (level) {
        return make_block(a_q, b_q, &a_p, &b_p);
    }
    return make_block(a_q, b_q, nullptr, nullptr);
}

template <EvalMode M>
Query::SingleQuery EncryptorImpl<M>::innerEncrypt(const span<float> &msg, const uint32_t level, const double scale,
                                                  std::optional<const SecretKey> seckey, std::optional<bool> ntt) {
    deb::CoeffMessage deb_msg(DEGREE);
    for (size_t i = 0; i < DEGREE; ++i) {
        deb_msg[i] = (i < msg.size()) ? static_cast<double>(msg[i]) : 0.0;
    }
    const bool ntt_val = ntt.value_or(true);

    // IP3 -> deb::Encryptor32 (u32-native); all other presets -> u64.
    if (utils::isU32NativePreset(context_)) {
        return innerEncryptT<u32>(deb_msg, level, scale, ntt_val, seckey);
    }
    return innerEncryptT<u64>(deb_msg, level, scale, ntt_val, seckey);
}

/**
 * ===========================
 *           Encode
 * ===========================
 */

template <EvalMode M>
Query EncryptorImpl<M>::encode(const std::vector<std::vector<float>> &msg, const EncodeType type,
                               const std::optional<uint32_t> level, std::optional<float> scale) {
    Query res;
    res.reserve(msg.size());
    for (const auto &row : msg) {
        Query partial = encode(span<float>(row), type, level, scale);
        res.append(partial);
    }
    return res;
}

template <EvalMode M>
Query EncryptorImpl<M>::encode(const span<float> msg, const EncodeType type, const std::optional<uint32_t> level,
                               std::optional<float> scale) {
    const uint32_t actual_level = level.value_or(context_->getParam()->getNumQ() - 1);
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }
    double scale_bits;
    if (scale.has_value()) {
        scale_bits = static_cast<u64>(std::log2(scale.value()));
    } else {
        scale_bits = context_->getParam()->getQueryScaleFactor();
    }
    double delta = scale.value_or(std::pow(2.0, scale_bits));

    u64 pad_size = 0;
    Query res;
    if constexpr (CHECK_MM(M)) {
        if (type != EncodeType::QUERY) {
            throw evi::NotSupportedError("Only EncodeType::QUERY is supported for EvalMode::MM.");
        }
        auto tmp = innerEncode(msg, actual_level, delta, msg.size(), /* ntt */ false);
        setPrimeBits(*tmp, context_->getParam());
        tmp->n = 1;
        tmp->dim = msg.size();
        tmp->degree = DEGREE;
        tmp->encode_type = type;
        tmp->show_dim = msg.size();
        tmp->scale_bit = scale_bits;
        res.emplace_back(tmp);

    } else if constexpr (M == EvalMode::RMP) {
        uint32_t tmp_dim = msg.size();
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
        u64 copy_offset = 0;
        for (u64 j = 0; j < num_db; j++) {
            std::array<float, DEGREE> tmp_msg{};
            u64 copy_size = copy_offset + tmp_rank <= msg.size() ? tmp_rank : msg.size() - copy_offset;
            std::copy_n(msg.begin() + copy_offset, copy_size, tmp_msg.begin());
            if (type == EncodeType::QUERY) {
                std::reverse(tmp_msg.begin(), tmp_msg.begin() + tmp_rank);
            }
            copy_offset += copy_size;
            auto tmp = innerEncode(tmp_msg, actual_level, delta, tmp_rank);
            setPrimeBits(*tmp, context_->getParam());
            tmp->n = 1;
            tmp->dim = tmp_rank;
            tmp->show_dim = msg.size();
            tmp->degree = DEGREE;
            tmp->encode_type = type;
            tmp->scale_bit = scale_bits;
            res.emplace_back(tmp);
        }

    } else if constexpr (M == EvalMode::RMS) {
        uint32_t tmp_dim = msg.size();
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
        u64 copy_offset = 0;
        for (u64 j = 0; j < num_db; j++) {
            std::array<float, DEGREE> tmp_msg{};
            u64 copy_size = copy_offset + tmp_rank <= msg.size() ? tmp_rank : msg.size() - copy_offset;
            std::copy_n(msg.begin() + copy_offset, copy_size, tmp_msg.begin());
            if (type == EncodeType::QUERY) {
                std::reverse(tmp_msg.begin(), tmp_msg.begin() + tmp_rank);
            }
            copy_offset += copy_size;

            double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));
            poly plaintext_q{};

            for (u64 i = 0; i < tmp_rank; ++i) {
                i128 temp = static_cast<i128>(tmp_msg[i] * delta + (tmp_msg[i] > 0 ? 0.5 : -0.5));
                bool is_positive = temp >= 0;
                temp = is_positive ? temp : -temp;

                u64 value_q =
                    reduceBarrett(context_->getParam()->getQ(0), context_->getParam()->getTwoPrimeQ(0),
                                  context_->getParam()->getTwoTo64Q(0), context_->getParam()->getTwoTo64ShoupQ(0),
                                  context_->getParam()->getBarrRatioQ(0), static_cast<u128>(temp));
                plaintext_q[i] = is_positive ? value_q : (context_->getParam()->getQ(0) - value_q);
            }
            context_->nttModQMini(plaintext_q, tmp_rank);
            auto single_query = std::make_shared<SingleBlock<DataType::PLAIN>>(plaintext_q);
            setPrimeBits(*single_query, context_->getParam());
            single_query->n = 1;
            single_query->dim = tmp_rank;
            single_query->show_dim = msg.size();
            single_query->degree = DEGREE;
            single_query->encode_type = type;
            single_query->scale_bit = scale_bits;
            res.emplace_back(single_query);
        }

    } else {
        std::array<float, DEGREE> tmp_msg{};
        if (type == EncodeType::ITEM) {
            std::copy_n(msg.begin(), msg.size(), tmp_msg.begin());
        } else {
            pad_size = isPowerOfTwo(msg.size()) ? msg.size() : nextPowerOfTwo(msg.size());
            u64 pad_offset = pad_size - msg.size();
            std::reverse_copy(msg.begin(), msg.end(), tmp_msg.begin() + pad_offset);
        }

        auto tmp = innerEncode(tmp_msg, actual_level, delta);
        setPrimeBits(*tmp, context_->getParam());
        tmp->n = 1;
        tmp->dim = msg.size();
        tmp->degree = DEGREE;
        tmp->encode_type = type;
        tmp->show_dim = msg.size();
        tmp->scale_bit = scale_bits;
        res.emplace_back(tmp);
    }
    return res;
}

template <EvalMode M>
Query::SingleQuery EncryptorImpl<M>::innerEncode(const span<float> &msg, const uint32_t level, const double scale,
                                                 std::optional<const u64> msg_size, std::optional<bool> ntt) {
    // num_limbs = level + 1: level=0 -> 1 limb (Q only), level=1 -> 2 limbs (Q + second-limb).
    // Hard-coded to 2 because every current preset has NumQ <= 2; limb_outs_arr[2]
    // and the single optional plaintext_p capture this assumption. Future presets
    // with NumQ > 2 must refactor plaintext storage to a per-limb container.
    const uint32_t num_limbs = level + 1;
    if (num_limbs > context_->getParam()->getNumQ() || num_limbs > 2) {
        throw evi::InvalidInputError("innerEncode: level + 1 exceeds preset NumQ or hard-coded limb bound (2)");
    }

    Query::SingleQuery res;
    poly plaintext_q{};
    std::optional<poly> plaintext_p;
    if (level) {
        poly tmp{};
        plaintext_p = tmp;
    }

    // Build limb_outs array of size num_limbs for the variable-length encode API.
    u64 *limb_outs_arr[2] = {plaintext_q.data(), level ? plaintext_p.value().data() : nullptr};
    u64 num_iter = msg_size.value_or(DEGREE);
    encodeCoeffs<u64>(msg.data(), limb_outs_arr, num_iter, scale, *context_->getParam(), num_limbs);

    if (ntt.value_or(true)) {
        if (msg_size.has_value()) {
            context_->nttModQMini(plaintext_q, msg_size.value());
            if (level) {
                context_->nttModPMini(plaintext_p.value(), msg_size.value());
            }
        } else {
            context_->nttModQ(plaintext_q);
            if (level) {
                context_->nttModP(plaintext_p.value());
            }
        }

        // Normalize NTT outputs to [0, p) to avoid lazy ranges (up to 4p).
        // For all presets (including IP0 with NumQ=2), deb-flat[1] = PRIMES_Q[1].
        const u64 reduce_count = DEGREE;
        for (uint32_t r = 0; r < num_limbs; ++r) {
            const u64 mod_r = context_->getParam()->getQ(r);
            const u64 two_mod_r = context_->getParam()->getTwoPrimeQ(r);
            u64 *rail_buf = (r == 0) ? plaintext_q.data() : plaintext_p.value().data();
            for (u64 i = 0; i < reduce_count; ++i) {
                reduceModFactor<4, 1>(mod_r, two_mod_r, rail_buf[i]);
            }
        }
    }
    if (level) {
        res = std::make_shared<SingleBlock<DataType::PLAIN>>(plaintext_q, plaintext_p.value());
    } else {
        res = std::make_shared<SingleBlock<DataType::PLAIN>>(plaintext_q);
    }
    setPrimeBits(*res, context_->getParam());
    return res;
}

template class EncryptorImpl<EvalMode::FLAT>;
template class EncryptorImpl<EvalMode::RMP>;
template class EncryptorImpl<EvalMode::RMS>;
template class EncryptorImpl<EvalMode::MS>;
template class EncryptorImpl<EvalMode::MM>;
template class EncryptorImpl<EvalMode::MMS>;
template class EncryptorImpl<EvalMode::MM32>;
template class EncryptorImpl<EvalMode::MMS32>;

Encryptor makeEncryptor(const Context &context, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, seed));
    case EvalMode::SINGLE:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::SINGLE>>(context, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMP>>(context, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMS>>(context, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MS>>(context, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM>>(context, seed));
    case EvalMode::MMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS>>(context, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM32>>(context, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS32>>(context, seed));
    default:
        throw NotSupportedError("invalid mode");
    }
}
Encryptor makeEncryptor(const Context &context, const KeyPack &keypack, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, keypack, seed));
    case EvalMode::SINGLE:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::SINGLE>>(context, keypack, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMP>>(context, keypack, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMS>>(context, keypack, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MS>>(context, keypack, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM>>(context, keypack, seed));
    case EvalMode::MMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS>>(context, keypack, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM32>>(context, keypack, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS32>>(context, keypack, seed));
    default:
        throw NotSupportedError("invalid mode");
    }
}
Encryptor makeEncryptor(const Context &context, const std::string &path, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, path, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMP>>(context, path, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMS>>(context, path, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MS>>(context, path, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM>>(context, path, seed));
    case EvalMode::MMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS>>(context, path, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM32>>(context, path, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS32>>(context, path, seed));
    default:
        throw NotSupportedError("invalid mode");
    }
}
Encryptor makeEncryptor(const Context &context, std::istream &in, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, in, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMP>>(context, in, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::RMS>>(context, in, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MS>>(context, in, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM>>(context, in, seed));
    case EvalMode::MMS:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS>>(context, in, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MM32>>(context, in, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::MMS32>>(context, in, seed));
    default:
        throw NotSupportedError("invalid mode");
    }
}

} // namespace detail
} // namespace evi
