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
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Profiler.hpp"
#include "utils/Sampler.hpp"
#include "utils/Utils.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>

// deb header
#include <deb/SecretKeyGenerator.hpp>
#include <deb/Serialize.hpp>

namespace evi {
namespace detail {

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed),
      deb_encryptor_(utils::getDebPreset(context), utils::convertDebSeed(seed)),
      deb_enc_key_(utils::getDebContext(context), deb::SWK_ENC) {}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const KeyPack &keypack,
                                const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed),
      deb_encryptor_(utils::getDebPreset(context), utils::convertDebSeed(seed)),
      deb_enc_key_(utils::getDebContext(context), deb::SWK_ENC) {
    loadEncKey(keypack);
}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, const std::string &dir_path,
                                const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed),
      deb_encryptor_(utils::getDebPreset(context), utils::convertDebSeed(seed)),
      deb_enc_key_(utils::getDebContext(context), deb::SWK_ENC) {
    loadEncKey(dir_path);
}

template <EvalMode M>
EncryptorImpl<M>::EncryptorImpl(const Context &context, std::istream &in, const std::optional<std::vector<u8>> &seed)
    : context_(context), sampler_(context, seed),
      deb_encryptor_(utils::getDebPreset(context), utils::convertDebSeed(seed)),
      deb_enc_key_(utils::getDebContext(context), deb::SWK_ENC) {
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
    // utils::syncDebSwkKeyToFixedKey(context_, deb_enc_key_, encKey);
    char preset_buf[4];
    in.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    in.read(preset_buf, sizeof(preset_buf));
    in.read(reinterpret_cast<char *>(encKey_->getPolyData(1, 0)), U64_DEGREE);
    in.read(reinterpret_cast<char *>(encKey_->getPolyData(1, 1)), U64_DEGREE);
    in.read(reinterpret_cast<char *>(encKey_->getPolyData(0, 0)), U64_DEGREE);
    in.read(reinterpret_cast<char *>(encKey_->getPolyData(0, 1)), U64_DEGREE);
    utils::syncFixedKeyToDebSwkKey(context_, encKey_, deb_enc_key_);
    enc_loaded_ = true;
}

template <EvalMode M>
void EncryptorImpl<M>::loadEncKey(const KeyPack &kp) {
    auto keypack = std::dynamic_pointer_cast<KeyPackData>(kp);
    if (!keypack) {
        throw std::logic_error("EncryptorImpl::loadEncKey: KeyPack is not KeyPackData");
    }
    enc_loaded_ = keypack->enc_loaded_;
    encKey_ = keypack->enckey;
    deb_enc_key_ = keypack->deb_enc_key;
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
                                const bool level, std::optional<float> scale) {
    loadEncKey(enckey_path);
    return encrypt(msg, type, level, scale);
}

template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type,
                                const bool level, std::optional<float> scale) {
    loadEncKey(enckey_stream);
    return encrypt(msg, type, level, scale);
}

template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type, const bool level,
                                std::optional<float> scale) {
    loadEncKey(keypack);
    return encrypt(msg, type, level, scale);
}

// encrypt using secret key
template <EvalMode M>
Query EncryptorImpl<M>::encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type, const bool level,
                                std::optional<float> scale) {
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
    Query::SingleQuery s = innerEncrypt(tmp_msg, level, delta, seckey);
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
                                const bool level, std::optional<float> scale) {
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

            u64 value_q = reduceBarrett(context_->getParam()->getPrimeQ(), context_->getParam()->getTwoPrimeQ(),
                                        context_->getParam()->getTwoTo64Q(), context_->getParam()->getTwoTo64ShoupQ(),
                                        context_->getParam()->getBarrRatioQ(), static_cast<u128>(temp));
            ctxt_b_q[i] += (is_positive ? value_q : (context_->getParam()->getPrimeQ() - value_q));
            if (ctxt_b_q[i] >= context_->getParam()->getPrimeQ()) {
                ctxt_b_q[i] -= context_->getParam()->getPrimeQ();
            }
        }

        context_->nttModQ(ctxt_b_q);
        context_->madModQ(ctxt_a_q, seckey[j]->sec_key_q_, ctxt_b_q);
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
Query EncryptorImpl<M>::encrypt(const span<float> msg, const EncodeType type, const bool level,
                                std::optional<float> scale) {
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

        auto s = innerEncrypt(tmp_msg, level, delta);
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
            auto tmp = innerEncrypt(tmp_msg, level, delta);
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
                                             const EncodeType type, const bool level, std::optional<float> scale) {
    loadEncKey(keypack);
    if constexpr (CHECK_MM(M)) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                                             const EncodeType type, const bool level, std::optional<float> scale) {
    loadEncKey(enckey_path);
    if (context_->getEvalMode() == EvalMode::MM) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                                             const EncodeType type, const bool level, std::optional<float> scale) {
    loadEncKey(enckey_stream);
    if (context_->getEvalMode() == EvalMode::MM) {
        return encryptMM(msg, type, level, scale);
    } else {
        return encrypt(msg, type, level, scale);
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encrypt(const std::vector<std::vector<float>> &msg, const EncodeType type,
                                             const bool level, std::optional<float> scale) {
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

                Query::SingleQuery tmp = innerEncrypt(inner_msg, level, delta);
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

                    Query::SingleQuery tmp = innerEncrypt(inner_msg, level, delta);
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
            res.emplace_back(encrypt(evi::span<float>(item), type, level, scale));
        }
        return res;
    } else {
        throw evi::NotSupportedError("Batch encryption is not supported for this evaluation mode");
    }
}

template <EvalMode M>
std::vector<Query> EncryptorImpl<M>::encryptMM(const std::vector<std::vector<float>> &msg, const EncodeType type,
                                               const bool level, std::optional<float> scale) {
    if (!msg.size()) {
        throw evi::EncryptionError("EncryptorImpl<M>::encryptMM Nothing to encrypt! Input message must has its size");
    }
    if constexpr (!CHECK_MM(M)) {
        throw evi::NotSupportedError("Batch encryption is only supported for MM mode");
    }

    double delta = scale.value_or(std::pow(2.0, context_->getParam()->getDBScaleFactor()));

    int rows = msg[0].size();
    int cols = DEGREE;
    int batch = (msg.size() + DEGREE - 1) / DEGREE;

    std::vector<Query> queries;
    queries.reserve(batch);

    for (int b = 0; b < batch; b++) {
        const size_t col_offset = static_cast<size_t>(b) * static_cast<size_t>(cols);
        const size_t remaining_cols = col_offset < msg.size() ? (msg.size() - col_offset) : 0;
        const u32 col_base = static_cast<u32>(std::min(static_cast<size_t>(cols), remaining_cols));

        Query q;
        q.reserve(rows);
        for (u64 i = 0; i < static_cast<u64>(rows); ++i) {

            std::array<float, DEGREE> coeff_msg{};
            for (u64 j = 0; j < static_cast<u64>(col_base); ++j) {
                coeff_msg[j] = static_cast<float>(msg[col_offset + j][i]);
            }
            Query::SingleQuery tmp = innerEncrypt(coeff_msg, level, delta, std::nullopt, /*is_ntt*/ false);
            tmp->n = col_base;
            tmp->dim = static_cast<u64>(rows);
            tmp->show_dim = static_cast<u64>(rows);
            tmp->degree = DEGREE;
            tmp->encode_type = type;
            q.push_back(tmp);
        }
        queries.emplace_back(std::move(q));
    }
    return queries;
}

template <EvalMode M>
Query::SingleQuery EncryptorImpl<M>::innerEncrypt(const span<float> &msg, const bool level, const double scale,
                                                  std::optional<const SecretKey> seckey, std::optional<bool> ntt) {
    poly ctxt_a_q, ctxt_b_q;
    poly ctxt_a_p, ctxt_b_p;
    deb::Ciphertext deb_ctxt =
        level ? utils::convertPointerToDebCipher(context_, ctxt_a_q.data(), ctxt_b_q.data(), ctxt_a_p.data(),
                                                 ctxt_b_p.data())
              : utils::convertPointerToDebCipher(context_, ctxt_a_q.data(), ctxt_b_q.data(), nullptr, nullptr);

    // convert message
    deb::CoeffMessage deb_msg(DEGREE);
    for (size_t i = 0; i < DEGREE; ++i) {
        if (i < msg.size()) {
            deb_msg[i] = static_cast<double>(msg[i]);
        } else {
            deb_msg[i] = 0.0;
        }
    }

    // encrypt with deb_encryptor
    bool ntt_val = ntt.value_or(true);
    if (seckey.has_value()) {
        deb_encryptor_.encrypt(deb_msg, (*seckey)->deb_sk_, deb_ctxt,
                               deb::EncryptOptions().Scale(scale).Level(level).NttOut(ntt_val));
    } else {
        deb_encryptor_.encrypt(deb_msg, deb_enc_key_, deb_ctxt,
                               deb::EncryptOptions().Scale(scale).Level(level).NttOut(ntt_val));
    }

    if (level) {
        return std::make_shared<SingleBlock<DataType::CIPHER>>(ctxt_a_q, ctxt_a_p, ctxt_b_q, ctxt_b_p);
    } else {
        return std::make_shared<SingleBlock<DataType::CIPHER>>(ctxt_a_q, ctxt_b_q);
    }
}

/**
 * ===========================
 *           Encode
 * ===========================
 */

template <EvalMode M>
Query EncryptorImpl<M>::encode(const std::vector<std::vector<float>> &msg, const EncodeType type, const int level,
                               std::optional<float> scale) {
    Query res;
    res.reserve(msg.size());
    for (const auto &row : msg) {
        Query partial = encode(span<float>(row), type, level, scale);
        res.append(partial);
    }
    return res;
}

template <EvalMode M>
Query EncryptorImpl<M>::encode(const span<float> msg, const EncodeType type, const bool level,
                               std::optional<float> scale) {
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }
    u64 scale_bits;
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
        auto tmp = innerEncode(msg, level, delta, msg.size(), /* ntt */ false);
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
            auto tmp = innerEncode(tmp_msg, level, delta, tmp_rank);
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
                    reduceBarrett(context_->getParam()->getPrimeQ(), context_->getParam()->getTwoPrimeQ(),
                                  context_->getParam()->getTwoTo64Q(), context_->getParam()->getTwoTo64ShoupQ(),
                                  context_->getParam()->getBarrRatioQ(), static_cast<u128>(temp));
                plaintext_q[i] = is_positive ? value_q : (context_->getParam()->getPrimeQ() - value_q);
            }
            context_->nttModQMini(plaintext_q, tmp_rank);
            polyvec128 tmp(plaintext_q.begin(), plaintext_q.end());
            res.emplace_back(std::make_shared<SerializedSingleQuery<DataType::PLAIN>>(tmp));
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

        auto tmp = innerEncode(tmp_msg, level, delta);
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
Query::SingleQuery EncryptorImpl<M>::innerEncode(const span<float> &msg, const bool level, const double scale,
                                                 std::optional<const u64> msg_size, std::optional<bool> ntt) {
    Query::SingleQuery res;
    poly plaintext_q{};
    std::optional<poly> plaintext_p;
    if (level) {
        poly tmp{};
        plaintext_p = tmp;
    }

    u64 num_iter = msg_size.value_or(DEGREE);
    for (u64 i = 0; i < num_iter; ++i) {
        i128 temp = static_cast<i128>(msg[i] * scale + signBiasDouble(msg[i]));
        i64 is_positive = temp >= 0;
        temp = absI128(temp);

        u64 value_q = reduceBarrett(context_->getParam()->getPrimeQ(), context_->getParam()->getTwoPrimeQ(),
                                    context_->getParam()->getTwoTo64Q(), context_->getParam()->getTwoTo64ShoupQ(),
                                    context_->getParam()->getBarrRatioQ(), static_cast<u128>(temp));
        plaintext_q[i] = selectIfCondU64(is_positive, value_q, context_->getParam()->getPrimeQ() - value_q);

        if (level) {
            u64 value_p = reduceBarrett(context_->getParam()->getPrimeP(), context_->getParam()->getTwoPrimeP(),
                                        context_->getParam()->getTwoTo64P(), context_->getParam()->getTwoTo64ShoupP(),
                                        context_->getParam()->getBarrRatioP(), static_cast<u128>(temp));
            plaintext_p.value()[i] = selectIfCondU64(is_positive, value_p, context_->getParam()->getPrimeP() - value_p);
        }
    }

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
    }
    if (level) {
        res = std::make_shared<SingleBlock<DataType::PLAIN>>(plaintext_q, plaintext_p.value());
    } else {
        res = std::make_shared<SingleBlock<DataType::PLAIN>>(plaintext_q);
    }
    return res;
}

/**
 * ===========================
 *           Blob
 * ===========================
 */

template <EvalMode M>
Blob EncryptorImpl<M>::encrypt(const span<float> msg, const int num_items, const bool level,
                               std::optional<float> scale) {
    if (!enc_loaded_) {
        throw evi::EncryptionError("Encryption key is not loaded for encryption");
    }
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }
    if (!isPowerOfTwo(msg.size() / num_items)) {
        throw evi::EncryptionError("Invalid dimension for bulk encryption! Input message size must be power of two");
    }

    Blob res;
    if constexpr (!CHECK_RMP(M)) {
        polyvec a_q, b_q;
        std::optional<polyvec> a_p, b_p;
        if (level) {
            polyvec tmp_a, tmp_b;
            a_p = tmp_a;
            b_p = tmp_b;
        }

        for (u64 offset = 0; offset < msg.size(); offset += DEGREE) {
            auto tmp_span = msg.subspan(offset, DEGREE);
            auto tmp = encrypt(tmp_span, EncodeType::ITEM, level, scale);
            a_q.insert(a_q.end(), tmp[0]->getPoly(1, 0).begin(), tmp[0]->getPoly(1, 0).end());
            b_q.insert(b_q.end(), tmp[0]->getPoly(0, 0).begin(), tmp[0]->getPoly(0, 0).end());
            if (level) {
                a_p.value().insert(a_p.value().end(), tmp[0]->getPoly(1, 1).begin(), tmp[0]->getPoly(1, 1).end());
                b_p.value().insert(b_p.value().end(), tmp[0]->getPoly(0, 1).begin(), tmp[0]->getPoly(0, 1).end());
            }
        }

        if (level) {
            auto tmp = std::make_shared<Matrix<DataType::CIPHER>>(a_q, a_p.value(), b_q, b_p.value());
            tmp->dim = msg.size() / num_items;
            tmp->n = num_items;
            tmp->degree = DEGREE;

            res.emplace_back(tmp);

        } else {
            auto tmp = std::make_shared<Matrix<DataType::CIPHER>>(a_q, b_q);
            tmp->dim = msg.size() / num_items;
            tmp->n = num_items;
            tmp->degree = DEGREE;

            res.emplace_back(tmp);
        }
    } else {
        uint32_t tmp_dim = msg.size() / num_items;
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
        uint32_t num_item_per_ctxt = DEGREE / tmp_rank;
        uint32_t num_ctxt = (num_items + num_item_per_ctxt - 1) / num_item_per_ctxt;

        for (u32 db_idx = 0; db_idx < num_db; ++db_idx) {
            polyvec a_q, b_q;
            std::optional<polyvec> a_p, b_p;
            if (level) {
                polyvec tmp_a, tmp_b;
                a_p = tmp_a;
                b_p = tmp_b;
            }

            for (u32 ctxt_idx = 0; ctxt_idx < num_ctxt; ++ctxt_idx) {

                auto num_item_per_ctxt = DEGREE / tmp_rank;

                std::array<float, DEGREE> inner_msg{};
                for (int i = 0; i < num_item_per_ctxt; i++) {
                    auto copy_size = std::min(int32_t(msg.size()) - int32_t(num_db * DEGREE * ctxt_idx +
                                                                            db_idx * tmp_rank + i * num_db * tmp_rank),
                                              int32_t(tmp_rank));
                    if (copy_size < 0) {
                        copy_size = 0;
                    }
                    std::copy_n(msg.begin() + num_db * DEGREE * ctxt_idx + db_idx * tmp_rank + i * num_db * tmp_rank,
                                copy_size, inner_msg.begin() + i * tmp_rank);
                }

                double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));
                Query::SingleQuery tmp = innerEncrypt(inner_msg, level, delta);
                tmp->n = 1;
                tmp->dim = tmp_rank;
                tmp->degree = DEGREE;
                a_q.insert(a_q.end(), tmp->getPoly(1, 0).begin(), tmp->getPoly(1, 0).end());
                b_q.insert(b_q.end(), tmp->getPoly(0, 0).begin(), tmp->getPoly(0, 0).end());
                if (level) {
                    a_p.value().insert(a_p.value().end(), tmp->getPoly(1, 1).begin(), tmp->getPoly(1, 1).end());
                    b_p.value().insert(b_p.value().end(), tmp->getPoly(0, 1).begin(), tmp->getPoly(0, 1).end());
                }
            }

            if (level) {
                res.push_back(std::make_shared<Matrix<DataType::CIPHER>>(a_q, a_p.value(), b_q, b_p.value()));

            } else {
                res.push_back(std::make_shared<Matrix<DataType::CIPHER>>(a_q, b_q));
            }

            res[db_idx]->n = num_items;
            res[db_idx]->dim = tmp_rank;
            res[db_idx]->degree = DEGREE;
        }
    }

    return res;
}

template <EvalMode M>
Blob EncryptorImpl<M>::encode(const span<float> msg, const int num_items, const bool level,
                              std::optional<float> scale) {
    if (!msg.size()) {
        throw evi::EncryptionError("Invalid data type for encryption! Input message must has its size");
    }
    if (!isPowerOfTwo(msg.size() / num_items)) {
        throw evi::EncryptionError("Invalid dimension for bulk encryption! Input message size must be power of two");
    }

    Blob res;
    if constexpr (!CHECK_RMP(M)) {
        polyvec q;
        std::optional<polyvec> p;
        if (level) {
            polyvec tmp_p;
            p = tmp_p;
        }

        for (u64 offset = 0; offset < msg.size(); offset += DEGREE) {
            auto tmp_span = msg.subspan(offset, DEGREE);
            auto tmp = encode(tmp_span, EncodeType::ITEM, level, scale);
            q.insert(q.end(), tmp[0]->getPoly(0, 0).begin(), tmp[0]->getPoly(0, 0).end());
            if (level) {
                p.value().insert(p.value().end(), tmp[0]->getPoly(0, 1).begin(), tmp[0]->getPoly(0, 1).end());
            }
        }

        if (level) {
            res.emplace_back(std::make_shared<Matrix<DataType::PLAIN>>(q, p.value()));
        } else {
            res.emplace_back(std::make_shared<Matrix<DataType::PLAIN>>(q));
        }

        res[0]->dim = msg.size() / num_items;
        res[0]->n = num_items;
        res[0]->degree = DEGREE;
    } else {
        uint32_t tmp_dim = msg.size() / num_items;
        uint32_t tmp_rank = getInnerRank(tmp_dim);
        uint32_t num_db = (tmp_dim + tmp_rank - 1) / tmp_rank;
        uint32_t num_item_per_ctxt = DEGREE / tmp_rank;
        uint32_t num_ctxt = (num_items + num_item_per_ctxt - 1) / num_item_per_ctxt;

        for (u32 db_idx = 0; db_idx < num_db; ++db_idx) {
            polyvec q;
            std::optional<polyvec> p;
            if (level) {
                polyvec tmp_p;
                p = tmp_p;
            }

            for (u32 ctxt_idx = 0; ctxt_idx < num_ctxt; ++ctxt_idx) {
                auto num_item_per_ctxt = DEGREE / tmp_rank;

                std::array<float, DEGREE> inner_msg{};
                for (int i = 0; i < num_item_per_ctxt; i++) {
                    auto copy_size = std::min(int32_t(msg.size()) - int32_t(num_db * DEGREE * ctxt_idx +
                                                                            db_idx * tmp_rank + i * num_db * tmp_rank),
                                              int32_t(tmp_rank));
                    if (copy_size < 0) {
                        copy_size = 0;
                    }
                    std::copy_n(msg.begin() + num_db * DEGREE * ctxt_idx + db_idx * tmp_rank + i * num_db * tmp_rank,
                                copy_size, inner_msg.begin() + i * tmp_rank);
                }

                double delta = scale.value_or(std::pow(2.0, context_->getParam()->getScaleFactor()));
                Query::SingleQuery tmp = innerEncode(inner_msg, level, delta);
                tmp->n = 1;
                tmp->dim = tmp_rank;
                tmp->degree = DEGREE;
                q.insert(q.end(), tmp->getPoly(0, 0).begin(), tmp->getPoly(0, 0).end());
                if (level) {
                    p.value().insert(p.value().end(), tmp->getPoly(0, 1).begin(), tmp->getPoly(0, 1).end());
                }
            }

            if (level) {
                res.push_back(std::make_shared<Matrix<DataType::PLAIN>>(q, p.value()));

            } else {
                res.push_back(std::make_shared<Matrix<DataType::PLAIN>>(q));
            }

            res[db_idx]->n = num_items;
            res[db_idx]->dim = tmp_rank;
            res[db_idx]->degree = DEGREE;
        }
    }
    return res;
}

template class EncryptorImpl<EvalMode::FLAT>;
template class EncryptorImpl<EvalMode::RMP>;
template class EncryptorImpl<EvalMode::RMS>;
template class EncryptorImpl<EvalMode::MS>;
template class EncryptorImpl<EvalMode::MM>;

Encryptor makeEncryptor(const Context &context, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, seed));
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
    default:
        throw NotSupportedError("invalid mode");
    }
}
Encryptor makeEncryptor(const Context &context, const KeyPack &keypack, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<EncryptorInterface>(
            std::make_shared<EncryptorImpl<EvalMode::FLAT>>(context, keypack, seed));
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
    default:
        throw NotSupportedError("invalid mode");
    }
}

} // namespace detail
} // namespace evi
