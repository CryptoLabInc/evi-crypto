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

#include <algorithm>
#include <iostream>
#include <memory>

#include "EVI/Enums.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/DecryptorImpl.hpp"
#include "EVI/impl/Parameter.hpp"
#include "nlohmann/json.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include <cmath>
#include <deb/SecretKeyGenerator.hpp>
#include <fstream>

using json = nlohmann::json;

namespace evi {
namespace detail {

DecryptorInterface::DecryptorInterface(const Context &context)
    : context_(context), deb_dec_(utils::getDebPreset(context)) {}

Message DecryptorInterface::decrypt(const int idx, const Query &ctxt, const SecretKey &key,
                                    std::optional<double> scale) {
    throw evi::NotSupportedError("decrypt(idx, Query, SecretKey) is only available in EvalMode::RMP");
}

DecryptorFLAT::DecryptorFLAT(const Context &context) : DecryptorInterface(context) {}
DecryptorRMP::DecryptorRMP(const Context &context) : DecryptorFLAT(context) {}
DecryptorMM::DecryptorMM(const Context &context) : DecryptorInterface(context) {}

/**
 * DecryptorFLAT
 */
Message DecryptorFLAT::decrypt(const SearchResult ip_res, std::istream &key_stream, bool is_score,
                               std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorFLAT::decrypt(const SearchResult ip_res, const std::string &key_path, bool is_score,
                               std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorFLAT::decrypt(const SearchResult ip_res, const SecretKey &key, bool is_score,
                               std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorImpl!");
    }
    SecretKeyAccessScope key_access(key);

    auto &ctxt = ip_res->ip_data;
    if (!ctxt->getPoly(0, 0).size()) {
        throw evi::DecryptionError("Invalid Ciphertext type is given");
    }

    Message res;
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor() * (is_score ? 2 : 1));
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage buf(DEGREE);
    for (u64 offset = 0; offset < ctxt->getPoly(0, 0).size(); offset += DEGREE) {
        if (!ctxt->getLevel()) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(context_, ctxt->getPoly(1, 0).data() + offset,
                                                                        ctxt->getPoly(0, 0).data() + offset);
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), buf, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(
                context_, ctxt->getPoly(1, 0).data() + offset, ctxt->getPoly(0, 0).data() + offset,
                ctxt->getPoly(1, 1).data() + offset, ctxt->getPoly(0, 1).data() + offset);
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), buf, scale_factor);
        }

        if (is_score) {
            const u64 items_per_ctxt = context_->getItemsPerCtxt();
            const u64 pad_rank = context_->getPadRank();
            const u64 item_count = ctxt->n ? ctxt->n : items_per_ctxt;
            float tmp;
            if (context_->getEvalMode() == EvalMode::SINGLE) {
                res.push_back(buf[pad_rank - 1]);
            } else {
                for (u64 j = 0; j < ctxt->n; ++j) {
                    tmp = buf[(j % context_->getItemsPerCtxt()) * context_->getPadRank() +
                              j / context_->getItemsPerCtxt()];
                    res.push_back(tmp);
                }
            }
        } else {
            for (u64 j = 0; j < DEGREE; ++j) {
                res.push_back(buf[j]);
            }
        }
    }
    return res;
}

Message DecryptorFLAT::decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ctxt, key, scale);
}

Message DecryptorFLAT::decrypt(const Query &ctxt, const std::string &key_path, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ctxt, key, scale);
}

Message DecryptorFLAT::decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorImpl!");
    }
    SecretKeyAccessScope key_access(key);

    Message res(DEGREE, 0.0f);
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor());
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    for (int i = 0; i < ctxt.size(); i++) {
        if (ctxt[i]->getLevel() == 0) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(),
                                                                        ctxt[i]->getPoly(0, 0).data());
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt =
                utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(), ctxt[i]->getPoly(0, 0).data(),
                                                 ctxt[i]->getPoly(1, 1).data(), ctxt[i]->getPoly(0, 1).data());
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        }

        u64 size = ctxt[i]->dim;
        u64 ctxt_dim = isPowerOfTwo(size) ? size : nextPowerOfTwo(size);

        u64 pad_offset = ctxt_dim - ((i + 1 == ctxt.size()) ? (ctxt[i]->show_dim % ctxt[i]->dim) : 0);
        if (ctxt[i]->encode_type == EncodeType::ITEM) {
            // std::copy_n(tmp_msg.begin(), pad_offset, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[j]);
            }
        } else {
            // std::reverse_copy(tmp_msg.begin() + size - pad_offset, tmp_msg.begin() + size, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[size - 1 - j]);
            }
        }
    }

    return res;
}

/**
 * DecryptorRMP
 */
Message DecryptorRMP::decrypt(const int idx, const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    if (!key->sec_loaded_) {
        throw evi::DecryptionError("Secret key is not loaded to DecryptorInterface!");
    }
    SecretKeyAccessScope key_access(key);
    Message res(DEGREE, 0.0f);
    double scale_factor = std::pow(2, context_->getParam()->getScaleFactor());
    if (scale.has_value()) {
        scale_factor = scale.value();
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    for (int i = 0; i < ctxt.size(); i++) {
        if (ctxt[i]->getLevel() == 0) {
            deb::Ciphertext deb_ctxt = utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(),
                                                                        ctxt[i]->getPoly(0, 0).data());
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        } else {
            deb::Ciphertext deb_ctxt =
                utils::convertPointerToDebCipher(context_, ctxt[i]->getPoly(1, 0).data(), ctxt[i]->getPoly(0, 0).data(),
                                                 ctxt[i]->getPoly(1, 1).data(), ctxt[i]->getPoly(0, 1).data());
            deb_dec_.decrypt(deb_ctxt, key->getDebSecKey(), tmp_msg, scale_factor);
        }

        u64 size = ctxt[i]->dim;
        u64 ctxt_dim = isPowerOfTwo(size) ? size : nextPowerOfTwo(size);

        u64 pad_offset = ctxt_dim - ((i + 1 == ctxt.size()) ? (ctxt[i]->show_dim % ctxt[i]->dim) : 0);
        if (ctxt[i]->encode_type == EncodeType::ITEM) {
            // std::copy_n(tmp_msg.begin(), pad_offset, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[j + idx * size]);
            }
        } else {
            // std::reverse_copy(tmp_msg.begin() + size - pad_offset, tmp_msg.begin() + size, res.begin() + size * i);
            for (u64 j = 0; j < pad_offset; ++j) {
                res[size * i + j] = static_cast<float>(tmp_msg[size - 1 - j]);
            }
        }
    }

    return res;
}

/**
 * DecryptorMM
 */
Message DecryptorMM::decrypt(const SearchResult ip_res, std::istream &key_stream, bool is_score,
                             std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorMM::decrypt(const SearchResult ip_res, const std::string &key_path, bool is_score,
                             std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ip_res, key, is_score, scale);
}

Message DecryptorMM::decrypt(const SearchResult ctxts, const evi::detail::SecretKey &seckey, bool is_score,
                             std::optional<double> scale) {
    SecretKeyAccessScope key_access(seckey);

    auto &matrix = ctxts->ip_data;
    if (!matrix->getPoly(0, 0).size()) {
        throw evi::DecryptionError("Invalid Ciphertext type is given");
    }

    const int level = matrix->getLevel();

    // Detect base conversion: IData::preset holds the prime space the
    // ciphertext's coefficients are in (set by compute after base conversion,
    // RUNTIME if no conversion). ctx_preset is the encryption preset —
    // the Decryptor context must always match what was used to encrypt.
    const auto ctx_preset = context_->getParam()->getPreset();
    const auto res_preset = matrix->preset;
    const bool is_base_converted = res_preset != ParameterPreset::RUNTIME && res_preset != ctx_preset;

    // Auto-compute scale bits for the decoded plaintext.
    //
    // Two cases:
    //   1. Rescale-only (or level > 0): use context SCALE_FACTOR (existing path).
    //   2. Base-converted: base conversion multiplies raw values by
    //      Q_target / (Q_ctx * P_ctx) instead of rescaling by P_ctx.
    //      Result scale = DB_SCALE + log2(Q_target / (Q_ctx * P_ctx)) + QUERY_SCALE.
    double delta = 0.0;
    double scale_bits = 0.0;

    if (is_base_converted) {
        const auto res_param = setPreset(res_preset);
        const double q_target = static_cast<double>(res_param->getPrimeQ());
        const double q_ctx = static_cast<double>(context_->getParam()->getPrimeQ());
        const double p_ctx = static_cast<double>(context_->getParam()->getPrimeP());
        const double db_scale = context_->getParam()->getDBScaleFactor();
        const double query_scale = context_->getParam()->getQueryScaleFactor();
        scale_bits = db_scale + std::log2(q_target / (q_ctx * p_ctx)) + query_scale;
    } else if ((ctx_preset == evi::ParameterPreset::IP1 || ctx_preset == evi::ParameterPreset::IP2) && level == 0) {
        scale_bits = context_->getParam()->getScaleFactor();
    } else {
        scale_bits = context_->getParam()->getScaleFactor() * 2;
    }
    delta = scale.value_or(std::pow(2.0, scale_bits));

    // For base-converted results, decrypt with the target preset's deb
    // decryptor so that b + s*a is computed mod the correct modulus.
    std::optional<deb::Decryptor> bc_dec;
    std::optional<deb::SecretKey> bc_sk;
    if (is_base_converted) {
        const auto deb_preset = utils::getDebPreset(res_preset);
        bc_dec.emplace(deb_preset);
        bc_sk.emplace(deb::SecretKeyGenerator::GenSecretKeyFromCoeff(deb_preset, seckey->getDebSecKey().coeffs()));
    }

    const size_t rows = static_cast<size_t>(matrix->dim);
    size_t item_count = ctxts.getTotalItemCount() / DEGREE;
    if (!item_count) {
        item_count = static_cast<size_t>(matrix->n);
    }

    Message msgs(rows * item_count * DEGREE, 0.0f);
    deb::CoeffMessage dmsg(DEGREE);

    u64 *a_lvl0_base = matrix->getPolyData(1, 0);
    u64 *b_lvl0_base = matrix->getPolyData(0, 0);
    u64 *a_lvl1_base = level ? matrix->getPolyData(1, 1) : nullptr;
    u64 *b_lvl1_base = level ? matrix->getPolyData(0, 1) : nullptr;

    for (size_t row = 0; row < rows; ++row) {
        for (size_t item = 0; item < item_count; ++item) {
            const size_t poly_idx = item * rows + row;
            u64 *a_lvl0 = a_lvl0_base + poly_idx * DEGREE;
            u64 *b_lvl0 = b_lvl0_base + poly_idx * DEGREE;
            u64 *a_lvl1 = level ? a_lvl1_base + poly_idx * DEGREE : nullptr;
            u64 *b_lvl1 = level ? b_lvl1_base + poly_idx * DEGREE : nullptr;

            if (is_base_converted) {
                auto deb_ctxt = utils::convertPointerToDebCipherWithPreset(res_preset, a_lvl0, b_lvl0, false);
                bc_dec->decrypt(deb_ctxt, *bc_sk, dmsg, delta);
            } else {
                auto deb_ctxt = utils::convertPointerToDebCipher(context_, a_lvl0, b_lvl0, a_lvl1, b_lvl1, false);
                deb_dec_.decrypt(deb_ctxt, seckey->getDebSecKey(), dmsg, delta);
            }

            float *dst = msgs.data() + (row * item_count + item) * DEGREE;
            for (u64 k = 0; k < DEGREE; ++k) {
                dst[k] = static_cast<float>(dmsg[k]);
            }
        }
    }
    return msgs;
}

Message DecryptorMM::decrypt(const Query &ctxts, std::istream &key_stream, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(context_);
    key->loadSecKey(key_stream);
    return decrypt(ctxts, key, scale);
}

Message DecryptorMM::decrypt(const Query &ctxts, const std::string &key_path, std::optional<double> scale) {
    SecretKey key = std::make_shared<SecretKeyData>(key_path);
    return decrypt(ctxts, key, scale);
}

Message DecryptorMM::decrypt(const Query &ctxts, const SecretKey &seckey, std::optional<double> scale) {
    SecretKeyAccessScope key_access(seckey);
    const u64 rows = static_cast<u64>(ctxts.size());
    if (!rows) {
        throw evi::InvalidInputError("Matrix query is empty");
    }

    const u64 inner_count = static_cast<u64>(ctxts.getInnerItemCount());
    const u64 cols = inner_count ? inner_count : static_cast<u64>(DEGREE);
    const u32 msg_dim = context_->getShowRank();
    Message msgs(cols * msg_dim, 0.0f);

    double delta = 0.0;
    if (scale.has_value()) {
        delta = scale.value();
    } else if (ctxts[0]->encode_type == EncodeType::ITEM) {
        // MM bulk ITEM encryption uses the DB scale for level-1 ciphertexts.
        delta = std::pow(2.0, context_->getParam()->getDBScaleFactor());
    } else {
        delta = std::pow(2.0, context_->getParam()->getScaleFactor());
    }

    deb::CoeffMessage tmp_msg(DEGREE);
    const u64 stride = msg_dim;
    const u64 active_rows = std::min<u64>(rows, stride);
    const u64 active_cols = std::min<u64>(cols, static_cast<u64>(DEGREE));

    for (u64 row = 0; row < active_rows; ++row) {
        const auto &block = ctxts[row];
        if (!block) {
            throw evi::InvalidInputError("Matrix query contains null single block");
        }

        deb::Ciphertext deb_ctxt =
            block->getLevel() == 0
                ? utils::convertPointerToDebCipher(context_, block->getPoly(1, 0).data(), block->getPoly(0, 0).data(),
                                                   nullptr, nullptr, false)
                : utils::convertPointerToDebCipher(context_, block->getPoly(1, 0).data(), block->getPoly(0, 0).data(),
                                                   block->getPoly(1, 1).data(), block->getPoly(0, 1).data(), false);
        deb_dec_.decrypt(deb_ctxt, seckey->getDebSecKey(), tmp_msg, delta);

        for (u64 col = 0; col < active_cols; ++col) {
            msgs[col * stride + row] = static_cast<float>(tmp_msg[col]);
        }
    }
    return msgs;
}

Decryptor makeDecryptor(const Context &context) {
    if (context->getEvalMode() == EvalMode::FLAT) {
        return Decryptor(std::make_shared<DecryptorFLAT>(context));
    } else if (context->getEvalMode() == EvalMode::SINGLE) {
        return Decryptor(std::make_shared<DecryptorFLAT>(context));
    } else if (context->getEvalMode() == EvalMode::RMP) {
        return Decryptor(std::make_shared<DecryptorRMP>(context));
    } else if (context->getEvalMode() == EvalMode::MM || context->getEvalMode() == EvalMode::MMS ||
               context->getEvalMode() == EvalMode::MM32 || context->getEvalMode() == EvalMode::MMS32) {
        return Decryptor(std::make_shared<DecryptorMM>(context));
    } else {
        throw InvalidAccessError("invalid access");
    }
}
} // namespace detail
} // namespace evi
