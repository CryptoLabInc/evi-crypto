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

#include "EVI/impl/KeyGeneratorImpl.hpp"

#include "EVI/Const.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Sampler.hpp"
#include "utils/Utils.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>

// deb header
#include <deb/SecretKeyGenerator.hpp>

using json = nlohmann::json;

namespace evi {
namespace detail {

template <EvalMode M>
KeyGeneratorImpl<M>::KeyGeneratorImpl(const Context &context, KeyPack &pack, const std::optional<std::vector<u8>> &seed)
    : context_(context), deb_keygen_(utils::getDebPreset(context), utils::convertDebSeed(seed)), pack_iface_(pack),
      sampler_(context, seed) {
    pack_ = std::dynamic_pointer_cast<KeyPackData>(pack_iface_);
    if (!pack_) {
        throw std::logic_error("Failed to cast KeyPack");
    }
}

template <EvalMode M>
KeyGeneratorImpl<M>::KeyGeneratorImpl(const Context &context, const std::optional<std::vector<u8>> &seed)
    : context_(context), deb_keygen_(utils::getDebPreset(context), utils::convertDebSeed(seed)),
      sampler_(context, seed) {
    auto data = std::make_shared<KeyPackData>(context_);
    pack_ = data;
    pack_iface_ = std::static_pointer_cast<IKeyPack>(data);
}

template <EvalMode M>
SecretKey KeyGeneratorImpl<M>::genSecKey(std::optional<const int *> coeff) {
    SecretKey seckey = std::make_shared<SecretKeyData>(context_);
    if (coeff) {
        std::copy_n(coeff.value(), DEGREE, seckey->sec_coeff_.data());
    } else {
        sampler_.sampleHWT(seckey->sec_coeff_);
    }
    for (u64 i = 0; i < DEGREE; ++i) {
        seckey->deb_sk_.coeffs()[i] = static_cast<int8_t>(seckey->sec_coeff_[i]);
    }
    seckey->deb_sk_ =
        deb::SecretKeyGenerator::GenSecretKeyFromCoeff(utils::getDebPreset(context_), seckey->deb_sk_.coeffs());
    std::memcpy(seckey->sec_key_q_.data(), seckey->deb_sk_[0][0].data(), detail::U64_DEGREE);
    std::memcpy(seckey->sec_key_p_.data(), seckey->deb_sk_[0][1].data(), detail::U64_DEGREE);
    seckey->sec_loaded_ = true;
    return seckey;
}

template <EvalMode M>
std::vector<SecretKey> KeyGeneratorImpl<M>::genMultiSecKey() {
    std::vector<SecretKey> res;
    res.reserve(context_->getRank());
    for (int i = 0; i < context_->getRank(); i++) {
        res.emplace_back(genSecKey());
    }
    return res;
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    pack_->num_shared_secret = sec_to.size();

    pack_->shared_a_key->setSize(sec_to.size() * sec_to.size() * DEGREE, sec_to.size() * DEGREE);
    // genA
    for (u64 i = 0; i < sec_to.size(); ++i) {
        sampler_.sampleUniformModQ(pack_->shared_a_key->getPolyData(1, 0) + (i * DEGREE));
        sampler_.sampleUniformModP(pack_->shared_a_key->getPolyData(1, 1) + (i * DEGREE));
    }
    // genB
    poly error_poly_q;
    poly error_poly_p;
    poly poly_p{};

    poly_p[0] = context_->getParam()->getPModQ();
    context_->nttModQ(poly_p);

    for (u64 i = 0; i < sec_to.size(); ++i) {
        for (u64 j = 0; j < sec_to.size(); ++j) {
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->shared_a_key->getPolyData(1, 0) + j * DEGREE, sec_to[i]->sec_key_q_,
                               pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
            context_->multModP(pack_->shared_a_key->getPolyData(1, 1) + j * DEGREE, sec_to[i]->sec_key_p_,
                               pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE));
            context_->addModQ(pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE), error_poly_q,
                              pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
            context_->addModP(pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE), error_poly_p,
                              pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE));

            if (i == j) {
                context_->madModQ(sec_from->sec_key_q_, poly_p,
                                  pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
            }
        }
    }

    for (u64 i = 0; i < sec_to.size(); ++i) {
        context_->negateModQ(pack_->shared_a_key->getPolyData(1, 0) + (i * DEGREE));
        context_->negateModP(pack_->shared_a_key->getPolyData(1, 1) + (i * DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genAdditiveSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    // S to s[0] key

    pack_->reverse_switch_key->setSize(sec_to.size() * DEGREE);

    for (int i = 0; i < sec_to.size(); i++) {
        genSwitchingKey(sec_to[i], sec_from->sec_key_q_, pack_->reverse_switch_key->getPolyData(1, 0) + i * DEGREE,
                        pack_->reverse_switch_key->getPolyData(1, 1) + i * DEGREE,
                        pack_->reverse_switch_key->getPolyData(0, 0) + i * DEGREE,
                        pack_->reverse_switch_key->getPolyData(0, 1) + i * DEGREE);
    }

    pack_->num_shared_secret = sec_to.size();
    // genA
    pack_->additive_shared_a_key.resize(sec_to.size());
    for (u64 i = 0; i < sec_to.size(); ++i) {
        int b_size = i == sec_to.size() - 1 ? 0 : 2 * (i + 2) * DEGREE;
        pack_->additive_shared_a_key[i]->setSize(b_size, 2 * DEGREE);

        sampler_.sampleUniformModQ(pack_->additive_shared_a_key[i]->getPolyData(1, 0));
        sampler_.sampleUniformModP(pack_->additive_shared_a_key[i]->getPolyData(1, 1));
        // sampler_.sampleUniformModP(pack_->additive_shared_a_key_a_p_[i].data());

        sampler_.sampleUniformModQ(pack_->additive_shared_a_key[i]->getPolyData(1, 0) + DEGREE);
        sampler_.sampleUniformModP(pack_->additive_shared_a_key[i]->getPolyData(1, 1) + DEGREE);
    }

    // genB

    poly error_poly_q;
    poly error_poly_p;
    poly poly_p{};

    poly_p[0] = context_->getParam()->getPModQ();
    context_->nttModQ(poly_p);

    for (u64 k = 0; k < sec_to.size() - 1; ++k) {
        for (u64 i = 0; i <= k; ++i) {
            // add secret key encryption.
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[i]->sec_key_q_,
                               pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));
            context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[i]->sec_key_p_,
                               pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE));
            context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE), error_poly_q,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));
            context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE), error_poly_p,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE));

            context_->madModQ(sec_to[i]->sec_key_q_, poly_p,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));

            // zero encryption.
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[i]->sec_key_q_,
                               pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 2 + i) * DEGREE));
            context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[i]->sec_key_p_,
                               pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 2 + i) * DEGREE));
            context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 2 + i) * DEGREE), error_poly_q,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 2 + i) * DEGREE));
            context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 2 + i) * DEGREE), error_poly_p,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 2 + i) * DEGREE));
        }

        // zero encryption.
        sampler_.sampleGaussian(error_poly_q, error_poly_p);
        context_->nttModQ(error_poly_q);
        context_->nttModP(error_poly_p);

        context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[k + 1]->sec_key_q_,
                           pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE));
        context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[k + 1]->sec_key_p_,
                           pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE));
        context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE), error_poly_q,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE));
        context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE), error_poly_p,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE));

        // seckey encryption.
        sampler_.sampleGaussian(error_poly_q, error_poly_p);
        context_->nttModQ(error_poly_q);
        context_->nttModP(error_poly_p);

        context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[k + 1]->sec_key_q_,
                           pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE));
        context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[k + 1]->sec_key_p_,
                           pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE));
        context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE), error_poly_q,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE));
        context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE), error_poly_p,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE));
        context_->madModQ(sec_to[k + 1]->sec_key_q_, poly_p,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE));
    }

    for (u64 i = 0; i < sec_to.size(); ++i) {
        context_->negateModQ(pack_->additive_shared_a_key[i]->getPolyData(1, 0));
        context_->negateModQ(pack_->additive_shared_a_key[i]->getPolyData(1, 0) + DEGREE);
        context_->negateModP(pack_->additive_shared_a_key[i]->getPolyData(1, 1));
        context_->negateModP(pack_->additive_shared_a_key[i]->getPolyData(1, 1) + DEGREE);
    }

    //
}
//
template <EvalMode M>
void KeyGeneratorImpl<M>::genEncKey(const SecretKey &sec_key) {
    utils::syncFixedKeyToDebSwkKey(context_, pack_->enckey, pack_->deb_enc_key);
    deb_keygen_.genEncKeyInplace(pack_->deb_enc_key, sec_key->deb_sk_);
    pack_->enc_loaded_ = true;
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genRelinKey(const SecretKey &sec_key) {
    utils::syncFixedKeyToDebSwkKey(context_, pack_->relin_key, pack_->deb_relin_key);
    deb_keygen_.genMultKeyInplace(pack_->deb_relin_key, sec_key->deb_sk_);
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    pack_->shared_a_mod_pack_loaded_ = true;
    pack_->shared_a_mod_pack_key->setSize(sec_to.size() * DEGREE);
    for (u64 k = 0; k < sec_to.size(); ++k) { // num key
        s_poly from_coeff{};
        for (u64 j = 0; j < context_->getItemsPerCtxt(); ++j) {
            for (u64 i = 0; i < context_->getPadRank(); ++i) {
                from_coeff[context_->getPadRank() * j + i] =
                    sec_to[i]
                        ->sec_coeff_[(j * context_->getPadRank() + context_->getPadRank() - 1 - k + DEGREE) % DEGREE];
            }
        }

        poly sk_tmp;
        sampler_.embedding(from_coeff, sk_tmp, context_->getParam()->getPrimeQ());
        context_->nttModQ(sk_tmp);
        genSwitchingKey(sec_from, sk_tmp, pack_->shared_a_mod_pack_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    pack_->switch_key->setSize(sec_to.size() * DEGREE);
    for (u64 k = 0; k < sec_to.size(); ++k) { // num key
        genSwitchingKey(sec_from, sec_to[k]->sec_key_q_, pack_->switch_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genCCSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    pack_->cc_shared_a_mod_pack_loaded_ = true;
    pack_->cc_shared_a_mod_pack_key->setSize(sec_to.size() * DEGREE);
    std::vector<s_poly> multi_sec_key(sec_to.size(), {0});
    for (u64 k = 0; k < sec_to.size(); ++k) { // num key // To prevent precision loss..
        for (u64 j = 0; j < DEGREE; j++) {
            for (u64 i = 0; i < DEGREE; ++i) {
                multi_sec_key[k][(j + i) % DEGREE] +=
                    (j + i >= DEGREE ? -1 : 1) * sec_to[k]->sec_coeff_[i] * sec_from->sec_coeff_[j];
            }
        }
    }

    for (u64 k = 0; k < sec_to.size(); ++k) { // num key
        s_poly from_coeff{};
        for (u64 j = 0; j < context_->getItemsPerCtxt(); ++j) {
            for (u64 i = 0; i < context_->getPadRank(); ++i) {
                from_coeff[context_->getPadRank() * j + i] =
                    multi_sec_key[i][(j * context_->getPadRank() + context_->getPadRank() - 1 - k + DEGREE) % DEGREE];
            }
        }

        poly sk_tmp;
        sampler_.embedding(from_coeff, sk_tmp, context_->getParam()->getPrimeQ());
        context_->nttModQ(sk_tmp);
        genSwitchingKey(sec_from, sk_tmp, pack_->cc_shared_a_mod_pack_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genModPackKey(const SecretKey &sec_key) {
    pack_->deb_mod_pack_key.addAx(2, context_->getPadRank(), true);
    // assume num_secret == 1
    pack_->deb_mod_pack_key.addBx(2, context_->getPadRank(), true);
    utils::syncVarKeyToDebSwkKey(context_, pack_->mod_pack_key, pack_->deb_mod_pack_key);
    deb_keygen_.genModPackKeyBundleInplace(context_->getPadRank(), pack_->deb_mod_pack_key, sec_key->deb_sk_);
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genPubKeys(const SecretKey &sec_key) {
    genEncKey(sec_key);
    genModPackKey(sec_key);
    genRelinKey(sec_key);
    pack_->eval_loaded_ = true;
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSwitchingKey(const SecretKey &sec_key, span<u64> from_s, span<u64> out_a_q,
                                          span<u64> out_a_p, span<u64> out_b_q, span<u64> out_b_p) {
    sampler_.sampleUniformModQ(out_a_q);
    sampler_.sampleUniformModP(out_a_p);
    sampler_.sampleGaussian(out_b_q, out_b_p);
    context_->nttModQ(out_b_q);
    context_->nttModP(out_b_p);
    context_->madModQ(out_a_q, sec_key->sec_key_q_, out_b_q);
    context_->madModP(out_a_p, sec_key->sec_key_p_, out_b_p);
    context_->negateModQ(out_a_q);
    context_->negateModP(out_a_p);
    context_->madModQ(from_s, context_->getParam()->getPModQ(), out_b_q);
}

template class KeyGeneratorImpl<EvalMode::FLAT>;
template class KeyGeneratorImpl<EvalMode::RMP>;
template class KeyGeneratorImpl<EvalMode::RMS>;
template class KeyGeneratorImpl<EvalMode::MS>;
template class KeyGeneratorImpl<EvalMode::MM>;

KeyGenerator makeKeyGenerator(const Context &context, KeyPack &pack, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::FLAT>>(context, pack, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::RMP>>(context, pack, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::RMS>>(context, pack, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MS>>(context, pack, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MM>>(context, pack, seed));
    default:
        throw NotSupportedError("Invalid mode");
    }
}

KeyGenerator makeKeyGenerator(const Context &context, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::FLAT>>(context, seed));
    case EvalMode::RMP:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::RMP>>(context, seed));
    case EvalMode::RMS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::RMS>>(context, seed));
    case EvalMode::MS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MS>>(context, seed));
    case EvalMode::MM:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MM>>(context, seed));
    default:
        throw NotSupportedError("Invalid mode");
    }
}

MultiKeyGenerator::MultiKeyGenerator(std::vector<Context> &context, const std::string &store_path, SealInfo &s_info,
                                     const std::optional<std::vector<u8>> &seed)
    : evi_context_(context), store_path_(store_path), s_info_(std::make_shared<SealInfo>(s_info)) {

    std::vector<u8> nseed;
    if (seed.has_value()) {
        nseed = *seed;
    } else {
        nseed.resize(SEED_MIN_SIZE);
        std::random_device rd;
        for (int i = 0; i < SEED_MIN_SIZE / 4; i++) {
            u32 val = rd();
            std::memcpy(nseed.data() + i * 4, &val, sizeof(val));
        }
    }
    as_ = std::shared_ptr<void>(alea_init(nseed.data(), ALEA_ALGORITHM_SHAKE256), [](void *p) {
        alea_free(static_cast<alea_state *>(p));
    });

    if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < evi_context_.size(); i++) {
            rank_list_.push_back(context[i]->getShowRank());
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::FLAT) {
        for (int i = 0; i < evi_context_.size(); i++) {
            rank_list_.push_back(context[i]->getRank());
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::MM) {
        for (int i = 0; i < static_cast<int>(evi_context_.size()); i++) {
            auto r = context[i]->getRank();
            rank_list_.push_back(r);
        }
    }

    preset_ = context[0]->getParam()->getPreset();
    this->initialize();
}

void MultiKeyGenerator::initialize() {
    // set context per dim
    inner_rank_list_ = utils::adjustRankList(rank_list_);
    if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < inner_rank_list_.size(); i++) {
            evi_keypack_.push_back(evi::detail::makeKeyPack(evi_context_[inner_rank_list_[i].second]));
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::FLAT) {
        for (int i = 0; i < rank_list_.size(); i++) {
            evi_keypack_.push_back(evi::detail::makeKeyPack(evi_context_[i]));
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::MM) {
        evi_keypack_.push_back(evi::detail::makeKeyPack(evi_context_[0]));
    } else {
        throw NotSupportedError("MultiKeyGenerator::initialize does not support EvalMode value: " +
                                std::to_string(static_cast<int>(evi_context_[0]->getEvalMode())));
    }
}

SecretKey MultiKeyGenerator::generateKeys() {
    SecretKey sec_key = generateSecKey();
    generatePubKey(sec_key);
    saveAllKeys(sec_key);
    return sec_key;
}

SecretKey MultiKeyGenerator::generateKeys(std::ostream &os) {
    SecretKey sec_key = generateKeys();
    utils::serializeKeyFiles(store_path_, os);
    std::filesystem::remove_all(store_path_);
    return sec_key;
}

void MultiKeyGenerator::generateKeysFromSecKey(const std::string &sec_key_path) {
    SecretKey sec_key = std::make_shared<SecretKeyData>(sec_key_path);
    generatePubKey(sec_key);
    saveAllKeys(sec_key);
}

SecretKey MultiKeyGenerator::generateSecKey() {
    std::vector<u8> seed(SEED_MIN_SIZE, 0);
    alea_get_random_bytes(as_.get(), seed.data(), SEED_MIN_SIZE);
    KeyGenerator keygen = makeKeyGenerator(evi_context_[0], evi_keypack_[0], seed);
    SecretKey sec_key = keygen->genSecKey();

    sec_key->s_info_.emplace(*s_info_);
    if (teew_.has_value()) {
        sec_key->teew_.emplace(teew_.value());
    }
    return sec_key;
}

void MultiKeyGenerator::generatePubKey(SecretKey &sec_key) {
    std::vector<u8> seed(SEED_MIN_SIZE, 0);
    if (evi_context_[0]->getEvalMode() == EvalMode::FLAT) {
        for (int i = 0; i < rank_list_.size(); i++) {
            alea_get_random_bytes(as_.get(), seed.data(), SEED_MIN_SIZE);
            KeyGenerator keygen = makeKeyGenerator(evi_context_[i], evi_keypack_[i], seed);
            keygen->genPubKeys(sec_key);
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < inner_rank_list_.size(); i++) {
            alea_get_random_bytes(as_.get(), seed.data(), SEED_MIN_SIZE);
            KeyGenerator keygen = makeKeyGenerator(evi_context_[inner_rank_list_[i].second], evi_keypack_[i], seed);
            keygen->genPubKeys(sec_key);
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::MM) {
        alea_get_random_bytes(as_.get(), seed.data(), SEED_MIN_SIZE);
        KeyGenerator keygen = makeKeyGenerator(evi_context_[0], evi_keypack_[0], seed);
        keygen->genPubKeys(sec_key);
    } else {
        throw NotSupportedError("MultiKeyGenerator::generate_pub_key does not support EvalMode value: " +
                                std::to_string(static_cast<int>(evi_context_[0]->getEvalMode())));
    }
}

bool MultiKeyGenerator::saveAllKeys(SecretKey &sec_key) {
    if (!fs::exists(store_path_)) {
        fs::create_directories(store_path_);
    }
    saveEncKey();
    saveEviSecKey(sec_key);
    if (evi_context_[0]->getEvalMode() != EvalMode::MM) {
        saveEvalKey();
    }
    return true;
}

void MultiKeyGenerator::saveEncKey() {
    evi_keypack_[0]->saveEncKeyFile(fs::path(store_path_ / "EncKey.bin"));
}

SecretKey MultiKeyGenerator::saveEviSecKey() {
    SecretKey sec_key = generateSecKey();
    if (s_info_->s_mode == SealMode::NONE) {
        sec_key->saveSecKey(fs::path(store_path_ / "SecKey.bin"));
    } else {
        sec_key->saveSealedSecKey(fs::path(store_path_ / "SecKey_sealed.bin"));
    }
    return sec_key;
}

void MultiKeyGenerator::saveEviSecKey(SecretKey &sec_key) {
    if (s_info_->s_mode == SealMode::NONE) {
        sec_key->saveSecKey(fs::path(store_path_ / "SecKey.bin"));
    } else {
        sec_key->saveSealedSecKey(fs::path(store_path_ / "SecKey_sealed.bin"));
    }
}

void MultiKeyGenerator::saveEvalKey() {
    fs::path meta_path = fs::path(store_path_.string()) / "metadata-eval.json";
    std::ofstream meta(meta_path);
    json j;

    j["ParameterPreset"] = utils::assignParameterString(preset_);
    j["Ranks"] = rank_list_;

    meta << std::setw(4) << j << std::endl;
    meta.close();
    if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < inner_rank_list_.size(); i++) {
            std::string path = (store_path_.string() + "/EVIKeys" + std::to_string(inner_rank_list_[i].first) + ".bin");
            evi_keypack_[i]->saveEvalKeyFile(path);
        }
    } else {
        for (int i = 0; i < rank_list_.size(); i++) {
            std::string path = (store_path_.string() + "/EVIKeys" + std::to_string(rank_list_[i]) + ".bin");
            evi_keypack_[i]->saveEvalKeyFile(path);
        }
    }
    utils::serializeEvalKey(store_path_.string(), store_path_.string() + "/EvalKey.bin");
}

bool MultiKeyGenerator::checkFileExist() {
    if (s_info_->s_mode == SealMode::NONE) {
        if (fs::exists(fs::path(store_path_.string() + "/SecKeyD16.bin"))) {
            return false;
        }
    } else {
        teew_.emplace(*s_info_);
        if (fs::exists(store_path_.string() + "/SecKeyD16_sealed.bin")) {
            return false;
        }
    }
    return true;
}
} // namespace detail
} // namespace evi
