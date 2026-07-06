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
#include "utils/security/Security.hpp"
#include <alea/alea.h>
#include <nlohmann/json.hpp>

#include "EVI/impl/KeyGeneratorImpl.hpp"

#include <SecretKeyGenerator.hpp>

#include <algorithm>
#include <cstring>
#include <limits>
#include <random>
#include <type_traits>

// deb header
#include <deb/SecretKeyGenerator.hpp>

using json = nlohmann::json;

namespace evi {
namespace detail {
namespace {

constexpr auto kCoeffNttType = deb::utils::NTTType::NEGACYCLIC;
constexpr auto kCoeffRootType = deb::utils::NTTRootType::MIN;

} // namespace

template <EvalMode M>
template <class KG>
KG &KeyGeneratorImpl<M>::keygen() {
    auto &slot = [this]() -> auto & {
        if constexpr (std::is_same_v<KG, deb::KeyGenerator32>) {
            return deb_keygen32_;
        } else {
            return deb_keygen_;
        }
    }();
    if (!slot) {
        slot.emplace(utils::getDebPreset(context_), deb_seed_);
    }
    return *slot;
}

template <EvalMode M>
KeyGeneratorImpl<M>::KeyGeneratorImpl(const Context &context, KeyPack &pack, const std::optional<std::vector<u8>> &seed)
    : context_(context), deb_seed_(utils::convertDebSeed(seed)), pack_iface_(pack), sampler_(context, seed) {
    pack_ = std::dynamic_pointer_cast<KeyPackData>(pack_iface_);
    if (!pack_) {
        throw std::logic_error("Failed to cast KeyPack");
    }
}

template <EvalMode M>
KeyGeneratorImpl<M>::KeyGeneratorImpl(const Context &context, const std::optional<std::vector<u8>> &seed)
    : context_(context), deb_seed_(utils::convertDebSeed(seed)), sampler_(context, seed) {
    auto data = std::make_shared<KeyPackData>(context_);
    pack_ = data;
    pack_iface_ = std::static_pointer_cast<IKeyPack>(data);
}

template <EvalMode M>
SecretKey KeyGeneratorImpl<M>::genSecKey(std::optional<const int *> coeff) {
    SecretKey seckey = std::make_shared<SecretKeyData>(context_);
    SecretKeyAccessScope key_access(seckey);
    if (coeff) {
        std::copy_n(coeff.value(), DEGREE, seckey->getCoeff().data());
    } else {
        sampler_.sampleHWT(seckey->getCoeff());
    }
    for (u64 i = 0; i < DEGREE; ++i) {
        seckey->getDebSecKey().coeffs()[i] = static_cast<int8_t>(seckey->getCoeff()[i]);
    }
    seckey->getDebSecKey() = utils::makeDebSecretKey<deb::u64>(utils::getDebPreset(context_), seckey->getDebSecKey());
    std::memcpy(seckey->getKeyQ().data(), seckey->getDebSecKey()[0][0].data(), detail::U64_DEGREE);
    std::memcpy(seckey->getKeyP().data(), seckey->getDebSecKey()[0][1].data(), detail::U64_DEGREE);
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
    SecretKeyAccessScope from_access(sec_from);
    pack_->num_shared_secret = sec_to.size();

    pack_->shared_a_key->setSize(sec_to.size() * sec_to.size() * DEGREE, sec_to.size() * DEGREE);

    // genA: independent random for Q and P (same as original RMS pattern)
    for (u64 i = 0; i < sec_to.size(); ++i) {
        sampler_.sampleUniformModQ(pack_->shared_a_key->getPolyData(1, 0) + (i * DEGREE));
        sampler_.sampleUniformModP(pack_->shared_a_key->getPolyData(1, 1) + (i * DEGREE));
    }

    // genB
    poly error_poly_q;
    poly error_poly_p;
    poly poly_p{};

    // P*s term: P is the key-switch auxiliary (same as RMS at level 0)
    poly_p[0] = context_->getParam()->getPModQ();
    context_->nttModQ(poly_p);

    for (u64 i = 0; i < sec_to.size(); ++i) {
        SecretKeyAccessScope to_access_i(sec_to[i]);
        for (u64 j = 0; j < sec_to.size(); ++j) {
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->shared_a_key->getPolyData(1, 0) + j * DEGREE, sec_to[i]->getKeyQ(),
                               pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
            context_->multModP(pack_->shared_a_key->getPolyData(1, 1) + j * DEGREE, sec_to[i]->getKeyP(),
                               pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE));
            context_->addModQ(pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE), error_poly_q,
                              pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
            context_->addModP(pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE), error_poly_p,
                              pack_->shared_a_key->getPolyData(0, 1) + ((j * sec_to.size() + i) * DEGREE));

            if (i == j) {
                // P*s term in Q channel (P is KS auxiliary, like RMS)
                context_->madModQ(sec_from->getKeyQ(), poly_p,
                                  pack_->shared_a_key->getPolyData(0, 0) + ((j * sec_to.size() + i) * DEGREE));
                // No P*s term in P channel (P ≡ 0 mod P)
            }
        }
    }

    // Negate A (Q and P channels)
    for (u64 i = 0; i < sec_to.size(); ++i) {
        context_->negateModQ(pack_->shared_a_key->getPolyData(1, 0) + (i * DEGREE));
        context_->negateModP(pack_->shared_a_key->getPolyData(1, 1) + (i * DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genAdditiveSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    SecretKeyAccessScope from_access(sec_from);
    // S to s[0] key
    pack_->reverse_switch_key->setSize(sec_to.size() * DEGREE);

    for (int i = 0; i < sec_to.size(); i++) {
        genSwitchingKey(sec_to[i], sec_from->getKeyQ(), pack_->reverse_switch_key->getPolyData(1, 0) + i * DEGREE,
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
        SecretKeyAccessScope to_access_k1(sec_to[k + 1]);
        for (u64 i = 0; i <= k; ++i) {
            SecretKeyAccessScope to_access_i(sec_to[i]);
            // add secret key encryption.
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[i]->getKeyQ(),
                               pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));
            context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[i]->getKeyP(),
                               pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE));
            context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE), error_poly_q,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));
            context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE), error_poly_p,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 1) + (i * DEGREE));

            context_->madModQ(sec_to[i]->getKeyQ(), poly_p,
                              pack_->additive_shared_a_key[k]->getPolyData(0, 0) + (i * DEGREE));

            // zero encryption.
            sampler_.sampleGaussian(error_poly_q, error_poly_p);
            context_->nttModQ(error_poly_q);
            context_->nttModP(error_poly_p);

            context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[i]->getKeyQ(),
                               pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 2 + i) * DEGREE));
            context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[i]->getKeyP(),
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

        context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[k + 1]->getKeyQ(),
                           pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE));
        context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[k + 1]->getKeyP(),
                           pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE));
        context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE), error_poly_q,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((k + 1) * DEGREE));
        context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE), error_poly_p,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((k + 1) * DEGREE));

        // seckey encryption.
        sampler_.sampleGaussian(error_poly_q, error_poly_p);
        context_->nttModQ(error_poly_q);
        context_->nttModP(error_poly_p);

        context_->multModQ(pack_->additive_shared_a_key[k]->getPolyData(1, 0), sec_to[k + 1]->getKeyQ(),
                           pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE));
        context_->multModP(pack_->additive_shared_a_key[k]->getPolyData(1, 1), sec_to[k + 1]->getKeyP(),
                           pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE));
        context_->addModQ(pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE), error_poly_q,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 0) + ((2 * k + 3) * DEGREE));
        context_->addModP(pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE), error_poly_p,
                          pack_->additive_shared_a_key[k]->getPolyData(0, 1) + ((2 * k + 3) * DEGREE));
        context_->madModQ(sec_to[k + 1]->getKeyQ(), poly_p,
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
    SecretKeyAccessScope key_access(sec_key);
    if (utils::isU32NativePreset(context_)) {
        // IP3 u32-native: generate the enc key with deb::KeyGenerator32 from the
        // u32 secret key and keep it as u32. No widen to u64 — the key lives
        // only as u32 (serialized via writePacked<u32>, byte-identical to the
        // u64 wire, and loaded straight back into a u32 encryptor key).
        const auto preset = utils::getDebPreset(context_);
        deb::SwitchKey32 enckey32(preset, deb::SWK_ENC);
        enckey32.addAx(2, 1);
        enckey32.addBx(2, 1);
        keygen<deb::KeyGenerator32>().genEncKeyInplace(enckey32, sec_key->getDebSecKey32(preset));
        pack_->deb_enc_key32.emplace(std::move(enckey32));
        pack_->enc_loaded_ = true;
        return;
    }
    utils::syncFixedKeyToDebSwkKey(context_, pack_->enckey, pack_->deb_enc_key);
    keygen<deb::KeyGenerator>().genEncKeyInplace(pack_->deb_enc_key, sec_key->getDebSecKey());
    pack_->enc_loaded_ = true;
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genRelinKey(const SecretKey &sec_key) {
    SecretKeyAccessScope key_access(sec_key);
    utils::syncVarKeyToDebSwkKey(context_, pack_->relin_key, pack_->deb_relin_key);
    keygen<deb::KeyGenerator>().genMultKeyInplace(pack_->deb_relin_key, sec_key->getDebSecKey());
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    SecretKeyAccessScope from_access(sec_from);
    pack_->shared_a_mod_pack_loaded_ = true;
    pack_->shared_a_mod_pack_key->setSize(sec_to.size() * DEGREE);
    for (u64 k = 0; k < sec_to.size(); ++k) { // num key
        SecretKeyAccessScope to_access(sec_to[k]);
        s_poly from_coeff{};
        for (u64 j = 0; j < context_->getItemsPerCtxt(); ++j) {
            for (u64 i = 0; i < context_->getPadRank(); ++i) {
                from_coeff[context_->getPadRank() * j + i] =
                    sec_to[i]
                        ->getCoeff()[(j * context_->getPadRank() + context_->getPadRank() - 1 - k + DEGREE) % DEGREE];
            }
        }

        poly sk_tmp;
        sampler_.embedding(from_coeff, sk_tmp, context_->getParam()->getQ(0));
        context_->nttModQ(sk_tmp);
        genSwitchingKey(sec_from, sk_tmp, pack_->shared_a_mod_pack_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->shared_a_mod_pack_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <typename T>
inline void automorphism(const T *op, T *res, const deb::Size sig, const deb::Size degree) {
    // X -> X^{2 * sig + 1}
    deb::Size base = ((sig << 1) ^ 1) & (2 * degree - 1);
    deb::Size idx = 0;
    for (deb::Size i = 0; i < degree; i++) {
        if (idx & degree) {
            res[idx & (degree - 1)] = -1 * op[i];
        } else {
            res[idx] = op[i];
        }
        idx = (idx + base) & (2 * degree - 1);
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    SecretKeyAccessScope from_access(sec_from);
    pack_->switch_key->setSize(sec_to.size() * DEGREE);
    for (u64 k = 0; k < sec_to.size(); ++k) {
        SecretKeyAccessScope to_access(sec_to[k]);
        genSwitchingKey(sec_from, sec_to[k]->getKeyQ(), pack_->switch_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->switch_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genCCSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    SecretKeyAccessScope from_access(sec_from);
    pack_->cc_shared_a_mod_pack_loaded_ = true;
    pack_->cc_shared_a_mod_pack_key->setSize(sec_to.size() * DEGREE);
    std::vector<s_poly> multi_sec_key(sec_to.size(), {0});
    for (u64 k = 0; k < sec_to.size(); ++k) { // num key // To prevent precision loss..
        SecretKeyAccessScope to_access(sec_to[k]);
        for (u64 j = 0; j < DEGREE; j++) {
            for (u64 i = 0; i < DEGREE; ++i) {
                multi_sec_key[k][(j + i) % DEGREE] +=
                    (j + i >= DEGREE ? -1 : 1) * sec_to[k]->getCoeff()[i] * sec_from->getCoeff()[j];
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
        sampler_.embedding(from_coeff, sk_tmp, context_->getParam()->getQ(0));
        context_->nttModQ(sk_tmp);
        genSwitchingKey(sec_from, sk_tmp, pack_->cc_shared_a_mod_pack_key->getPolyData(1, 0) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(1, 1) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(0, 0) + (k << LOG_DEGREE),
                        pack_->cc_shared_a_mod_pack_key->getPolyData(0, 1) + (k << LOG_DEGREE));
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genModPackKey(const SecretKey &sec_key) {
    SecretKeyAccessScope key_access(sec_key);
    const auto num_p = utils::getDebNumP(context_);
    pack_->deb_mod_pack_key.addAx(num_p, context_->getPadRank(), kCoeffNttType, kCoeffRootType);
    pack_->deb_mod_pack_key.addBx(num_p, context_->getPadRank(), kCoeffNttType, kCoeffRootType);
    utils::syncVarKeyToDebSwkKey(context_, pack_->mod_pack_key, pack_->deb_mod_pack_key);
    keygen<deb::KeyGenerator>().genModPackKeyBundleInplace(context_->getPadRank(), pack_->deb_mod_pack_key,
                                                           sec_key->getDebSecKey());
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genPubKeys(const SecretKey &sec_key) {
    genEncKey(sec_key);
    const auto mode = context_->getEvalMode();
    if (CHECK_MM(mode)) {
        genSwitchingKeys(sec_key);
        if (mode == evi::EvalMode::MMS || mode == evi::EvalMode::MMS32) {
            constexpr int K_NUM_SHARED_SECRET = 4;
            pack_->num_shared_secret = K_NUM_SHARED_SECRET;

            const auto deb_preset = utils::getDebPreset(context_);

            // 1. Generate random sub-secrets
            deb::SecretKeyGenerator deb_sk_gen(deb_preset);
            std::vector<deb::SecretKey> sub_sks;
            sub_sks.reserve(K_NUM_SHARED_SECRET);
            for (int i = 0; i < K_NUM_SHARED_SECRET; ++i) {
                sub_sks.push_back(deb_sk_gen.genSecretKey());
            }

            // 2. Forward switch keys: each diagonal key (s→s_j) has independent ax.
            //    Standard RLWE key-switch security requires independent randomness per key.
            //    The shared-A property is achieved later at toSharedA time, not at keygen.
            {
                const auto gadget_rank = deb::get_gadget_rank(deb_preset);
                const auto num_p = deb::get_num_p(deb_preset);
                const auto *deb_primes = deb::get_primes(deb_preset);

                SecretKeyAccessScope sk_access(sec_key);

                // Diagonal keys: independent genSwitchingKey per sub-secret
                pack_->shared_a_fwd_keys.clear();
                for (int s = 0; s < K_NUM_SHARED_SECRET; ++s) {
                    deb::SwitchKey sk_key(deb_preset, deb::SWK_GENERIC);
                    sk_key.addAx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);
                    sk_key.addBx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);

                    deb::Polynomial from_poly = sec_key->getDebSecKey()[0];
                    deb::Polynomial to_poly = sub_sks[s][0];
                    keygen<deb::KeyGenerator>().genSwitchingKey(&from_poly, &to_poly, sk_key.getAx().data(),
                                                                sk_key.getBx().data(), gadget_rank, gadget_rank);

                    pack_->shared_a_fwd_keys.emplace_back(deb_preset, deb::SWK_AUTO);
                    auto &fk = pack_->shared_a_fwd_keys[s];
                    for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                        for (deb::Size pj = 0; pj < num_p; ++pj) {
                            std::memcpy(fk.ax(gi)[pj].data(), sk_key.ax(gi)[pj].data(), DEGREE * sizeof(u64));
                            std::memcpy(fk.bx(gi)[pj].data(), sk_key.bx(gi)[pj].data(), DEGREE * sizeof(u64));
                        }
                    }
                }

                // Off-diagonal keys: bx = -(ax_s · sk'_j) + e
                // Uses diagonal key s's ax (independent per s), paired with sub_sks[j].
                pack_->shared_a_off_diag_keys.clear();
                auto offdiag_rng = deb::createRandomGenerator(deb::SeedGenerator::Gen());
                for (int i = 0; i < K_NUM_SHARED_SECRET * K_NUM_SHARED_SECRET; ++i) {
                    pack_->shared_a_off_diag_keys.emplace_back(deb_preset, deb::SWK_AUTO);
                }
                for (int s = 0; s < K_NUM_SHARED_SECRET; ++s) {
                    const auto &diag_key = pack_->shared_a_fwd_keys[s];
                    for (int j = 0; j < K_NUM_SHARED_SECRET; ++j) {
                        if (s == j) {
                            continue;
                        }
                        auto &boff = pack_->shared_a_off_diag_keys[s * K_NUM_SHARED_SECRET + j];
                        // Copy ax from diagonal key s (independent per s)
                        for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                            for (deb::Size pj = 0; pj < num_p; ++pj) {
                                std::memcpy(boff.ax(gi)[pj].data(), diag_key.ax(gi)[pj].data(), DEGREE * sizeof(u64));
                            }
                        }
                        for (deb::Size d = 0; d < gadget_rank; ++d) {
                            std::vector<i64> err_coeff(DEGREE);
                            offdiag_rng->sampleGaussianInt64Array(err_coeff.data(), DEGREE, 3.2);

                            for (deb::Size p = 0; p < num_p; ++p) {
                                deb::utils::ModArith<DEGREE> arith(deb_primes[p]);
                                const u64 prime = deb_primes[p];

                                // bx = -(ax_s · sk'_j) + e
                                arith.mulVector(boff.bx(d)[p].data(), diag_key.ax(d)[p].data(),
                                                sub_sks[j][0][p].data());
                                u64 *bd = boff.bx(d)[p].data();
                                for (u64 k = 0; k < DEGREE; ++k) {
                                    bd[k] = bd[k] == 0 ? 0 : prime - bd[k];
                                }
                                arith.backwardNTT(bd);
                                for (u64 k = 0; k < DEGREE; ++k) {
                                    u64 e_mod = (err_coeff[k] >= 0) ? static_cast<u64>(err_coeff[k])
                                                                    : prime - static_cast<u64>(-err_coeff[k]);
                                    u64 sum = bd[k] + e_mod;
                                    bd[k] = (sum >= prime) ? sum - prime : sum;
                                }
                                arith.forwardNTT(bd);
                            }
                        }
                    }
                }
            }

            // Legacy shared_a_key not used — new deb QPR forward keys stored separately
            pack_->shared_a_key_loaded_ = false;

            // 4. Backward L0 CRT-consistent keys (s_j → s) for post-PCMM key-switch.
            //    Target primes come from Parameter::getBackwardKey{Q,P}() so the
            //    preset/eval-mode routing lives in one place (see Parameter.hpp):
            //      - IP1 MMS      -> IP0 L0 (base conversion IP1 -> IP0)
            //      - IP2 MMS      -> IP2 L0 (no base conversion, stays in IP2)
            //      - IP2 MMS32    -> IP2 L0 (same as IP2 MMS; u64 storage)
            //      - IP3 MMS32    -> IP3 L0 (u32-native storage)
            //    Source primes always come from the context itself.
            {
                const u64 q_val = context_->getParam()->getBackwardKeyQ();
                const u64 p_val = context_->getParam()->getBackwardKeyP();
                deb::utils::ModArith<DEGREE> bwd_aq(q_val), bwd_ap(p_val);

                pack_->shared_a_bwd_l0_keys.resize(K_NUM_SHARED_SECRET);

                // Base-convert secret keys from context (source) primes to the
                // backward target primes. When source == target (IP2/MMS,
                // IP2/MMS32, IP0/MMS) the conversion is effectively identity
                // but the same code path is exercised for CT-ness.
                const u64 q_src = context_->getParam()->getQ(0);
                const u64 p_src = deb_prime_at(context_->getParam(), 1);
                const u64 q_half_src = q_src >> 1;
                deb::utils::ModArith<DEGREE> aq_src(q_src), ap_src(p_src);

                auto base_conv_key = [&](const u64 *src_ntt, u64 src_prime, u64 src_half,
                                         deb::utils::ModArith<DEGREE> &src_arith,
                                         deb::utils::ModArith<DEGREE> &dst_arith, u64 dst_prime) -> std::vector<u64> {
                    std::vector<u64> coeff(DEGREE), dst(DEGREE);
                    std::memcpy(coeff.data(), src_ntt, DEGREE * sizeof(u64));
                    src_arith.backwardNTT(coeff.data());
                    for (u64 k = 0; k < DEGREE; ++k) {
                        i64 v = (coeff[k] > src_half) ? (i64)coeff[k] - (i64)src_prime : (i64)coeff[k];
                        dst[k] = (v >= 0) ? (u64)v % dst_prime : dst_prime - ((u64)(-v) % dst_prime);
                    }
                    dst_arith.forwardNTT(dst.data());
                    return dst;
                };

                SecretKeyAccessScope bwd_sk_access(sec_key);
                std::vector<u64> sk_bwd_q =
                    base_conv_key(sec_key->getKeyQ().data(), q_src, q_half_src, aq_src, bwd_aq, q_val);
                std::vector<u64> sk_bwd_p =
                    base_conv_key(sec_key->getKeyQ().data(), q_src, q_half_src, aq_src, bwd_ap, p_val);

                // Sub-secrets in backward target Q (NTT domain). sub_sks are
                // deb::SecretKey-owned CRT buffers in the context's Q domain.
                std::vector<std::vector<u64>> sub_sk_bwd_q(K_NUM_SHARED_SECRET);
                for (int j = 0; j < K_NUM_SHARED_SECRET; ++j) {
                    sub_sk_bwd_q[j] = base_conv_key(sub_sks[j][0][0].data(), q_src, q_half_src, aq_src, bwd_aq, q_val);
                }

                // Use deb/alea CSPRNG for all random sampling
                auto bwd_rng = deb::createRandomGenerator(deb::SeedGenerator::Gen());
                auto sample_uniform_mod = [&](u64 mod) -> u64 {
                    const u64 max = std::numeric_limits<u64>::max();
                    const u64 threshold = max - (max % mod);
                    u64 val = 0;
                    do {
                        bwd_rng->getRandomUint64Array(&val, 1);
                    } while (val >= threshold);
                    return val % mod;
                };

                for (int j = 0; j < K_NUM_SHARED_SECRET; ++j) {
                    auto &bk = pack_->shared_a_bwd_l0_keys[j];
                    // Compute in local u64 scratch; only the active variant
                    // (u32 for IP3, else u64) is stored — no dual residency.
                    polyvec sc_ax_q(DEGREE), sc_ax_p(DEGREE), sc_bx_q(DEGREE), sc_bx_p(DEGREE);

                    // CRT-consistent random ax: uniform over [0, Q*P) via rejection sampling
                    {
                        for (u64 k = 0; k < DEGREE; ++k) {
                            sc_ax_q[k] = sample_uniform_mod(q_val);
                            sc_ax_p[k] = sample_uniform_mod(p_val);
                        }
                    }
                    bwd_aq.forwardNTT(sc_ax_q.data());
                    bwd_ap.forwardNTT(sc_ax_p.data());

                    // CRT-consistent Gaussian error (σ=3.2)
                    std::vector<u64> e_q(DEGREE), e_p(DEGREE);
                    {
                        std::vector<deb::i64> e_coeffs(DEGREE);
                        bwd_rng->sampleGaussianInt64Array(e_coeffs.data(), DEGREE, 3.2);
                        for (u64 k = 0; k < DEGREE; ++k) {
                            // Constant-time signed→unsigned mod
                            i64 e = e_coeffs[k];
                            u64 neg_mask = static_cast<u64>(e >> 63);
                            e_q[k] = (static_cast<u64>(e) + (q_val & neg_mask)) % q_val;
                            e_p[k] = (static_cast<u64>(e) + (p_val & neg_mask)) % p_val;
                        }
                    }
                    bwd_aq.forwardNTT(e_q.data());
                    bwd_ap.forwardNTT(e_p.data());

                    // Constant-time helpers (secret-dependent: bx involves secret key)
                    auto ct_neg = [](u64 x, u64 prime) -> u64 {
                        return (prime - x) & static_cast<u64>(-static_cast<i64>(x != 0));
                    };
                    auto ct_red = [](u64 x, u64 prime) -> u64 {
                        return x - (prime & static_cast<u64>(-static_cast<i64>(x >= prime)));
                    };

                    // bx_Q = -(ax * sk_bwd) + e + sk'_j_bwd * P mod Q  [constant-time]
                    bwd_aq.mulVector(sc_bx_q.data(), sc_ax_q.data(), sk_bwd_q.data());
                    for (u64 k = 0; k < DEGREE; ++k) {
                        sc_bx_q[k] = ct_neg(sc_bx_q[k], q_val);
                    }
                    for (u64 k = 0; k < DEGREE; ++k) {
                        sc_bx_q[k] = ct_red(sc_bx_q[k] + e_q[k], q_val);
                    }
                    u64 p_mod_q = p_val % q_val;
                    std::vector<u64> sfp(DEGREE);
                    bwd_aq.constMult(sub_sk_bwd_q[j].data(), p_mod_q, sfp.data());
                    for (u64 k = 0; k < DEGREE; ++k) {
                        sc_bx_q[k] = ct_red(sc_bx_q[k] + sfp[k], q_val);
                    }

                    // bx_P = -(ax * sk_bwd) + e (P mod P = 0)  [constant-time]
                    bwd_ap.mulVector(sc_bx_p.data(), sc_ax_p.data(), sk_bwd_p.data());
                    for (u64 k = 0; k < DEGREE; ++k) {
                        sc_bx_p[k] = ct_neg(sc_bx_p[k], p_val);
                    }
                    for (u64 k = 0; k < DEGREE; ++k) {
                        sc_bx_p[k] = ct_red(sc_bx_p[k] + e_p[k], p_val);
                    }

                    // Store only the active variant. Gate on preset == IP3,
                    // NOT prime width: IP2's backward primes also fit in 32
                    // bits but after the IP2->u64 demotion IP2 is u64-numeric
                    // (isU32Matrix()==false), so a width gate would corrupt
                    // it. IP3 -> u32-native; all others (incl. IP2) -> u64.
                    // Single source of truth shared with the KeyPackImpl reader
                    // (utils::isU32BackwardKey), so the write-side variant choice
                    // and the read-side allocation are the same function call.
                    const bool bwd_fits_u32 = utils::isU32BackwardKey(context_);
                    if (bwd_fits_u32) {
                        auto narrow = [](const polyvec &src) {
                            polyvec32 dst(src.size());
                            std::copy_n(src.data(), src.size(), dst.data());
                            return dst;
                        };
                        bk.ax_q.emplace<polyvec32>(narrow(sc_ax_q));
                        bk.ax_p.emplace<polyvec32>(narrow(sc_ax_p));
                        bk.bx_q.emplace<polyvec32>(narrow(sc_bx_q));
                        bk.bx_p.emplace<polyvec32>(narrow(sc_bx_p));
                    } else {
                        bk.ax_q.emplace<polyvec>(std::move(sc_ax_q));
                        bk.ax_p.emplace<polyvec>(std::move(sc_ax_p));
                        bk.bx_q.emplace<polyvec>(std::move(sc_bx_q));
                        bk.bx_p.emplace<polyvec>(std::move(sc_bx_p));
                    }
                }
            }
            // Legacy backward key flag: new L0 keys stored in shared_a_bwd_l0_keys
            // Do NOT set shared_a_mod_pack_loaded_ — legacy key not populated
        }
    } else if (context_->getEvalMode() == evi::EvalMode::SINGLE) {
        genRelinKey(sec_key);
    } else {
        genModPackKey(sec_key);
        genRelinKey(sec_key);
    }
    pack_->eval_loaded_ = true;
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSwitchingKeys(const SecretKey &sec_key) {
    SecretKeyAccessScope key_access(sec_key);
    pack_->eval_loaded_ = true;
    pack_->key_switching_key.resize(DEGREE);

    const auto deb_preset = evi::detail::utils::getDebPreset(context_);
    const auto num_p = evi::detail::utils::getDebNumP(context_);
    const auto gadget_rank = evi::detail::utils::getDebGadgetRank(context_);
    const auto poly_count = num_p * gadget_rank;
    const bool use_u32 = utils::isU32NativePreset(context_);

    const std::size_t count = static_cast<std::size_t>(DEGREE) * poly_count;

    for (deb::u64 sig = 0; sig < DEGREE; ++sig) {
        if (use_u32) {
            // IP3 u32-native: generate the automorphism key directly with
            // deb::KeyGenerator32 into u32 storage (no u64 compute + narrow).
            // dk32 ax/bx alias the polyvec32 buffers so genAutoKeyInplace
            // writes the u32 limbs in place; they are then moved into the
            // TransposeKey32 Matrix consumed by the IP3 keyswitch path.
            deb::SwitchKey32 dk32(deb_preset, deb::SWK_AUTO, sig);
            dk32.addAx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);
            dk32.addBx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);

            polyvec32 a_q32(count), b_q32(count);
            for (deb::u64 i = 0; i < gadget_rank; ++i) {
                for (deb::u64 j = 0; j < num_p; ++j) {
                    const deb::u64 idx = (i * num_p + j) * DEGREE;
                    dk32.ax(i)[j].setData(a_q32.data() + idx, DEGREE);
                    dk32.bx(i)[j].setData(b_q32.data() + idx, DEGREE);
                }
            }

            keygen<deb::KeyGenerator32>().genAutoKeyInplace(sig, dk32, sec_key->getDebSecKey32(deb_preset));

            auto key32 = std::make_shared<Matrix<DataType::CIPHER, u32>>(std::move(a_q32), std::move(b_q32));
            key32->preset = ParameterPreset::IP3;
            pack_->key_switching_key[sig].emplace<KeyPackData::TransposeKey32>(std::move(key32));
        } else {
            deb::SwitchKey dk(deb_preset, deb::SWK_AUTO, sig);
            VariadicKeyType generated_key;
            dk.addAx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);
            dk.addBx(num_p, gadget_rank, kCoeffNttType, kCoeffRootType);

            generated_key->setSize(DEGREE * poly_count);

            auto *a_q = generated_key->getPolyData(1, 0);
            auto *b_q = generated_key->getPolyData(0, 0);

            for (deb::u64 i = 0; i < gadget_rank; ++i) {
                for (deb::u64 j = 0; j < num_p; ++j) {
                    const deb::u64 idx = (i * num_p + j) * DEGREE;
                    dk.ax(i)[j].setData(a_q + idx, DEGREE);
                    dk.bx(i)[j].setData(b_q + idx, DEGREE);
                }
            }

            keygen<deb::KeyGenerator>().genAutoKeyInplace(sig, dk, sec_key->getDebSecKey());

            pack_->key_switching_key[sig].emplace<VariadicKeyType>(std::move(generated_key));
        }
    }
}

template <EvalMode M>
void KeyGeneratorImpl<M>::genSwitchingKey(const SecretKey &sec_key, span<u64> from_s, span<u64> out_a_q,
                                          span<u64> out_a_p, span<u64> out_b_q, span<u64> out_b_p) {
    SecretKeyAccessScope key_access(sec_key);
    sampler_.sampleUniformModQ(out_a_q);
    sampler_.sampleUniformModP(out_a_p);
    sampler_.sampleGaussian(out_b_q, out_b_p);
    context_->nttModQ(out_b_q);
    context_->nttModP(out_b_p);
    context_->madModQ(out_a_q, sec_key->getKeyQ(), out_b_q);
    context_->madModP(out_a_p, sec_key->getKeyP(), out_b_p);
    context_->negateModQ(out_a_q);
    context_->negateModP(out_a_p);
    context_->madModQ(from_s, context_->getParam()->getPModQ(), out_b_q);
}

template class KeyGeneratorImpl<EvalMode::FLAT>;
template class KeyGeneratorImpl<EvalMode::SINGLE>;
template class KeyGeneratorImpl<EvalMode::RMP>;
template class KeyGeneratorImpl<EvalMode::RMS>;
template class KeyGeneratorImpl<EvalMode::MS>;
template class KeyGeneratorImpl<EvalMode::MM>;
template class KeyGeneratorImpl<EvalMode::MMS>;
template class KeyGeneratorImpl<EvalMode::MM32>;
template class KeyGeneratorImpl<EvalMode::MMS32>;

KeyGenerator makeKeyGenerator(const Context &context, KeyPack &pack, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::FLAT>>(context, pack, seed));
    case EvalMode::SINGLE:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::SINGLE>>(context, pack, seed));
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
    case EvalMode::MMS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MMS>>(context, pack, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MM32>>(context, pack, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MMS32>>(context, pack, seed));
    default:
        throw NotSupportedError("Invalid mode");
    }
}

KeyGenerator makeKeyGenerator(const Context &context, const std::optional<std::vector<u8>> &seed) {
    switch (context->getEvalMode()) {
    case EvalMode::FLAT:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::FLAT>>(context, seed));
    case EvalMode::SINGLE:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::SINGLE>>(context, seed));
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
    case EvalMode::MMS:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MMS>>(context, seed));
    case EvalMode::MM32:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MM32>>(context, seed));
    case EvalMode::MMS32:
        return std::static_pointer_cast<KeyGeneratorInterface>(
            std::make_shared<KeyGeneratorImpl<EvalMode::MMS32>>(context, seed));
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
    std::vector<u8> sec_seed(SEED_MIN_SIZE);
    std::vector<u8> pub_seed(SEED_MIN_SIZE);
    if (alea_hkdf(nseed.data(), nseed.size(), nullptr, 0, reinterpret_cast<const uint8_t *>("seckey"),
                  std::strlen("seckey"), sec_seed.data(), sec_seed.size()) != ALEA_RETURN_OK) {
        throw std::runtime_error("Failed to derive seckey seed");
    }
    if (alea_hkdf(nseed.data(), nseed.size(), nullptr, 0, reinterpret_cast<const uint8_t *>("pubkey"),
                  std::strlen("pubkey"), pub_seed.data(), pub_seed.size()) != ALEA_RETURN_OK) {
        throw std::runtime_error("Failed to derive pubkey seed");
    }
    sec_as_ = std::shared_ptr<alea_state>(alea_init(sec_seed.data(), ALEA_ALGORITHM_SHAKE256), [](alea_state *p) {
        alea_free(p);
    });
    pub_as_ = std::shared_ptr<alea_state>(alea_init(pub_seed.data(), ALEA_ALGORITHM_SHAKE256), [](alea_state *p) {
        alea_free(p);
    });
    evi::security::secureZeroMemory(sec_seed.data(), sec_seed.size());
    evi::security::secureZeroMemory(pub_seed.data(), pub_seed.size());
    evi::security::secureZeroMemory(nseed.data(), nseed.size());

    if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < evi_context_.size(); i++) {
            rank_list_.push_back(context[i]->getShowRank());
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::FLAT) {
        for (int i = 0; i < evi_context_.size(); i++) {
            rank_list_.push_back(context[i]->getRank());
        }
    } else if (CHECK_MM(evi_context_[0]->getEvalMode())) {
        for (int i = 0; i < static_cast<int>(evi_context_.size()); i++) {
            auto r = context[i]->getRank();
            rank_list_.push_back(r);
        }
    }

    preset_ = context[0]->getParam()->getPreset();
    this->initialize();
}

MultiKeyGenerator::~MultiKeyGenerator() {
    if (s_info_) {
        if (!s_info_->kek.empty()) {
            evi::security::secureZeroMemory(s_info_->kek.data(), s_info_->kek.size());
            s_info_->kek.clear();
            s_info_->kek.shrink_to_fit();
        }
        if (!s_info_->h_auth_pw.empty()) {
            evi::security::secureZeroMemory(s_info_->h_auth_pw.data(), s_info_->h_auth_pw.size());
            s_info_->h_auth_pw.clear();
            s_info_->h_auth_pw.shrink_to_fit();
        }
    }
    teew_.reset();
    sec_as_.reset();
    pub_as_.reset();
    s_info_.reset();
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
    } else if (CHECK_MM(evi_context_[0]->getEvalMode())) {
        evi_keypack_.push_back(evi::detail::makeKeyPack(evi_context_[0]));
    } else if (evi_context_[0]->getEvalMode() == EvalMode::SINGLE) {
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
    utils::serializeKeyFiles(store_path_.string(), os);
    std::filesystem::remove_all(store_path_);
    return sec_key;
}

void MultiKeyGenerator::generateKeysFromSecKey(const std::string &sec_key_path) {
    SecretKey sec_key = std::make_shared<SecretKeyData>(sec_key_path);
    generatePubKey(sec_key);
    saveAllKeys(sec_key);
    sec_key.reset();
}

SecretKey MultiKeyGenerator::generateSecKey() {
    std::vector<u8> seed(SEED_MIN_SIZE, 0);
    alea_get_random_bytes(sec_as_.get(), seed.data(), SEED_MIN_SIZE);
    KeyGenerator keygen = makeKeyGenerator(evi_context_[0], evi_keypack_[0], seed);
    evi::security::secureZeroMemory(seed.data(), seed.size());
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
            alea_get_random_bytes(pub_as_.get(), seed.data(), SEED_MIN_SIZE);
            KeyGenerator keygen = makeKeyGenerator(evi_context_[i], evi_keypack_[i], seed);
            keygen->genPubKeys(sec_key);
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < inner_rank_list_.size(); i++) {
            alea_get_random_bytes(pub_as_.get(), seed.data(), SEED_MIN_SIZE);
            KeyGenerator keygen = makeKeyGenerator(evi_context_[inner_rank_list_[i].second], evi_keypack_[i], seed);
            keygen->genPubKeys(sec_key);
        }
    } else if (CHECK_MM(evi_context_[0]->getEvalMode())) {
        alea_get_random_bytes(pub_as_.get(), seed.data(), SEED_MIN_SIZE);
        KeyGenerator keygen = makeKeyGenerator(evi_context_[0], evi_keypack_[0], seed);
        keygen->genPubKeys(sec_key);
    } else if (evi_context_[0]->getEvalMode() == EvalMode::SINGLE) {
        alea_get_random_bytes(pub_as_.get(), seed.data(), SEED_MIN_SIZE);
        KeyGenerator keygen = makeKeyGenerator(evi_context_[0], evi_keypack_[0], seed);
        keygen->genPubKeys(sec_key);
    }
    evi::security::secureZeroMemory(seed.data(), seed.size());
}

bool MultiKeyGenerator::saveAllKeys(SecretKey &sec_key) {
    if (!fs::exists(store_path_)) {
        fs::create_directories(store_path_);
    }
    saveEncKey();
    saveEviSecKey(sec_key);
    saveEvalKey();
    return true;
}

SecretKey MultiKeyGenerator::generateKeys(std::ostream &seckey, std::ostream &enckey, std::ostream &evalkey) {
    if (!fs::exists(store_path_)) {
        fs::create_directories(store_path_);
    }
    SecretKey sk = generateSecKey();
    sk->serialize(seckey);
    generatePubKey(sk);
    evi_keypack_[0]->getEncKeyBuffer(enckey);
    saveEvalKey();
    std::filesystem::path eval_path = store_path_ / "EvalKey.bin";
    std::ifstream eval(eval_path, std::ios::binary);
    evalkey << eval.rdbuf();
    eval.close();
    fs::remove(eval_path);
    return sk;
}

SecretKey MultiKeyGenerator::generateKeys(SecretKey &seckey, std::ostream &enckey, std::ostream &evalkey) {
    if (!seckey) {
        throw std::logic_error("SecretKey impl is null");
    }
    if (!fs::exists(store_path_)) {
        fs::create_directories(store_path_);
    }

    generatePubKey(seckey);
    evi_keypack_[0]->getEncKeyBuffer(enckey);

    const fs::path original_store_path = store_path_;
    const fs::path temp_store_path =
        original_store_path / (".tmp-generate-evalkey-" +
                               std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

    struct StorePathGuard {
        fs::path &store_path;
        fs::path original_path;

        ~StorePathGuard() {
            store_path = original_path;
        }
    } guard{store_path_, original_store_path};

    fs::create_directories(temp_store_path);
    store_path_ = temp_store_path;
    saveEvalKey();

    const fs::path eval_path = temp_store_path / "EvalKey.bin";
    std::ifstream eval(eval_path, std::ios::binary);
    if (!eval.is_open()) {
        fs::remove_all(temp_store_path);
        throw std::runtime_error("Failed to open generated EvalKey.bin");
    }

    evalkey << eval.rdbuf();
    eval.close();
    fs::remove_all(temp_store_path);
    return seckey;
}

void MultiKeyGenerator::saveEncKey() {
    evi_keypack_[0]->saveEncKeyFile((store_path_ / "EncKey.bin").string());
}

SecretKey MultiKeyGenerator::saveEviSecKey() {
    SecretKey sec_key = generateSecKey();
    if (s_info_->s_mode == SealMode::NONE) {
        sec_key->saveSecKey((store_path_ / "SecKey.bin").string());
    } else {
        sec_key->saveSealedSecKey((store_path_ / "SecKey_sealed.bin").string());
    }
    return sec_key;
}

void MultiKeyGenerator::saveEviSecKey(SecretKey &sec_key) {
    if (s_info_->s_mode == SealMode::NONE) {
        sec_key->saveSecKey((store_path_ / "SecKey.bin").string());
    } else {
        sec_key->saveSealedSecKey((store_path_ / "SecKey_sealed.bin").string());
    }
}

void MultiKeyGenerator::saveEvalKey() {
    fs::path tmp_store_path =
        store_path_ /
        (".tmp-evalkey-" + std::to_string(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    if (!fs::exists(tmp_store_path)) {
        fs::create_directories(tmp_store_path);
    }

    fs::path meta_path = tmp_store_path / "metadata-eval.json";
    std::ofstream meta(meta_path);
    json j;

    j["ParameterPreset"] = utils::assignParameterString(preset_);
    j["EvalMode"] = utils::assignEvalModeString(evi_context_[0]->getEvalMode());
    j["Ranks"] = rank_list_;

    meta << std::setw(4) << j << std::endl;
    meta.close();
    if (evi_context_[0]->getEvalMode() == EvalMode::RMP) {
        for (int i = 0; i < inner_rank_list_.size(); i++) {
            const auto pad_rank = evi_context_[inner_rank_list_[i].second]->getPadRank();
            std::string path = (tmp_store_path.string() + "/EVIKeys" + std::to_string(pad_rank) + ".bin");
            evi_keypack_[i]->saveEvalKeyFile(path);
        }
    } else if (evi_context_[0]->getEvalMode() == EvalMode::FLAT) {
        for (int i = 0; i < rank_list_.size(); i++) {
            std::string path = (tmp_store_path.string() + "/EVIKeys" + std::to_string(rank_list_[i]) + ".bin");
            evi_keypack_[i]->saveEvalKeyFile(path);
        }
    } else if (CHECK_MM(evi_context_[0]->getEvalMode())) {
        evi_keypack_[0]->saveEvalKeyFile(tmp_store_path.string() + "/EVIKeys" + std::to_string(rank_list_[0]) + ".bin");
    } else if (evi_context_[0]->getEvalMode() == EvalMode::SINGLE) {
        evi_keypack_[0]->saveEvalKeyFile(tmp_store_path.string() + "/EVIKeys" + std::to_string(rank_list_[0]) + ".bin");
    }
    utils::serializeEvalKey(tmp_store_path.string(), store_path_.string() + "/EvalKey.bin");
    fs::remove_all(tmp_store_path);
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
