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

#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/Basic.cuh"
#include "EVI/impl/Bitpack.hpp"
#include "EVI/impl/Parameter.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

using json = nlohmann::json;

namespace evi {
namespace detail {

KeyPackData::KeyPackData(const Context &context)
    : context_(context), deb_enc_key(utils::getDebPreset(context), deb::SWK_ENC),
      deb_relin_key(utils::getDebPreset(context), deb::SWK_MULT),
      deb_mod_pack_key(utils::getDebPreset(context), deb::SWK_MODPACK_SELF),
      deb_shared_a_fwd_key(utils::getDebPreset(context), deb::SWK_GENERIC),
      deb_shared_a_bwd_key(utils::getDebPreset(context), deb::SWK_GENERIC) {
    const std::size_t relin_ax_poly_count = static_cast<std::size_t>(utils::getDebGadgetRank(context));
    const auto preset = utils::getDebPreset(context);
    const std::size_t relin_bx_poly_count = relin_ax_poly_count * static_cast<std::size_t>(deb::get_num_secret(preset));
    relin_key->setSize(static_cast<int>(DEGREE * relin_bx_poly_count), static_cast<int>(DEGREE * relin_ax_poly_count));
    mod_pack_key->setSize(context->getPadRank() * DEGREE);
    num_shared_secret = 0;
    shared_a_key_loaded_ = false;
    shared_a_mod_pack_loaded_ = false;
    cc_shared_a_mod_pack_loaded_ = false;
    enc_loaded_ = false;
    eval_loaded_ = false;
    keyswitcher_cpu_loaded_ = false;
    keyswitcher_gpu_loaded_ = false;
    keyswitcher_cpu_.reset();
    keyswitcher_gpu_.reset();
}

KeyPackData::KeyPackData(const Context &context, std::istream &in) : KeyPackData(context) {
    this->deserialize(in);
}

KeyPackData::KeyPackData(const Context &context, const std::string &dir_path) : KeyPackData(context) {
    loadEncKeyFile(dir_path);

    if (context->getEvalMode() != EvalMode::MM && context->getEvalMode() != EvalMode::MM32) {
        loadEvalKeyFile(dir_path);
    }
}

void KeyPackData::saveEncKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios::out | std::ios_base::binary);
    if (!out.is_open()) {
        throw evi::FileNotFoundError("Failed to save encryption key");
    }
    getEncKeyBuffer(out);
    out.close();
}

void KeyPackData::getEncKeyBuffer(std::ostream &os) const {
    if (!enc_loaded_) {
        throw evi::KeyNotLoadedError("Encryption key is not loaded to be saved");
    }
    std::string preset_str = utils::assignParameterString(context_->getParam()->getPreset());
    preset_str.resize(4, '\0');
    char byte = 0x02;
    os.write(&byte, sizeof(byte));
    os.write(preset_str.data(), preset_str.size());
    serialization::writeHeader(os, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(context_->getParam()->getPrimeQ());
    const uint8_t p_bits = serialization::bitLengthU64(context_->getParam()->getPrimeP());
    os.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    os.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    serialization::writePackedU64(os, enckey->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, enckey->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePackedU64(os, enckey->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, enckey->getPolyData(0, 1), DEGREE, p_bits);
}

void KeyPackData::getEvalKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_relin_key, out);
    // deb::serializeToStream(deb_mod_pack_key, out);
    char byte = 0x03;
    out.write(&byte, sizeof(byte));
    serialization::writeHeader(out, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(context_->getParam()->getPrimeQ());
    const uint8_t p_bits = serialization::bitLengthU64(context_->getParam()->getPrimeP());
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    // preset, dim, eval
    if (context_->getEvalMode() == EvalMode::SINGLE) {
        serialization::writePackedU64(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);

    } else if (!CHECK_MM(context_->getEvalMode())) {
        serialization::writePackedU64(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::writePackedU64(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
        serialization::writePackedU64(out, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::writePackedU64(out, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::writePackedU64(out, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::writePackedU64(out, mod_pack_key->getPolyData(0, 1), count, p_bits);
    } else {
        const auto num_p = utils::getDebNumP(context_);
        const auto gadget_rank = utils::getDebGadgetRank(context_);
        const auto poly_count = num_p * gadget_rank;
        const auto *primes = utils::getDebPrimes(context_);
        std::vector<uint8_t> p_bits_list(num_p);
        for (deb::Size j = 0; j < num_p; ++j) {
            p_bits_list[j] = serialization::bitLengthU64(primes[j]);
        }
        const uint32_t num_p_u32 = static_cast<uint32_t>(num_p);
        out.write(reinterpret_cast<const char *>(&num_p_u32), sizeof(num_p_u32));
        out.write(reinterpret_cast<const char *>(p_bits_list.data()), p_bits_list.size());

        for (int i = 0; i < key_switching_key.size(); i++) {
            auto &key = key_switching_key[i];
            key->setSize(DEGREE * poly_count);
            for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                for (deb::Size pj = 0; pj < num_p; ++pj) {
                    const std::size_t idx = (gi * num_p + pj) * DEGREE;
                    const uint8_t bits = p_bits_list[pj];
                    serialization::writePackedU64(out, key->getPolyData(1, 0) + idx, DEGREE, bits);
                    serialization::writePackedU64(out, key->getPolyData(0, 0) + idx, DEGREE, bits);
                }
            }
        }
        // MMS: store num_shared_secret + key flags + shared-A keys after switching keys
        const int32_t nss = num_shared_secret;
        out.write(reinterpret_cast<const char *>(&nss), sizeof(nss));
        if (nss > 0) {
            // Format flags: bit 0 = backward swk, bit 1 = cc backward, bit 2 = forward key
            uint8_t key_flags = 0;
            if (shared_a_mod_pack_loaded_) {
                key_flags |= 0x01;
            }
            if (cc_shared_a_mod_pack_loaded_) {
                key_flags |= 0x02;
            }
            if (shared_a_key_loaded_) {
                key_flags |= 0x04;
            }
            out.write(reinterpret_cast<const char *>(&key_flags), sizeof(key_flags));

            if (key_flags & 0x01) {
                // Backward key: nss simple QP switching keys (s_i → s)
                // Each key has 1 poly per channel, nss keys total
                const uint32_t bwd_count = static_cast<uint32_t>(nss);
                out.write(reinterpret_cast<const char *>(&bwd_count), sizeof(bwd_count));
                const std::size_t count = static_cast<std::size_t>(nss) * DEGREE;
                serialization::writePackedU64(out, shared_a_mod_pack_key->getPolyData(1, 0), count, q_bits);
                serialization::writePackedU64(out, shared_a_mod_pack_key->getPolyData(1, 1), count, p_bits);
                serialization::writePackedU64(out, shared_a_mod_pack_key->getPolyData(0, 0), count, q_bits);
                serialization::writePackedU64(out, shared_a_mod_pack_key->getPolyData(0, 1), count, p_bits);
            }
            if (key_flags & 0x02) {
                const std::size_t sa_count = static_cast<std::size_t>(nss) * DEGREE;
                serialization::writePackedU64(out, cc_shared_a_mod_pack_key->getPolyData(1, 0), sa_count, q_bits);
                serialization::writePackedU64(out, cc_shared_a_mod_pack_key->getPolyData(1, 1), sa_count, p_bits);
                serialization::writePackedU64(out, cc_shared_a_mod_pack_key->getPolyData(0, 0), sa_count, q_bits);
                serialization::writePackedU64(out, cc_shared_a_mod_pack_key->getPolyData(0, 1), sa_count, p_bits);
            }
            if (key_flags & 0x04) {
                // Legacy forward conversion key (RMS format)
                const std::size_t fwd_b = static_cast<std::size_t>(nss) * nss * DEGREE;
                const std::size_t fwd_a = static_cast<std::size_t>(nss) * DEGREE;
                serialization::writePackedU64(out, shared_a_key->getPolyData(0, 0), fwd_b, q_bits);
                serialization::writePackedU64(out, shared_a_key->getPolyData(0, 1), fwd_b, p_bits);
                serialization::writePackedU64(out, shared_a_key->getPolyData(1, 0), fwd_a, q_bits);
                serialization::writePackedU64(out, shared_a_key->getPolyData(1, 1), fwd_a, p_bits);

                // QPR: R-channel data for forward key
                const uint8_t has_r = shared_a_key_r_a.empty() ? 0 : 1;
                out.write(reinterpret_cast<const char *>(&has_r), sizeof(has_r));
                if (has_r) {
                    out.write(reinterpret_cast<const char *>(&r_prime_), sizeof(r_prime_));
                    const uint8_t r_bits = serialization::bitLengthU64(r_prime_);
                    out.write(reinterpret_cast<const char *>(&r_bits), sizeof(r_bits));
                    serialization::writePackedU64(out, shared_a_key_r_a.data(), fwd_a, r_bits);
                    serialization::writePackedU64(out, shared_a_key_r_b.data(), fwd_b, r_bits);
                }
            }
            // MMS deb QPR forward keys (independent of legacy flag 0x04)
            {
                const uint8_t has_deb_fwd = shared_a_fwd_keys.empty() ? 0 : 1;
                out.write(reinterpret_cast<const char *>(&has_deb_fwd), sizeof(has_deb_fwd));
                if (has_deb_fwd) {
                    const auto deb_preset_val = utils::getDebPreset(context_);
                    const auto deb_gr = deb::get_gadget_rank(deb_preset_val);
                    const auto deb_np = deb::get_num_p(deb_preset_val);
                    const auto *deb_p = deb::get_primes(deb_preset_val);
                    for (int s = 0; s < nss; ++s) {
                        for (deb::Size d = 0; d < deb_gr; ++d) {
                            for (deb::Size p = 0; p < deb_np; ++p) {
                                const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                serialization::writePackedU64(out, shared_a_fwd_keys[s].ax(d)[p].data(), DEGREE, bits);
                                serialization::writePackedU64(out, shared_a_fwd_keys[s].bx(d)[p].data(), DEGREE, bits);
                            }
                        }
                    }
                    // Off-diagonal keys (nss*nss entries)
                    for (int idx = 0; idx < nss * nss; ++idx) {
                        for (deb::Size d = 0; d < deb_gr; ++d) {
                            for (deb::Size p = 0; p < deb_np; ++p) {
                                const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                serialization::writePackedU64(out, shared_a_off_diag_keys[idx].bx(d)[p].data(), DEGREE,
                                                              bits);
                            }
                        }
                    }
                    // Backward L0 keys (nss entries, 4 polyvecs each).
                    // Bit width matches the backward key target primes, which are
                    // preset-dependent (IP1/MMS→IP0, IP2/MMS→IP2). Do NOT hardcode
                    // to IP0 — IP2 keys fit in 32 bits so using IP0 widths (51/55)
                    // would inflate storage ~60%, and a future preset with P>51bit
                    // would silently truncate.
                    const uint8_t bwd_q_bits = serialization::bitLengthU64(context_->getParam()->getBackwardKeyQ());
                    const uint8_t bwd_p_bits = serialization::bitLengthU64(context_->getParam()->getBackwardKeyP());
                    for (int j = 0; j < nss; ++j) {
                        serialization::writePackedU64(out, shared_a_bwd_l0_keys[j].ax_q.data(), DEGREE, bwd_q_bits);
                        serialization::writePackedU64(out, shared_a_bwd_l0_keys[j].ax_p.data(), DEGREE, bwd_p_bits);
                        serialization::writePackedU64(out, shared_a_bwd_l0_keys[j].bx_q.data(), DEGREE, bwd_q_bits);
                        serialization::writePackedU64(out, shared_a_bwd_l0_keys[j].bx_p.data(), DEGREE, bwd_p_bits);
                    }
                }
            }
        }
    }
}

void KeyPackData::getModPackKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }
    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_mod_pack_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    serialization::writeHeader(out, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(context_->getParam()->getPrimeQ());
    const uint8_t p_bits = serialization::bitLengthU64(context_->getParam()->getPrimeP());
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
    serialization::writePackedU64(out, mod_pack_key->getPolyData(1, 0), count, q_bits);
    serialization::writePackedU64(out, mod_pack_key->getPolyData(1, 1), count, p_bits);
    serialization::writePackedU64(out, mod_pack_key->getPolyData(0, 0), count, q_bits);
    serialization::writePackedU64(out, mod_pack_key->getPolyData(0, 1), count, p_bits);
}

void KeyPackData::getRelinKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_relin_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    serialization::writeHeader(out, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(context_->getParam()->getPrimeQ());
    const uint8_t p_bits = serialization::bitLengthU64(context_->getParam()->getPrimeP());
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    serialization::writePackedU64(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePackedU64(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePackedU64(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePackedU64(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);
}

void KeyPackData::saveEvalKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getEvalKeyBuffer(out);
    out.close();
}

void KeyPackData::saveRelinKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getRelinKeyBuffer(out);
    out.close();
}

void KeyPackData::saveModPackKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getModPackKeyBuffer(out);
    out.close();
}

void KeyPackData::serialize(std::ostream &os) const {
    if (os.fail()) {
        throw evi::EviError("Failed to open stream");
    }

    serialization::writeHeader(os, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(context_->getParam()->getPrimeQ());
    const uint8_t p_bits = serialization::bitLengthU64(context_->getParam()->getPrimeP());
    os.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    os.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    // deb::serializeToStream(deb_relin_key, os);
    // deb::serializeToStream(deb_mod_pack_key, os);
    os.write(reinterpret_cast<const char *>(&enc_loaded_), sizeof(bool));
    serialization::writePackedU64(os, enckey->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, enckey->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePackedU64(os, enckey->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, enckey->getPolyData(0, 1), DEGREE, p_bits);
    os.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    serialization::writePackedU64(os, relin_key->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, relin_key->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePackedU64(os, relin_key->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePackedU64(os, relin_key->getPolyData(0, 1), DEGREE, p_bits);
    const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
    serialization::writePackedU64(os, mod_pack_key->getPolyData(1, 0), count, q_bits);
    serialization::writePackedU64(os, mod_pack_key->getPolyData(1, 1), count, p_bits);
    serialization::writePackedU64(os, mod_pack_key->getPolyData(0, 0), count, q_bits);
    serialization::writePackedU64(os, mod_pack_key->getPolyData(0, 1), count, p_bits);
}

void KeyPackData::deserialize(std::istream &is) {
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported keypack serialization version");
    }
    uint8_t q_bits = 0;
    uint8_t p_bits = 0;
    if (header.has_header) {
        is.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        is.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
    }

    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_enc_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_enc_key, enckey);
    // enc_loaded_ = true;
    is.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    if (header.has_header) {
        serialization::readPackedU64(is, enckey->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, enckey->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPackedU64(is, enckey->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, enckey->getPolyData(0, 1), DEGREE, p_bits);
    } else {
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    }
    utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);

    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    if (header.has_header) {
        serialization::readPackedU64(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
        serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
    } else {
        is.read(reinterpret_cast<char *>(relin_key->getPolyData(1, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(relin_key->getPolyData(1, 1)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(relin_key->getPolyData(0, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(relin_key->getPolyData(0, 1)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
    }
    utils::syncVarKeyToDebSwkKey(context_, relin_key, deb_relin_key);
    utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
}

void KeyPackData::loadEncKeyFile(const std::string &path) {
    fs::path input(path);
    fs::path target = input;
    if (fs::is_directory(input) || (!fs::is_regular_file(input) && input.extension() != ".bin")) {
        target = input / "EncKey.bin";
    }
    std::ifstream in(target, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load encryption key");
    }
    loadEncKeyBuffer(in);
    in.close();
}

void KeyPackData::loadEncKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_enc_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_enc_key, enckey);
    // enc_loaded_ = true;
    char preset_buf[4];
    is.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    is.read(preset_buf, sizeof(preset_buf));
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported encryption key serialization version");
    }
    if (header.has_header) {
        uint8_t q_bits = 0;
        uint8_t p_bits = 0;
        is.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        is.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
        serialization::readPackedU64(is, enckey->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, enckey->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPackedU64(is, enckey->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, enckey->getPolyData(0, 1), DEGREE, p_bits);
    } else {
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    }
    utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);
    enc_loaded_ = true;
}

void KeyPackData::loadEvalKeyFile(const std::string &path, EvalKeyComponents components) {
    // Save components in thread-local-like storage? No — simpler: call the
    // buffer loader directly on the raw file/bundle path. We replicate the
    // dispatch logic from loadEvalKeyFile(path) but pass components through.
    fs::path input(path);

    auto select_eval_key_file = [&](const fs::path &dir_path) {
        fs::path expected = dir_path / ("EVIKeys" + std::to_string(context_->getPadRank()) + ".bin");
        if (fs::exists(expected) ||
            (context_->getEvalMode() != EvalMode::SINGLE && !CHECK_MM(context_->getEvalMode()))) {
            return expected;
        }
        if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
            for (const auto &entry : fs::directory_iterator(dir_path)) {
                const fs::path &candidate = entry.path();
                if (entry.is_regular_file() && candidate.extension() == ".bin" &&
                    candidate.filename().string().rfind("EVIKeys", 0) == 0) {
                    return candidate;
                }
            }
        }
        return expected;
    };

    std::function<void(const fs::path &)> handle_eval_bundle = [&](const fs::path &bundle_path) {
        fs::path base_dir = bundle_path.parent_path().empty() ? fs::path(".") : bundle_path.parent_path();
        fs::path dump_dir = base_dir / "dump";
        utils::deserializeEvalKey(bundle_path.string(), dump_dir.string(), false);
        loadEvalKeyFile(select_eval_key_file(dump_dir).string(), components);
        fs::remove_all(dump_dir);
    };

    auto load_raw_file = [&](const fs::path &file_path) {
        std::ifstream in(file_path, std::ios::in | std::ios_base::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("Failed to load evaluation key" + file_path.string());
        }

        bool is_bundle = false;
        int first = in.peek();
        if (first == 'D' || first == 'F') {
            is_bundle = true;
        } else {
            auto header = serialization::readHeader(in);
            if (header.has_header) {
                int next = in.peek();
                if (next == 'D' || next == 'F') {
                    is_bundle = true;
                }
            }
        }

        in.clear();
        in.seekg(0, std::ios::beg);
        if (is_bundle) {
            in.close();
            handle_eval_bundle(file_path);
            return;
        }

        loadEvalKeyBuffer(in, components);
        in.close();
    };

    if (fs::is_directory(input) || (!fs::exists(input) && !input.has_extension())) {
        fs::path &base_dir = input;
        fs::path bundle = base_dir / "EvalKey.bin";
        if (fs::exists(bundle)) {
            handle_eval_bundle(bundle);
            return;
        }
        load_raw_file(select_eval_key_file(base_dir));
        return;
    }

    if (fs::is_regular_file(input)) {
        load_raw_file(input);
        return;
    }

    if (input.has_extension()) {
        load_raw_file(input);
        return;
    }
    load_raw_file(select_eval_key_file(input));
}

void KeyPackData::loadEvalKeyFile(const std::string &path) {
    loadEvalKeyFile(path, EvalKeyComponents::All);
}

void KeyPackData::loadEvalKeyBuffer(std::istream &is) {
    loadEvalKeyBuffer(is, EvalKeyComponents::All);
}

void KeyPackData::loadEvalKeyBuffer(std::istream &is, EvalKeyComponents components) {
    const bool load_relin = hasComponent(components, EvalKeyComponents::Relin);
    const bool load_modpack = hasComponent(components, EvalKeyComponents::ModPack);
    const bool load_transpose = hasComponent(components, EvalKeyComponents::Transpose);
    const bool load_fwd = hasComponent(components, EvalKeyComponents::SharedAFwd);
    const bool load_bwd = hasComponent(components, EvalKeyComponents::SharedABwd);

    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported evaluation key serialization version");
    }
    uint8_t q_bits = 0;
    uint8_t p_bits = 0;
    if (header.has_header) {
        is.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        is.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
    }

    if (context_->getEvalMode() == EvalMode::SINGLE) {
        if (load_relin) {
            if (header.has_header) {
                serialization::readPackedU64(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
            } else {
                is.read((char *)relin_key->getPolyData(1, 0), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(1, 1), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(0, 0), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(0, 1), U64_DEGREE);
            }
            utils::syncVarKeyToDebSwkKey(context_, relin_key, deb_relin_key);
        } else {
            if (header.has_header) {
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
            } else {
                is.seekg(4 * U64_DEGREE, std::ios::cur);
            }
        }
    } else if (!CHECK_MM(context_->getEvalMode())) {
        if (header.has_header) {
            if (load_relin) {
                serialization::readPackedU64(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
                serialization::readPackedU64(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
            } else {
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
            }
            const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
            if (load_modpack) {
                serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
                serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
                serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
                serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
            } else {
                serialization::skipPackedU64(is, count, q_bits);
                serialization::skipPackedU64(is, count, p_bits);
                serialization::skipPackedU64(is, count, q_bits);
                serialization::skipPackedU64(is, count, p_bits);
            }
        } else {
            if (load_relin) {
                is.read((char *)relin_key->getPolyData(1, 0), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(1, 1), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(0, 0), U64_DEGREE);
                is.read((char *)relin_key->getPolyData(0, 1), U64_DEGREE);
            } else {
                is.seekg(4 * U64_DEGREE, std::ios::cur);
            }
            if (load_modpack) {
                is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
                is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
                is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
                is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
            } else {
                is.seekg(4 * U64_DEGREE * context_->getPadRank(), std::ios::cur);
            }
        }
        if (load_relin) {
            utils::syncVarKeyToDebSwkKey(context_, relin_key, deb_relin_key);
        }
        if (load_modpack) {
            utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
        }
    } else {
        const auto num_p = utils::getDebNumP(context_);
        const auto gadget_rank = utils::getDebGadgetRank(context_);
        const auto poly_count = num_p * gadget_rank;
        std::vector<uint8_t> p_bits_list;
        if (header.has_header) {
            uint32_t num_p_u32 = 0;
            is.read(reinterpret_cast<char *>(&num_p_u32), sizeof(num_p_u32));
            if (num_p_u32 != static_cast<uint32_t>(num_p)) {
                throw evi::NotSupportedError("Evaluation key prime count mismatch");
            }
            p_bits_list.resize(num_p);
            is.read(reinterpret_cast<char *>(p_bits_list.data()), p_bits_list.size());
        }

        if (load_transpose) {
            key_switching_key.resize(DEGREE);
            for (int i = 0; i < DEGREE; i++) {
                auto &key = key_switching_key[i];
                key->setSize(DEGREE * poly_count);
                if (header.has_header) {
                    for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                        for (deb::Size pj = 0; pj < num_p; ++pj) {
                            const std::size_t idx = (gi * num_p + pj) * DEGREE;
                            const uint8_t bits = p_bits_list[pj];
                            serialization::readPackedU64(is, key->getPolyData(1, 0) + idx, DEGREE, bits);
                            serialization::readPackedU64(is, key->getPolyData(0, 0) + idx, DEGREE, bits);
                        }
                    }
                } else {
                    is.read(reinterpret_cast<char *>(key->getPolyData(1, 0)), U64_DEGREE * poly_count);
                    is.read(reinterpret_cast<char *>(key->getPolyData(0, 0)), U64_DEGREE * poly_count);
                }
            }
        } else {
            // Skip transpose keys (DEGREE switch keys, each with num_p*gadget_rank polys per a/b).
            // This is the dominant memory consumer (~768MB for IP1 DEGREE=4096).
            for (int i = 0; i < DEGREE; i++) {
                if (header.has_header) {
                    for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                        for (deb::Size pj = 0; pj < num_p; ++pj) {
                            const uint8_t bits = p_bits_list[pj];
                            serialization::skipPackedU64(is, DEGREE, bits);
                            serialization::skipPackedU64(is, DEGREE, bits);
                        }
                    }
                } else {
                    is.seekg(static_cast<std::streamoff>(2 * U64_DEGREE * poly_count), std::ios::cur);
                }
            }
        }
        // MMS: read num_shared_secret + key flags + shared-A keys after switching keys
        int32_t nss = 0;
        if (is.read(reinterpret_cast<char *>(&nss), sizeof(nss))) {
            num_shared_secret = nss;
            if (nss > 0) {
                uint8_t key_flags = 0;
                is.read(reinterpret_cast<char *>(&key_flags), sizeof(key_flags));

                if (key_flags & 0x01) {
                    // Read backward key: nss simple QP switching keys
                    uint32_t bwd_count = 0;
                    is.read(reinterpret_cast<char *>(&bwd_count), sizeof(bwd_count));
                    const std::size_t count = static_cast<std::size_t>(bwd_count) * DEGREE;
                    if (load_fwd) {
                        shared_a_mod_pack_key->setSize(count);
                        serialization::readPackedU64(is, shared_a_mod_pack_key->getPolyData(1, 0), count, q_bits);
                        serialization::readPackedU64(is, shared_a_mod_pack_key->getPolyData(1, 1), count, p_bits);
                        serialization::readPackedU64(is, shared_a_mod_pack_key->getPolyData(0, 0), count, q_bits);
                        serialization::readPackedU64(is, shared_a_mod_pack_key->getPolyData(0, 1), count, p_bits);
                        shared_a_mod_pack_loaded_ = true;
                    } else {
                        serialization::skipPackedU64(is, count, q_bits);
                        serialization::skipPackedU64(is, count, p_bits);
                        serialization::skipPackedU64(is, count, q_bits);
                        serialization::skipPackedU64(is, count, p_bits);
                    }
                }
                if (key_flags & 0x02) {
                    const std::size_t sa_count = static_cast<std::size_t>(nss) * DEGREE;
                    if (load_fwd) {
                        cc_shared_a_mod_pack_key->setSize(sa_count);
                        serialization::readPackedU64(is, cc_shared_a_mod_pack_key->getPolyData(1, 0), sa_count, q_bits);
                        serialization::readPackedU64(is, cc_shared_a_mod_pack_key->getPolyData(1, 1), sa_count, p_bits);
                        serialization::readPackedU64(is, cc_shared_a_mod_pack_key->getPolyData(0, 0), sa_count, q_bits);
                        serialization::readPackedU64(is, cc_shared_a_mod_pack_key->getPolyData(0, 1), sa_count, p_bits);
                        cc_shared_a_mod_pack_loaded_ = true;
                    } else {
                        serialization::skipPackedU64(is, sa_count, q_bits);
                        serialization::skipPackedU64(is, sa_count, p_bits);
                        serialization::skipPackedU64(is, sa_count, q_bits);
                        serialization::skipPackedU64(is, sa_count, p_bits);
                    }
                }
                if (key_flags & 0x04) {
                    const std::size_t fwd_b = static_cast<std::size_t>(nss) * nss * DEGREE;
                    const std::size_t fwd_a = static_cast<std::size_t>(nss) * DEGREE;
                    if (load_fwd) {
                        shared_a_key->setSize(fwd_b, fwd_a);
                        serialization::readPackedU64(is, shared_a_key->getPolyData(0, 0), fwd_b, q_bits);
                        serialization::readPackedU64(is, shared_a_key->getPolyData(0, 1), fwd_b, p_bits);
                        serialization::readPackedU64(is, shared_a_key->getPolyData(1, 0), fwd_a, q_bits);
                        serialization::readPackedU64(is, shared_a_key->getPolyData(1, 1), fwd_a, p_bits);
                        shared_a_key_loaded_ = true;
                    } else {
                        serialization::skipPackedU64(is, fwd_b, q_bits);
                        serialization::skipPackedU64(is, fwd_b, p_bits);
                        serialization::skipPackedU64(is, fwd_a, q_bits);
                        serialization::skipPackedU64(is, fwd_a, p_bits);
                    }

                    // QPR: R-channel data for forward key
                    uint8_t has_r = 0;
                    if (is.read(reinterpret_cast<char *>(&has_r), sizeof(has_r)) && has_r) {
                        is.read(reinterpret_cast<char *>(&r_prime_), sizeof(r_prime_));
                        uint8_t r_bits = 0;
                        is.read(reinterpret_cast<char *>(&r_bits), sizeof(r_bits));
                        if (load_fwd) {
                            shared_a_key_r_a.resize(fwd_a);
                            shared_a_key_r_b.resize(fwd_b);
                            serialization::readPackedU64(is, shared_a_key_r_a.data(), fwd_a, r_bits);
                            serialization::readPackedU64(is, shared_a_key_r_b.data(), fwd_b, r_bits);
                        } else {
                            serialization::skipPackedU64(is, fwd_a, r_bits);
                            serialization::skipPackedU64(is, fwd_b, r_bits);
                        }
                    }
                }
                // MMS deb QPR forward keys (independent of legacy flag 0x04)
                {
                    uint8_t has_deb_fwd = 0;
                    if (is.read(reinterpret_cast<char *>(&has_deb_fwd), sizeof(has_deb_fwd)) && has_deb_fwd) {
                        const auto deb_preset_val = utils::getDebPreset(context_);
                        const auto deb_gr = deb::get_gadget_rank(deb_preset_val);
                        const auto deb_np = deb::get_num_p(deb_preset_val);
                        const auto *deb_p = deb::get_primes(deb_preset_val);

                        if (load_fwd) {
                            shared_a_fwd_keys.clear();
                            for (int s = 0; s < nss; ++s) {
                                shared_a_fwd_keys.emplace_back(deb_preset_val, deb::SWK_AUTO);
                                for (deb::Size d = 0; d < deb_gr; ++d) {
                                    for (deb::Size p = 0; p < deb_np; ++p) {
                                        const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                        serialization::readPackedU64(is, shared_a_fwd_keys[s].ax(d)[p].data(), DEGREE,
                                                                     bits);
                                        serialization::readPackedU64(is, shared_a_fwd_keys[s].bx(d)[p].data(), DEGREE,
                                                                     bits);
                                    }
                                }
                            }
                        } else {
                            for (int s = 0; s < nss; ++s) {
                                for (deb::Size d = 0; d < deb_gr; ++d) {
                                    for (deb::Size p = 0; p < deb_np; ++p) {
                                        const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                        serialization::skipPackedU64(is, DEGREE, bits);
                                        serialization::skipPackedU64(is, DEGREE, bits);
                                    }
                                }
                            }
                        }

                        if (load_fwd) {
                            shared_a_off_diag_keys.clear();
                            for (int idx = 0; idx < nss * nss; ++idx) {
                                shared_a_off_diag_keys.emplace_back(deb_preset_val, deb::SWK_AUTO);
                                for (deb::Size d = 0; d < deb_gr; ++d) {
                                    for (deb::Size p = 0; p < deb_np; ++p) {
                                        const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                        serialization::readPackedU64(is, shared_a_off_diag_keys[idx].bx(d)[p].data(),
                                                                     DEGREE, bits);
                                    }
                                }
                            }
                        } else {
                            for (int idx = 0; idx < nss * nss; ++idx) {
                                for (deb::Size d = 0; d < deb_gr; ++d) {
                                    for (deb::Size p = 0; p < deb_np; ++p) {
                                        const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                        serialization::skipPackedU64(is, DEGREE, bits);
                                    }
                                }
                            }
                        }

                        // Backward L0 key bit width matches the target preset
                        // from Parameter::getBackwardKey{Q,P}(). Must match the
                        // writer side exactly — see KeyPackImpl.cpp save path.
                        const uint8_t bwd_q_bits = serialization::bitLengthU64(context_->getParam()->getBackwardKeyQ());
                        const uint8_t bwd_p_bits = serialization::bitLengthU64(context_->getParam()->getBackwardKeyP());
                        if (load_bwd) {
                            shared_a_bwd_l0_keys.resize(nss);
                            for (int j = 0; j < nss; ++j) {
                                shared_a_bwd_l0_keys[j].ax_q.resize(DEGREE);
                                shared_a_bwd_l0_keys[j].ax_p.resize(DEGREE);
                                shared_a_bwd_l0_keys[j].bx_q.resize(DEGREE);
                                shared_a_bwd_l0_keys[j].bx_p.resize(DEGREE);
                                serialization::readPackedU64(is, shared_a_bwd_l0_keys[j].ax_q.data(), DEGREE,
                                                             bwd_q_bits);
                                serialization::readPackedU64(is, shared_a_bwd_l0_keys[j].ax_p.data(), DEGREE,
                                                             bwd_p_bits);
                                serialization::readPackedU64(is, shared_a_bwd_l0_keys[j].bx_q.data(), DEGREE,
                                                             bwd_q_bits);
                                serialization::readPackedU64(is, shared_a_bwd_l0_keys[j].bx_p.data(), DEGREE,
                                                             bwd_p_bits);
                            }
                        } else {
                            for (int j = 0; j < nss; ++j) {
                                serialization::skipPackedU64(is, DEGREE, bwd_q_bits);
                                serialization::skipPackedU64(is, DEGREE, bwd_p_bits);
                                serialization::skipPackedU64(is, DEGREE, bwd_q_bits);
                                serialization::skipPackedU64(is, DEGREE, bwd_p_bits);
                            }
                        }
                    }
                }
            }
        }
    }
    eval_loaded_ = true;
}

void KeyPackData::loadRelinKeyFile(const std::string &path) {
    std::ifstream in(path, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load evaluation key");
    }
    loadRelinKeyBuffer(in);
    in.close();
}

void KeyPackData::loadRelinKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported relin key serialization version");
    }
    if (header.has_header) {
        uint8_t q_bits = 0;
        uint8_t p_bits = 0;
        is.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        is.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
        serialization::readPackedU64(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPackedU64(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
    } else {
        is.read((char *)relin_key->getPolyData(1, 0), U64_DEGREE);
        is.read((char *)relin_key->getPolyData(1, 1), U64_DEGREE);
        is.read((char *)relin_key->getPolyData(0, 0), U64_DEGREE);
        is.read((char *)relin_key->getPolyData(0, 1), U64_DEGREE);
    }
    utils::syncVarKeyToDebSwkKey(context_, relin_key, deb_relin_key);
    eval_loaded_ = true;
}

void KeyPackData::loadModPackKeyFile(const std::string &path) {
    std::ifstream in(path, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load evaluation key");
    }
    loadModPackKeyBuffer(in);
    in.close();
}

void KeyPackData::loadModPackKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw evi::NotSupportedError("Unsupported modpack key serialization version");
    }
    if (header.has_header) {
        uint8_t q_bits = 0;
        uint8_t p_bits = 0;
        is.read(reinterpret_cast<char *>(&q_bits), sizeof(q_bits));
        is.read(reinterpret_cast<char *>(&p_bits), sizeof(p_bits));
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
        serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::readPackedU64(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
    } else {
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
        is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
    }
    utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
    eval_loaded_ = true;
}

void KeyPackData::save(const std::string &path) {
    saveEncKeyFile(path + "/EncKey.bin");
    saveEvalKeyFile(path + "/EVIKeys.bin");
}

KeyPack makeKeyPack(const Context &context) {
    return std::make_shared<KeyPackData>(context);
}

KeyPack makeKeyPack(const Context &context, std::istream &in) {
    return std::make_shared<KeyPackData>(context, in);
}

KeyPack makeKeyPack(const Context &context, const std::string &dir_path) {
    return std::make_shared<KeyPackData>(context, dir_path);
}

} // namespace detail
} // namespace evi
