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
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <type_traits>
#include <vector>

using json = nlohmann::json;

namespace evi {
namespace detail {

// Backward L0 key u32/u64 routing is preset==IP3 (the IP2->u64 demotion
// invariant: u32 storage <=> IP3). Do not add a file-local width-based
// helper; gate on preset==IP3 (read-side) or std::visit the stored variant
// (write-side).

// Reads one transpose (key-switching) key into an already-sized
// Matrix<CIPHER, T>. The caller decides T via the preset==IP3 gate (u32) or
// u64 default and then dispatches here; this helper only performs the width-
// parameterized populate, so it does not itself route on width. The header
// (bit-packed) path is identical for u32/u64 apart from T; only the legacy
// (pre-header) wire — which is always u64-on-disk — differs and is selected
// via if constexpr (raw read for u64, widen-copy for u32).
template <class T>
void readTransposeKeyInto(std::istream &is, Matrix<DataType::CIPHER, T> &key, bool has_header, deb::Size gadget_rank,
                          deb::Size num_p, const std::vector<uint8_t> &p_bits_list, std::size_t poly_count) {
    if (has_header) {
        for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
            for (deb::Size pj = 0; pj < num_p; ++pj) {
                const std::size_t idx = (gi * num_p + pj) * DEGREE;
                const uint8_t bits = p_bits_list[pj];
                serialization::readPacked<T>(is, key.getPolyData(1, 0) + idx, DEGREE, bits);
                serialization::readPacked<T>(is, key.getPolyData(0, 0) + idx, DEGREE, bits);
            }
        }
    } else if constexpr (std::is_same_v<T, u64>) {
        is.read(reinterpret_cast<char *>(key.getPolyData(1, 0)), U64_DEGREE * poly_count);
        is.read(reinterpret_cast<char *>(key.getPolyData(0, 0)), U64_DEGREE * poly_count);
    } else {
        // Legacy wire stores u64; widen each DEGREE poly into the u32 key.
        std::vector<u64> scratch(DEGREE);
        for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
            for (deb::Size pj = 0; pj < num_p; ++pj) {
                const std::size_t idx = (gi * num_p + pj) * DEGREE;
                is.read(reinterpret_cast<char *>(scratch.data()), U64_DEGREE);
                std::copy_n(scratch.data(), DEGREE, key.getPolyData(1, 0) + idx);
                is.read(reinterpret_cast<char *>(scratch.data()), U64_DEGREE);
                std::copy_n(scratch.data(), DEGREE, key.getPolyData(0, 0) + idx);
            }
        }
    }
}

KeyPackData::KeyPackData(const Context &context)
    : context_(context), deb_enc_key(utils::getDebPreset(context), deb::SWK_ENC),
      deb_relin_key(utils::getDebPreset(context), deb::SWK_MULT),
      deb_mod_pack_key(utils::getDebPreset(context), deb::SWK_MODPACK_SELF) {
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
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 1));
    os.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    os.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    writeEncKeyPacked(os, q_bits, p_bits);
}

void KeyPackData::writeEncKeyPacked(std::ostream &os, uint8_t q_bits, uint8_t p_bits) const {
    if (deb_enc_key32) {
        // u32-native (IP3): pack straight from the u32 key. writePacked<u32>
        // emits the same bytes as writePacked<u64> for these widths, so the
        // file is interchangeable with the u64 path.
        auto &k = *deb_enc_key32;
        serialization::writePacked<u32>(os, k.ax(0)[0].data(), DEGREE, q_bits);
        serialization::writePacked<u32>(os, k.ax(0)[1].data(), DEGREE, p_bits);
        serialization::writePacked<u32>(os, k.bx(0)[0].data(), DEGREE, q_bits);
        serialization::writePacked<u32>(os, k.bx(0)[1].data(), DEGREE, p_bits);
        return;
    }
    serialization::writePacked<u64>(os, enckey->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(os, enckey->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePacked<u64>(os, enckey->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(os, enckey->getPolyData(0, 1), DEGREE, p_bits);
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
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 1));
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    // preset, dim, eval
    if (context_->getEvalMode() == EvalMode::SINGLE) {
        serialization::writePacked<u64>(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);

    } else if (!CHECK_MM(context_->getEvalMode())) {
        serialization::writePacked<u64>(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::writePacked<u64>(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
        serialization::writePacked<u64>(out, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::writePacked<u64>(out, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::writePacked<u64>(out, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::writePacked<u64>(out, mod_pack_key->getPolyData(0, 1), count, p_bits);
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
            std::visit(
                [&](const auto &typed_key) {
                    using Ptr = std::decay_t<decltype(typed_key)>;
                    using Value = std::conditional_t<std::is_same_v<Ptr, KeyPackData::TransposeKey32>, u32, u64>;
                    const auto *a_q = typed_key->getPolyData(1, 0);
                    const auto *b_q = typed_key->getPolyData(0, 0);
                    for (deb::Size gi = 0; gi < gadget_rank; ++gi) {
                        for (deb::Size pj = 0; pj < num_p; ++pj) {
                            const std::size_t idx = (gi * num_p + pj) * DEGREE;
                            const uint8_t bits = p_bits_list[pj];
                            serialization::writePacked<Value>(out, a_q + idx, DEGREE, bits);
                            serialization::writePacked<Value>(out, b_q + idx, DEGREE, bits);
                        }
                    }
                },
                key);
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
                serialization::writePacked<u64>(out, shared_a_mod_pack_key->getPolyData(1, 0), count, q_bits);
                serialization::writePacked<u64>(out, shared_a_mod_pack_key->getPolyData(1, 1), count, p_bits);
                serialization::writePacked<u64>(out, shared_a_mod_pack_key->getPolyData(0, 0), count, q_bits);
                serialization::writePacked<u64>(out, shared_a_mod_pack_key->getPolyData(0, 1), count, p_bits);
            }
            if (key_flags & 0x02) {
                const std::size_t sa_count = static_cast<std::size_t>(nss) * DEGREE;
                serialization::writePacked<u64>(out, cc_shared_a_mod_pack_key->getPolyData(1, 0), sa_count, q_bits);
                serialization::writePacked<u64>(out, cc_shared_a_mod_pack_key->getPolyData(1, 1), sa_count, p_bits);
                serialization::writePacked<u64>(out, cc_shared_a_mod_pack_key->getPolyData(0, 0), sa_count, q_bits);
                serialization::writePacked<u64>(out, cc_shared_a_mod_pack_key->getPolyData(0, 1), sa_count, p_bits);
            }
            if (key_flags & 0x04) {
                // Legacy forward conversion key (RMS format)
                const std::size_t fwd_b = static_cast<std::size_t>(nss) * nss * DEGREE;
                const std::size_t fwd_a = static_cast<std::size_t>(nss) * DEGREE;
                serialization::writePacked<u64>(out, shared_a_key->getPolyData(0, 0), fwd_b, q_bits);
                serialization::writePacked<u64>(out, shared_a_key->getPolyData(0, 1), fwd_b, p_bits);
                serialization::writePacked<u64>(out, shared_a_key->getPolyData(1, 0), fwd_a, q_bits);
                serialization::writePacked<u64>(out, shared_a_key->getPolyData(1, 1), fwd_a, p_bits);

                // Reserved gating byte for the deprecated QPR R-channel
                // payload. Must remain written as 0 so older readers that
                // still consume this byte advance the stream correctly and
                // skip the (now absent) R-channel section.
                const uint8_t has_r = 0;
                out.write(reinterpret_cast<const char *>(&has_r), sizeof(has_r));
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
                                serialization::writePacked<u64>(out, shared_a_fwd_keys[s].ax(d)[p].data(), DEGREE,
                                                                bits);
                                serialization::writePacked<u64>(out, shared_a_fwd_keys[s].bx(d)[p].data(), DEGREE,
                                                                bits);
                            }
                        }
                    }
                    // Off-diagonal keys (nss*nss entries)
                    for (int idx = 0; idx < nss * nss; ++idx) {
                        for (deb::Size d = 0; d < deb_gr; ++d) {
                            for (deb::Size p = 0; p < deb_np; ++p) {
                                const uint8_t bits = serialization::bitLengthU64(deb_p[p]);
                                serialization::writePacked<u64>(out, shared_a_off_diag_keys[idx].bx(d)[p].data(),
                                                                DEGREE, bits);
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
                    // IP3 -> u32 alternative, others -> u64. Bit-packed
                    // payload is byte-identical (same width), no version bump.
                    // Branch-free: std::visit dispatches on the variant's
                    // active alternative (polyvec=u64 / polyvec32=u32) and
                    // writePacked<T> deduces T. Wire bytes are byte-identical
                    // to the explicit u32/u64 branch (same data ptr, DEGREE,
                    // and preset-driven bit width).
                    for (int j = 0; j < nss; ++j) {
                        const auto &bk = shared_a_bwd_l0_keys[j];
                        auto packF = [&](const auto &field, uint8_t bits) {
                            std::visit(
                                [&](const auto &v) {
                                    serialization::writePacked(out, v.data(), DEGREE, bits);
                                },
                                field);
                        };
                        packF(bk.ax_q, bwd_q_bits);
                        packF(bk.ax_p, bwd_p_bits);
                        packF(bk.bx_q, bwd_q_bits);
                        packF(bk.bx_p, bwd_p_bits);
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
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 1));
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
    serialization::writePacked<u64>(out, mod_pack_key->getPolyData(1, 0), count, q_bits);
    serialization::writePacked<u64>(out, mod_pack_key->getPolyData(1, 1), count, p_bits);
    serialization::writePacked<u64>(out, mod_pack_key->getPolyData(0, 0), count, q_bits);
    serialization::writePacked<u64>(out, mod_pack_key->getPolyData(0, 1), count, p_bits);
}

void KeyPackData::getRelinKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_relin_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    serialization::writeHeader(out, serialization::kVersionV1);
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 1));
    out.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    out.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    serialization::writePacked<u64>(out, relin_key->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(out, relin_key->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePacked<u64>(out, relin_key->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(out, relin_key->getPolyData(0, 1), DEGREE, p_bits);
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
    const uint8_t q_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 0));
    const uint8_t p_bits = serialization::bitLengthU64(deb_prime_at(context_->getParam(), 1));
    os.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    os.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    // deb::serializeToStream(deb_relin_key, os);
    // deb::serializeToStream(deb_mod_pack_key, os);
    os.write(reinterpret_cast<const char *>(&enc_loaded_), sizeof(bool));
    writeEncKeyPacked(os, q_bits, p_bits);
    os.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    serialization::writePacked<u64>(os, relin_key->getPolyData(1, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(os, relin_key->getPolyData(1, 1), DEGREE, p_bits);
    serialization::writePacked<u64>(os, relin_key->getPolyData(0, 0), DEGREE, q_bits);
    serialization::writePacked<u64>(os, relin_key->getPolyData(0, 1), DEGREE, p_bits);
    const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
    serialization::writePacked<u64>(os, mod_pack_key->getPolyData(1, 0), count, q_bits);
    serialization::writePacked<u64>(os, mod_pack_key->getPolyData(1, 1), count, p_bits);
    serialization::writePacked<u64>(os, mod_pack_key->getPolyData(0, 0), count, q_bits);
    serialization::writePacked<u64>(os, mod_pack_key->getPolyData(0, 1), count, p_bits);
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
    if (header.has_header && utils::isU32NativePreset(context_)) {
        // u32-native (IP3): unpack straight into the u32 enc key — no u64
        // enckey/deb_enc_key materialized. Wire is byte-identical to u64.
        deb_enc_key32.emplace(utils::getDebPreset(context_), deb::SWK_ENC);
        deb_enc_key32->addAx(2, 1);
        deb_enc_key32->addBx(2, 1);
        serialization::readPacked<u32>(is, deb_enc_key32->ax(0)[0].data(), DEGREE, q_bits);
        serialization::readPacked<u32>(is, deb_enc_key32->ax(0)[1].data(), DEGREE, p_bits);
        serialization::readPacked<u32>(is, deb_enc_key32->bx(0)[0].data(), DEGREE, q_bits);
        serialization::readPacked<u32>(is, deb_enc_key32->bx(0)[1].data(), DEGREE, p_bits);
    } else {
        if (header.has_header) {
            serialization::readPacked<u64>(is, enckey->getPolyData(1, 0), DEGREE, q_bits);
            serialization::readPacked<u64>(is, enckey->getPolyData(1, 1), DEGREE, p_bits);
            serialization::readPacked<u64>(is, enckey->getPolyData(0, 0), DEGREE, q_bits);
            serialization::readPacked<u64>(is, enckey->getPolyData(0, 1), DEGREE, p_bits);
        } else {
            is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
            is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
            is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
            is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
        }
        utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);
    }

    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    if (header.has_header) {
        serialization::readPacked<u64>(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
        const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
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
        serialization::readPacked<u64>(is, enckey->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, enckey->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPacked<u64>(is, enckey->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, enckey->getPolyData(0, 1), DEGREE, p_bits);
    } else {
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
        is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    }
    utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);
    enc_loaded_ = true;
}

bool KeyPackData::peekIsArchive(std::istream &is) {
    // Archive detection must read past the variable-length EVIS header to peek
    // the next byte, which is only safe on a seekable stream we can rewind.
    // For non-seekable streams (tellg() == -1) we must NOT consume the header:
    // doing so would corrupt the cursor (it cannot be restored) and silently
    // break even the raw KeyPackData path. The caller is responsible for
    // spooling non-seekable streams to a temp file before probing.
    std::streampos start = is.tellg();
    if (start == std::streampos(-1)) {
        is.clear(); // drop the failbit set by the failed tellg()
        return false;
    }
    bool is_bundle = false;
    int first = is.peek();
    if (first == 'D' || first == 'F') {
        is_bundle = true;
    } else {
        auto header = serialization::readHeader(is);
        if (header.has_header) {
            int next = is.peek();
            if (next == 'D' || next == 'F') {
                is_bundle = true;
            }
        }
    }
    is.clear(); // drop the eof/fail bits set while probing
    is.seekg(start);
    return is_bundle;
}

void KeyPackData::loadEvalKeyFile(const std::string &path, EvalKeyComponents components) {
    // Save components in thread-local-like storage? No — simpler: call the
    // buffer loader directly on the raw file/bundle path. We replicate the
    // dispatch logic from loadEvalKeyFile(path) but pass components through.
    fs::path input(path);

    auto select_eval_key_file = [&](const fs::path &dir_path) {
        fs::path expected = dir_path / ("EVIKeys" + std::to_string(context_->getPadRank()) + ".bin");
        if (fs::exists(expected)) {
            return expected;
        }
        // The save side names eval-key files by the per-context rank suffix
        // (RMP: inner_rank_list_[i].first, FLAT: rank_list_[i]), which can
        // differ from getPadRank() for a single context -- so the padRank-named
        // file may be absent even though the bundle is valid. Recover by
        // scanning the bundle dir: if exactly one EVIKeys*.bin is present the
        // choice is unambiguous (single-context bundle). With multiple
        // candidates we cannot safely guess which rank maps to this context,
        // so fall through to `expected` and let the FileNotFound surface the
        // real multi-rank naming mismatch instead of loading the wrong key.
        if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
            fs::path sole_candidate;
            int candidate_count = 0;
            for (const auto &entry : fs::directory_iterator(dir_path)) {
                const fs::path &candidate = entry.path();
                if (entry.is_regular_file() && candidate.extension() == ".bin" &&
                    candidate.filename().string().rfind("EVIKeys", 0) == 0) {
                    sole_candidate = candidate;
                    ++candidate_count;
                }
            }
            if (candidate_count == 1) {
                return sole_candidate;
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
        if (peekIsArchive(in)) {
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
    // EvalKey streams come in two formats:
    //   1. raw KeyPackData buffer (saveEvalKeyFile / getEvalKeyBuffer output):
    //        flag(1) + EVIS header + payload
    //   2. multi-rank archive built by utils::serializeEvalKey (the format
    //      MultiKeyGenerator writes to EvalKey.bin):
    //        EVIS header + ('D'|'F') + relative-path + payload
    // Dispatch off peekIsArchive so the buffer loader stays consistent with
    // the file-path loader (both go through the same detection logic).
    if (peekIsArchive(is)) {
        namespace fs = std::filesystem;
        const auto ts = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        fs::path tmp_dir = fs::temp_directory_path() / (".evi-evalkey-bundle-" + std::to_string(ts));
        fs::create_directories(tmp_dir);
        fs::path bundle = tmp_dir / "EvalKey.bin";
        {
            std::ofstream out(bundle, std::ios::binary);
            if (!out.is_open()) {
                fs::remove_all(tmp_dir);
                throw evi::EviError("Failed to materialize eval-key bundle to temp file");
            }
            out << is.rdbuf();
        }
        try {
            loadEvalKeyFile(bundle.string(), components);
        } catch (...) {
            fs::remove_all(tmp_dir);
            throw;
        }
        fs::remove_all(tmp_dir);
        return;
    }

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
                serialization::readPacked<u64>(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
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
                serialization::readPacked<u64>(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
                serialization::readPacked<u64>(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
            } else {
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
                serialization::skipPackedU64(is, DEGREE, q_bits);
                serialization::skipPackedU64(is, DEGREE, p_bits);
            }
            const std::size_t count = static_cast<std::size_t>(DEGREE) * context_->getPadRank();
            if (load_modpack) {
                serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
                serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
                serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
                serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
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
            const bool transpose_u32 = context_->getParam()->getPreset() == evi::ParameterPreset::IP3 &&
                                       context_->getDeviceType() == evi::DeviceType::CPU;
            key_switching_key.resize(DEGREE);
            for (int i = 0; i < DEGREE; i++) {
                auto &key = key_switching_key[i];
                const std::size_t count = static_cast<std::size_t>(DEGREE) * poly_count;
                if (transpose_u32) {
                    auto key32 = std::make_shared<Matrix<DataType::CIPHER, u32>>(0);
                    key32->setSize(static_cast<int>(count));
                    readTransposeKeyInto<u32>(is, *key32, header.has_header, gadget_rank, num_p, p_bits_list,
                                              poly_count);
                    key32->preset = ParameterPreset::IP3;
                    key.emplace<KeyPackData::TransposeKey32>(std::move(key32));
                } else {
                    VariadicKeyType key64;
                    key64->setSize(static_cast<int>(count));
                    readTransposeKeyInto<u64>(is, *key64, header.has_header, gadget_rank, num_p, p_bits_list,
                                              poly_count);
                    key.emplace<VariadicKeyType>(std::move(key64));
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
                        serialization::readPacked<u64>(is, shared_a_mod_pack_key->getPolyData(1, 0), count, q_bits);
                        serialization::readPacked<u64>(is, shared_a_mod_pack_key->getPolyData(1, 1), count, p_bits);
                        serialization::readPacked<u64>(is, shared_a_mod_pack_key->getPolyData(0, 0), count, q_bits);
                        serialization::readPacked<u64>(is, shared_a_mod_pack_key->getPolyData(0, 1), count, p_bits);
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
                        serialization::readPacked<u64>(is, cc_shared_a_mod_pack_key->getPolyData(1, 0), sa_count,
                                                       q_bits);
                        serialization::readPacked<u64>(is, cc_shared_a_mod_pack_key->getPolyData(1, 1), sa_count,
                                                       p_bits);
                        serialization::readPacked<u64>(is, cc_shared_a_mod_pack_key->getPolyData(0, 0), sa_count,
                                                       q_bits);
                        serialization::readPacked<u64>(is, cc_shared_a_mod_pack_key->getPolyData(0, 1), sa_count,
                                                       p_bits);
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
                        serialization::readPacked<u64>(is, shared_a_key->getPolyData(0, 0), fwd_b, q_bits);
                        serialization::readPacked<u64>(is, shared_a_key->getPolyData(0, 1), fwd_b, p_bits);
                        serialization::readPacked<u64>(is, shared_a_key->getPolyData(1, 0), fwd_a, q_bits);
                        serialization::readPacked<u64>(is, shared_a_key->getPolyData(1, 1), fwd_a, p_bits);
                        shared_a_key_loaded_ = true;
                    } else {
                        serialization::skipPackedU64(is, fwd_b, q_bits);
                        serialization::skipPackedU64(is, fwd_b, p_bits);
                        serialization::skipPackedU64(is, fwd_a, q_bits);
                        serialization::skipPackedU64(is, fwd_a, p_bits);
                    }

                    // Backward-compat: legacy keypacks may carry the
                    // deprecated QPR R-channel section. r_prime / r_bits are
                    // read off the wire to advance the stream cursor, then
                    // the packed payload is skipped — the R-channel keys are
                    // no longer materialised. New keypacks always write
                    // has_r == 0 (see getEvalKeyBuffer).
                    uint8_t has_r = 0;
                    if (is.read(reinterpret_cast<char *>(&has_r), sizeof(has_r)) && has_r) {
                        u64 r_prime = 0;
                        is.read(reinterpret_cast<char *>(&r_prime), sizeof(r_prime));
                        uint8_t r_bits = 0;
                        is.read(reinterpret_cast<char *>(&r_bits), sizeof(r_bits));
                        serialization::skipPackedU64(is, fwd_a, r_bits);
                        serialization::skipPackedU64(is, fwd_b, r_bits);
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
                                        serialization::readPacked<u64>(is, shared_a_fwd_keys[s].ax(d)[p].data(), DEGREE,
                                                                       bits);
                                        serialization::readPacked<u64>(is, shared_a_fwd_keys[s].bx(d)[p].data(), DEGREE,
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
                                        serialization::readPacked<u64>(is, shared_a_off_diag_keys[idx].bx(d)[p].data(),
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
                        // IP3 -> u32 alternative, others (incl. IP2 after the
                        // IP2->u64 demotion) -> u64. Wire payload byte-
                        // identical (same width); format unchanged. Single
                        // source of truth shared with the KeyGeneratorImpl writer
                        // (utils::isU32BackwardKey), so the read-side allocation
                        // and the write-side variant choice are the same call.
                        const bool bwd_u32 = utils::isU32BackwardKey(context_);
                        if (load_bwd) {
                            shared_a_bwd_l0_keys.resize(nss);
                            for (int j = 0; j < nss; ++j) {
                                auto &bk = shared_a_bwd_l0_keys[j];
                                // ONE irreducible preset-driven gate per key:
                                // a variant alternative must be chosen before
                                // any value exists, so there is nothing to
                                // std::visit on yet. After the alternative is
                                // selected (size DEGREE, exactly one
                                // representation), the per-field read collapses
                                // to a visit. readPacked consumes the same
                                // words*sizeof(u64) bytes regardless of T and
                                // unpack_fixedW<u32> applies the same narrowing
                                // the explicit static_cast loop did — wire and
                                // value identical.
                                using BL0 = detail::KeyPackData::BackwardL0Key;
                                auto initF = [&](BL0::Poly &f) {
                                    if (bwd_u32)
                                        f.emplace<polyvec32>(DEGREE);
                                    else
                                        f.emplace<polyvec>(DEGREE);
                                };
                                auto readF = [&](BL0::Poly &f, uint8_t bits) {
                                    initF(f);
                                    std::visit(
                                        [&](auto &v) {
                                            serialization::readPacked(is, v.data(), DEGREE, bits);
                                        },
                                        f);
                                };
                                readF(bk.ax_q, bwd_q_bits);
                                readF(bk.ax_p, bwd_p_bits);
                                readF(bk.bx_q, bwd_q_bits);
                                readF(bk.bx_p, bwd_p_bits);
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
        serialization::readPacked<u64>(is, relin_key->getPolyData(1, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(1, 1), DEGREE, p_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(0, 0), DEGREE, q_bits);
        serialization::readPacked<u64>(is, relin_key->getPolyData(0, 1), DEGREE, p_bits);
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
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 0), count, q_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(1, 1), count, p_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 0), count, q_bits);
        serialization::readPacked<u64>(is, mod_pack_key->getPolyData(0, 1), count, p_bits);
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
