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

#include "utils/DebUtils.hpp"

#include <deb/SecretKeyGenerator.hpp>
#include <deb/utils/NTT.hpp>

#include <algorithm>
#include <cstring>

namespace evi {
namespace detail {
namespace utils {
namespace {

constexpr auto kCoeffNttType = deb::utils::NTTType::NEGACYCLIC;
constexpr auto kCoeffRootType = deb::utils::NTTRootType::MIN;

// Single coeff-domain NTT-state setter for any deb word width (u32/u64).
template <typename U>
void setCoeffNttState(deb::CiphertextT<U> &cipher, bool is_ntt) {
    if (is_ntt) {
        cipher.setNTT(kCoeffNttType, kCoeffRootType);
    } else {
        cipher.setNTT(deb::utils::NTTType::NONNTT);
    }
}

} // namespace

deb::Preset getDebPreset(const detail::Context &context) {
    switch (context->getParam()->getPreset()) {
    case ParameterPreset::IP0:
        return deb::PRESET_EVI_IP0;
    case ParameterPreset::IP1:
        return deb::PRESET_EVI_IP1;
    case ParameterPreset::IP2:
        return deb::PRESET_EVI_IP2;
    case ParameterPreset::IP3:
        return deb::PRESET_EVI_IP3;
    case evi::ParameterPreset::QF0:
    case evi::ParameterPreset::QF1:
        return deb::PRESET_EVI_QF;
    default:
        throw InvalidInputError("Invalid preset in context");
    }
}

deb::Preset getDebPreset(const std::string &preset) {
    if (preset == "IP0") {
        return deb::PRESET_EVI_IP0;
    } else if (preset == "IP1") {
        return deb::PRESET_EVI_IP1;
    } else if (preset == "IP2") {
        return deb::PRESET_EVI_IP2;
    } else if (preset == "IP3") {
        return deb::PRESET_EVI_IP3;
    } else if (preset == "QF0" || preset == "QF1") {
        return deb::PRESET_EVI_QF;
    } else {
        throw InvalidInputError("Invalid preset in context");
    }
}

bool isU32NativePreset(const detail::Context &context) {
    return context->getParam()->getPreset() == evi::ParameterPreset::IP3 &&
           context->getDeviceType() == evi::DeviceType::CPU;
}

bool isU32BackwardKey(const detail::Context &context) {
    // Single source of truth for the backward-L0-key u32/u64 variant decision,
    // shared by the writer (KeyGeneratorImpl) and reader (KeyPackImpl) so the two
    // sides cannot drift. Unlike isU32NativePreset there is NO device check: key
    // storage is device-agnostic (the same IP3 keyset is used on CPU and GPU), so
    // the variant is gated on preset alone. IP3 -> u32; all others (incl. IP2
    // after its u64 demotion) -> u64.
    return context->getParam()->getPreset() == evi::ParameterPreset::IP3;
}

deb::Size getDebNumP(const detail::Context &context) {
    return deb::get_num_p(getDebPreset(context));
}

deb::Size getDebGadgetRank(const detail::Context &context) {
    return deb::get_gadget_rank(getDebPreset(context));
}

const deb::u64 *getDebPrimes(const detail::Context &context) {
    return deb::get_primes(getDebPreset(context));
}

std::optional<deb::RNGSeed> convertDebSeed(const std::optional<std::vector<u8>> &seed) {
    if (seed.has_value()) {
        if (seed->size() != sizeof(deb::RNGSeed)) {
            throw InvalidInputError("Seed size does not match deb::RNGSeed size");
        }
        deb::RNGSeed deb_seed;
        std::memcpy(&deb_seed, seed->data(), sizeof(deb::RNGSeed));
        return deb_seed;
    }
    return std::nullopt;
}

bool syncFixedKeyToDebSwkKey(const detail::Context &context, const detail::FixedKeyType &fixed, deb::SwitchKey &swk) {
    if (swk.axSize() == 1 && swk.bxSize() == 1) {
        if (swk.ax()[0].data() == fixed->getPolyData(1, 0) && swk.ax()[1].data() == fixed->getPolyData(1, 1) &&
            swk.bx()[0].data() == fixed->getPolyData(0, 0) && swk.bx()[1].data() == fixed->getPolyData(0, 1)) {
            return false;
        }
    }
    if (swk.axSize() != 1) {
        swk.getAx().clear();
        swk.addAx(2, 1); // add one ax poly with two levels
    }
    if (swk.ax()[0].data() != fixed->getPolyData(1, 0)) {
        swk.ax()[0].setData(fixed->getPolyData(1, 0), detail::DEGREE);
    }
    if (swk.ax()[1].data() != fixed->getPolyData(1, 1)) {
        swk.ax()[1].setData(fixed->getPolyData(1, 1), detail::DEGREE);
    }

    if (swk.bxSize() != 1) {
        swk.getBx().clear();
        swk.addBx(2, 1); // add one bx poly with two levels
    }
    if (swk.bx()[0].data() != fixed->getPolyData(0, 0)) {
        swk.bx()[0].setData(fixed->getPolyData(0, 0), detail::DEGREE);
    }
    if (swk.bx()[1].data() != fixed->getPolyData(0, 1)) {
        swk.bx()[1].setData(fixed->getPolyData(0, 1), detail::DEGREE);
    }

    return true;
}

bool syncVarKeyToDebSwkKey(const detail::Context &context, const detail::VariadicKeyType &variadic,
                           deb::SwitchKey &swk) {
    const auto preset = getDebPreset(context);
    const auto num_p = getDebNumP(context);

    const auto num_secret = deb::get_num_secret(preset);
    const auto gadget_rank = getDebGadgetRank(context);
    const auto ax_size = (swk.type() == deb::SWK_MODPACK_SELF) ? context->getPadRank() : gadget_rank;
    const auto bx_size = (swk.type() == deb::SWK_MODPACK_SELF) ? context->getPadRank() : ax_size * num_secret;

    if (swk.axSize() != ax_size) {
        swk.getAx().clear();
        swk.addAx(num_p, ax_size, kCoeffNttType, kCoeffRootType);
    }
    for (deb::Size i = 0; i < ax_size; ++i) {
        for (deb::Size pj = 0; pj < num_p; ++pj) {
            swk.ax(i)[pj].setData(variadic->getPolyData(1, static_cast<int>(pj)) + i * detail::DEGREE, detail::DEGREE);
        }
    }

    if (swk.bxSize() != bx_size) {
        swk.getBx().clear();
        swk.addBx(num_p, bx_size, kCoeffNttType, kCoeffRootType);
    }
    for (deb::Size i = 0; i < bx_size; ++i) {
        for (deb::Size pj = 0; pj < num_p; ++pj) {
            swk.bx(i)[pj].setData(variadic->getPolyData(0, static_cast<int>(pj)) + i * detail::DEGREE, detail::DEGREE);
        }
    }

    return true;
}

deb::Ciphertext convertSingleCipherToDebCipher(const detail::Context &context,
                                               detail::SingleBlock<DataType::CIPHER> &cipher, bool is_ntt) {
    deb::Ciphertext deb_cipher(getDebPreset(context), static_cast<deb::Size>(cipher.getLevel()));
    deb_cipher[1][0].setData(cipher.getPoly(1, 0).data(), detail::DEGREE);
    deb_cipher[0][0].setData(cipher.getPoly(0, 0).data(), detail::DEGREE);
    deb_cipher.setEncoding(deb::COEFF);
    setCoeffNttState(deb_cipher, is_ntt);
    if (cipher.getLevel() != 0) {
        deb_cipher[1][1].setData(cipher.getPoly(1, 1).data(), detail::DEGREE);
        deb_cipher[0][1].setData(cipher.getPoly(0, 1).data(), detail::DEGREE);
    }
    return deb_cipher;
}

template <typename U>
deb::CiphertextT<U> convertPointerToDebCipher(const detail::Context &context, U *a_q, U *b_q, U *a_p, U *b_p,
                                              bool is_ntt) {
    deb::Size level = (a_p != nullptr && b_p != nullptr) ? 1 : 0;
    deb::CiphertextT<U> deb_cipher(getDebPreset(context), level, 2);
    deb_cipher[1][0].setData(a_q, detail::DEGREE);
    deb_cipher[0][0].setData(b_q, detail::DEGREE);
    if (level == 1) {
        deb_cipher[1][1].setData(a_p, detail::DEGREE);
        deb_cipher[0][1].setData(b_p, detail::DEGREE);
    }
    deb_cipher.setEncoding(deb::COEFF);
    setCoeffNttState(deb_cipher, is_ntt);
    return deb_cipher;
}

// Explicit instantiations: u64 (all non-IP3 presets) and u32 (IP3 native path).
template deb::Ciphertext convertPointerToDebCipher<detail::u64>(const detail::Context &, detail::u64 *, detail::u64 *,
                                                                detail::u64 *, detail::u64 *, bool);
template deb::Ciphertext32 convertPointerToDebCipher<u32>(const detail::Context &, u32 *, u32 *, u32 *, u32 *, bool);

template <typename U>
deb::SecretKeyT<U> makeDebSecretKey(deb::Preset preset, const deb::SecretKey &src) {
    return deb::SecretKeyGeneratorT<U>::GenSecretKeyFromCoeff(preset, src.coeffs());
}
template deb::SecretKey makeDebSecretKey<detail::u64>(deb::Preset, const deb::SecretKey &);
template deb::SecretKey32 makeDebSecretKey<u32>(deb::Preset, const deb::SecretKey &);

template <typename U>
deb::SecretKeyT<U> makeDirectRootDebSecretKey(deb::Preset preset, const deb::SecretKey &src) {
    deb::utils::ScopedNTTRootType direct_root(deb::utils::NTTRootType::DIRECT);
    return deb::SecretKeyGeneratorT<U>::GenSecretKeyFromCoeff(preset, src.coeffs());
}
template deb::SecretKey makeDirectRootDebSecretKey<detail::u64>(deb::Preset, const deb::SecretKey &);
template deb::SecretKey32 makeDirectRootDebSecretKey<u32>(deb::Preset, const deb::SecretKey &);

deb::Preset getDebPreset(evi::ParameterPreset preset) {
    switch (preset) {
    case ParameterPreset::IP0:
        return deb::PRESET_EVI_IP0;
    case ParameterPreset::IP1:
        return deb::PRESET_EVI_IP1;
    case ParameterPreset::IP2:
        return deb::PRESET_EVI_IP2;
    case ParameterPreset::IP3:
        return deb::PRESET_EVI_IP3;
    case ParameterPreset::QF0:
    case ParameterPreset::QF1:
        return deb::PRESET_EVI_QF;
    default:
        throw InvalidInputError("Invalid ParameterPreset for deb conversion");
    }
}

deb::Ciphertext convertPointerToDebCipherWithPreset(evi::ParameterPreset preset, detail::u64 *a_q, detail::u64 *b_q,
                                                    bool is_ntt) {
    deb::Ciphertext deb_cipher(getDebPreset(preset), 0, 2);
    deb_cipher[1][0].setData(a_q, detail::DEGREE);
    deb_cipher[0][0].setData(b_q, detail::DEGREE);
    deb_cipher.setEncoding(deb::COEFF);
    setCoeffNttState(deb_cipher, is_ntt);
    return deb_cipher;
}

} // namespace utils
} // namespace detail
} // namespace evi
