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

#include <cstring>

namespace evi {
namespace detail {
namespace utils {

deb::Preset getDebPreset(const detail::Context &context) {
    switch (context->getParam()->getPreset()) {
    case ParameterPreset::IP0:
        return deb::PRESET_EVI_IP0;
    case ParameterPreset::IP1:
        return deb::PRESET_EVI_IP1;
    case evi::ParameterPreset::QF0:
    case evi::ParameterPreset::QF1:
        return deb::PRESET_EVI_QF;
    default:
        throw InvalidInputError("Invalid preset in context");
    }
}

deb::Context getDebContext(const detail::Context &context) {
    return deb::getContext(getDebPreset(context));
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

bool syncVarKeyToDebSwkKey(const detail::Context &context, const detail::VariadicKeyType &variad, deb::SwitchKey &swk) {
    const auto size = context->getPadRank();
    if (swk.axSize() == size && swk.bxSize() == size) {
        bool matched = true;
        for (u64 i = 0; i < size; ++i) {
            if (swk.ax(i)[0].data() != variad->getPolyData(1, 0) + i * detail::DEGREE ||
                swk.ax(i)[1].data() != variad->getPolyData(1, 1) + i * detail::DEGREE ||
                swk.bx(i)[0].data() != variad->getPolyData(0, 0) + i * detail::DEGREE ||
                swk.bx(i)[1].data() != variad->getPolyData(0, 1) + i * detail::DEGREE) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return false;
        }
    }
    if (swk.axSize() != size) {
        swk.addAx(2, size - swk.axSize());
    }
    for (u64 i = 0; i < size; ++i) {
        if (swk.ax(i)[0].data() != variad->getPolyData(1, 0) + i * detail::DEGREE) {
            swk.ax(i)[0].setData(variad->getPolyData(1, 0) + i * detail::DEGREE, detail::DEGREE);
        }
        if (swk.ax(i)[1].data() != variad->getPolyData(1, 1) + i * detail::DEGREE) {
            swk.ax(i)[1].setData(variad->getPolyData(1, 1) + i * detail::DEGREE, detail::DEGREE);
        }
    }
    if (swk.bxSize() != size) {
        swk.addBx(2, size - swk.bxSize());
    }
    for (u64 i = 0; i < size; ++i) {
        if (swk.bx(i)[0].data() != variad->getPolyData(0, 0) + i * detail::DEGREE) {
            swk.bx(i)[0].setData(variad->getPolyData(0, 0) + i * detail::DEGREE, detail::DEGREE);
        }
        if (swk.bx(i)[1].data() != variad->getPolyData(0, 1) + i * detail::DEGREE) {
            swk.bx(i)[1].setData(variad->getPolyData(0, 1) + i * detail::DEGREE, detail::DEGREE);
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
    deb_cipher.setNTT(is_ntt);
    if (cipher.getLevel() != 0) {
        deb_cipher[1][1].setData(cipher.getPoly(1, 1).data(), detail::DEGREE);
        deb_cipher[0][1].setData(cipher.getPoly(0, 1).data(), detail::DEGREE);
    }
    return deb_cipher;
}

deb::Ciphertext convertPointerToDebCipher(const detail::Context &context, detail::u64 *a_q, detail::u64 *b_q,
                                          detail::u64 *a_p, detail::u64 *b_p, bool is_ntt) {
    deb::Size level = (a_p != nullptr && b_p != nullptr) ? 1 : 0;
    deb::Ciphertext deb_cipher(getDebPreset(context), level, 2);
    deb_cipher[1][0].setData(a_q, detail::DEGREE);
    deb_cipher[0][0].setData(b_q, detail::DEGREE);
    if (level == 1) {
        deb_cipher[1][1].setData(a_p, detail::DEGREE);
        deb_cipher[0][1].setData(b_p, detail::DEGREE);
    }
    deb_cipher.setEncoding(deb::COEFF);
    deb_cipher.setNTT(is_ntt);
    return deb_cipher;
}

} // namespace utils
} // namespace detail
} // namespace evi
