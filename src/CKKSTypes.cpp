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

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Bitpack.hpp"
#include "EVI/impl/Const.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Serialization.hpp"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <vector>

namespace evi {

// ======================= SingleBlock<T, U> ===============================================
namespace detail {

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(const int level) : dtype_(T), level_(level) {
    if constexpr (T == DataType::PLAIN) {
        dtype_ = DataType::PLAIN;
    }
}

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(const poly_t<U> &b_q) : dtype_(T) {
    if constexpr (T == DataType::CIPHER) {
        throw evi::InvalidAccessError("Cannot create Ciphertext with a polynomial");
    } else {
        level_ = 0;
        b_q_ = b_q;
    }
}

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(const poly_t<U> &a_q, const poly_t<U> &b_q) : dtype_(T) {
    if constexpr (T == DataType::CIPHER) {
        level_ = 0;
        a_q_ = (a_q);
        b_q_ = (b_q);
    } else {
        level_ = 1;
        b_q_ = (a_q);
        b_p_ = (b_q);
    }
}

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(const poly_t<U> &a_q, const poly_t<U> &a_p, const poly_t<U> &b_q, const poly_t<U> &b_p)
    : dtype_(T), level_(1), a_q_((a_q)), a_p_((a_p)), b_q_((b_q)), b_p_((b_p)) {
    if constexpr (T == DataType::PLAIN) {
        throw evi::InvalidAccessError("Cannot create plaintext with more than 2 polynomials");
    }
}

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(std::istream &stream) : dtype_(T) {
    deserializeFrom(stream);
}

template <DataType T, class U>
SingleBlock<T, U>::SingleBlock(std::vector<u8> &buf) : dtype_(T) {
    deserializeFrom(buf);
}

template <DataType T, class U>
void SingleBlock<T, U>::serializeTo(std::ostream &stream) const {
    serialization::writeHeader(stream, serialization::kVersionV1);
    stream.write(reinterpret_cast<const char *>(&level_), sizeof(int));
    stream.write(reinterpret_cast<const char *>(&n), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&degree), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&show_dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&scale_bit), sizeof(u64));
    auto enc_type = static_cast<std::underlying_type_t<evi::EncodeType>>(encode_type);
    stream.write(reinterpret_cast<const char *>(&enc_type), sizeof(enc_type));
    const u8 q_bits = prime_q_bits;
    const u8 p_bits = (level_ ? prime_p_bits : 0);
    if (!q_bits || (level_ && !p_bits)) {
        throw evi::InvalidInputError("Missing prime bit metadata for serialization");
    }
    stream.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    stream.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    if constexpr (T == DataType::CIPHER) {
        serialization::writePacked<U>(stream, a_q_.data(), DEGREE, q_bits);
        serialization::writePacked<U>(stream, b_q_.data(), DEGREE, q_bits);
        if (level_) {
            serialization::writePacked<U>(stream, a_p_.data(), DEGREE, p_bits);
            serialization::writePacked<U>(stream, b_p_.data(), DEGREE, p_bits);
        }
    } else {
        serialization::writePacked<U>(stream, b_q_.data(), DEGREE, q_bits);
        if (level_) {
            serialization::writePacked<U>(stream, b_p_.data(), DEGREE, p_bits);
        }
    }
}

template <DataType T, class U>
void SingleBlock<T, U>::serializeTo(std::ostream &stream, BTruncMode mode) const {
    if constexpr (T != DataType::CIPHER) {
        throw evi::NotSupportedError("b-part truncation is only valid for CIPHER blocks");
    }
    if constexpr (T == DataType::CIPHER) {
        serializeCipherBlockRow<U>(stream, *this, a_q_.data(), b_q_.data(), a_p_.data(), b_p_.data(), mode,
                                   prime_q_bits, level_ ? prime_p_bits : 0);
    }
}

// Explicit-length b-part truncation (V3), ported from #727 onto the <T, U>
// element-type-axis template (#703). The metadata header is byte-identical
// regardless of U; the packed polys use writePacked<U> so the u32-native path
// stays narrow (no u32->u64 widen). TRUNC emits a V3 header carrying
// b_trunc_len; NONE emits a full-width V1 block.
template <DataType T, class U>
void SingleBlock<T, U>::serializeTo(std::ostream &stream, BTruncMode mode, std::uint32_t b_trunc_len) const {
    if constexpr (T != DataType::CIPHER) {
        throw evi::NotSupportedError("b-part truncation is only valid for CIPHER blocks");
    }
    const bool b_part_trunc = (mode == BTruncMode::TRUNC);
    if (b_part_trunc && b_trunc_len > DEGREE) {
        throw evi::InvalidInputError("b_trunc_len exceeds DEGREE");
    }
    const uint8_t version = b_part_trunc ? serialization::kVersionV3 : serialization::kVersionV1;
    const std::size_t b_count = b_part_trunc ? static_cast<std::size_t>(b_trunc_len) : static_cast<std::size_t>(DEGREE);
    serialization::writeHeader(stream, version);
    stream.write(reinterpret_cast<const char *>(&level_), sizeof(int));
    stream.write(reinterpret_cast<const char *>(&n), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&degree), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&show_dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&scale_bit), sizeof(u64));
    auto enc_type = static_cast<std::underlying_type_t<evi::EncodeType>>(encode_type);
    stream.write(reinterpret_cast<const char *>(&enc_type), sizeof(enc_type));
    const u8 q_bits = prime_q_bits;
    const u8 p_bits = (level_ ? prime_p_bits : 0);
    if (!q_bits || (level_ && !p_bits)) {
        throw evi::InvalidInputError("Missing prime bit metadata for serialization");
    }
    stream.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    stream.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    if (version == serialization::kVersionV3) {
        stream.write(reinterpret_cast<const char *>(&b_trunc_len), sizeof(b_trunc_len));
    }
    if constexpr (T == DataType::CIPHER) {
        serialization::writePacked<U>(stream, a_q_.data(), DEGREE, q_bits);
        serialization::writePacked<U>(stream, b_q_.data(), b_count, q_bits);
        if (level_) {
            serialization::writePacked<U>(stream, a_p_.data(), DEGREE, p_bits);
            serialization::writePacked<U>(stream, b_p_.data(), b_count, p_bits);
        }
    }
}

template <DataType T, class U>
void SingleBlock<T, U>::deserializeFrom(std::istream &stream, BTruncMode mode) {
    if constexpr (T != DataType::CIPHER) {
        throw evi::NotSupportedError("b-part truncation is only valid for CIPHER blocks");
    }
    const auto header = serialization::readHeader(stream);
    const auto meta = readCipherBlockRowMeta(stream, header);
    // NONE <-> V1, TRUNC <-> V2. Caller's mode must agree with the stream version.
    if ((mode == BTruncMode::TRUNC) != meta.is_v2) {
        throw evi::InvalidInputError("BTruncMode does not match stream version");
    }
    level_ = meta.level;
    n = meta.n;
    dim = meta.dim;
    degree = meta.degree;
    show_dim = meta.show_dim;
    scale_bit = meta.scale_bit;
    encode_type = meta.encode_type;
    prime_q_bits = meta.q_bits;
    prime_p_bits = meta.p_bits;

    if constexpr (T == DataType::CIPHER) {
        readCipherBlockRowPolys<U>(stream, meta, a_q_.data(), b_q_.data(), level_ ? a_p_.data() : nullptr,
                                   level_ ? b_p_.data() : nullptr);
    }
}

template <DataType T, class U>
void SingleBlock<T, U>::deserializeFrom(std::istream &stream) {
    const auto header = serialization::readHeader(stream);
    if (header.has_header) {
        // Accept V1/V2/V3 (V3 = #727 explicit-length b-trunc). The version is
        // validated again inside readCipherBlockRowMeta, which also consumes the
        // V3 b_trunc_len field and folds it into meta.b_count.
        if (header.version != serialization::kVersionV1 && header.version != serialization::kVersionV2 &&
            header.version != serialization::kVersionV3) {
            throw evi::NotSupportedError("Unsupported SingleBlock serialization version");
        }
        if constexpr (T != DataType::CIPHER) {
            if (header.version == serialization::kVersionV2 || header.version == serialization::kVersionV3) {
                throw evi::NotSupportedError("b-part truncation is only valid for CIPHER blocks");
            }
        }
        const auto meta = readCipherBlockRowMeta(stream, header);
        level_ = meta.level;
        n = meta.n;
        dim = meta.dim;
        degree = meta.degree;
        show_dim = meta.show_dim;
        scale_bit = meta.scale_bit;
        encode_type = meta.encode_type;
        prime_q_bits = meta.q_bits;
        prime_p_bits = meta.p_bits;
        if constexpr (T == DataType::CIPHER) {
            readCipherBlockRowPolys<U>(stream, meta, a_q_.data(), b_q_.data(), level_ ? a_p_.data() : nullptr,
                                       level_ ? b_p_.data() : nullptr);
        } else {
            // Non-CIPHER stores only the b-part, full width (no V2 truncation).
            serialization::readPacked<U>(stream, b_q_.data(), DEGREE, meta.q_bits);
            if (level_) {
                serialization::readPacked<U>(stream, b_p_.data(), DEGREE, meta.p_bits);
            }
        }
    } else {
        stream.read(reinterpret_cast<char *>(&level_), sizeof(int));
        stream.read(reinterpret_cast<char *>(&n), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&degree), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&show_dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&scale_bit), sizeof(u64));
        std::underlying_type_t<evi::EncodeType> enc_type_raw = 0;
        stream.read(reinterpret_cast<char *>(&enc_type_raw), sizeof(enc_type_raw));
        encode_type = static_cast<evi::EncodeType>(enc_type_raw);
        prime_q_bits = 0;
        prime_p_bits = 0;
        const std::streamsize bytes = static_cast<std::streamsize>(sizeof(U) * DEGREE);
        if constexpr (T == DataType::CIPHER) {
            // Headerless (legacy) path: raw native-width dump, always full DEGREE,
            // no V2/V3 truncation (header.version is unset here, so b-truncation
            // never applies). #703 reads sizeof(U)*DEGREE bytes directly to keep
            // the u32-native storage narrow. main's V3 branch here is unreachable
            // (no header => version 0) and used the non-existent readPackedU64.
            stream.read(reinterpret_cast<char *>(a_q_.data()), bytes);
            stream.read(reinterpret_cast<char *>(b_q_.data()), bytes);
            if (level_) {
                stream.read(reinterpret_cast<char *>(a_p_.data()), bytes);
                stream.read(reinterpret_cast<char *>(b_p_.data()), bytes);
            }
        } else {
            stream.read(reinterpret_cast<char *>(b_q_.data()), bytes);
            if (level_) {
                stream.read(reinterpret_cast<char *>(b_p_.data()), bytes);
            }
        }
    }
}

template <DataType T, class U>
void SingleBlock<T, U>::serializeTo(std::vector<u8> &buf) const {
    std::stringstream ss;
    serializeTo(ss);
    std::string str = ss.str();
    buf.insert(buf.end(), str.begin(), str.end());
}

template <DataType T, class U>
void SingleBlock<T, U>::deserializeFrom(const std::vector<u8> &buf) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    deserializeFrom(ss);
}

template <DataType T, class U>
poly &SingleBlock<T, U>::getPoly(const int pos, const int level, std::optional<const int> index) {
    if constexpr (!std::is_same_v<U, u64>) {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
const poly &SingleBlock<T, U>::getPoly(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (!std::is_same_v<U, u64>) {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
poly32 &SingleBlock<T, U>::getPoly32(const int pos, const int level, std::optional<const int> index) {
    if constexpr (!std::is_same_v<U, u32>) {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
const poly32 &SingleBlock<T, U>::getPoly32(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (!std::is_same_v<U, u32>) {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
polydata SingleBlock<T, U>::getPolyData(const int pos, const int level, std::optional<const int> index) {
    if constexpr (!std::is_same_v<U, u64>) {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return a_p_.data();
            } else if (!pos) {
                return b_p_.data();
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_.data();
            } else if (!pos) {
                return b_q_.data();
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_.data();
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return b_p_.data();
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
polydata SingleBlock<T, U>::getPolyData(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (!std::is_same_v<U, u64>) {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    } else if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 1");
            }
            if (pos == 1) {
                return const_cast<polydata>(a_p_.data());
            } else if (!pos) {
                return const_cast<polydata>(b_p_.data());
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return const_cast<polydata>(a_q_.data());
            } else if (!pos) {
                return const_cast<polydata>(b_q_.data());
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return const_cast<polydata>(b_q_.data());
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("--");
                }
                return const_cast<polydata>(b_p_.data());
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T, class U>
polydata32 SingleBlock<T, U>::getPolyData32(const int pos, const int level, std::optional<const int> index) {
    return getPoly32(pos, level, index).data();
}

template <DataType T, class U>
polydata32 SingleBlock<T, U>::getPolyData32(const int pos, const int level, std::optional<const int> index) const {
    return const_cast<polydata32>(getPoly32(pos, level, index).data());
}

// ======================= Matrix<E, T> ============================================
//
// Step 3 of the IData element-type axis refactor (B-hybrid). The first template
// parameter `E` is the encryption-presence axis (CIPHER / PLAIN); the second
// parameter `T` is the storage element type (defaults to u64 in the header).
// Internal polyvec storage is `polyvec_t<T>` and the parent is `IData<T>`.

template <DataType E, class T>
Matrix<E, T>::Matrix(const int level) : dtype_(E) {
    level_ = level;
    if constexpr (E == DataType::CIPHER) {
        polyvec_t<T> a_q, b_q;
        a_q_ = std::move(a_q);
        b_q_ = std::move(b_q);
        if (level) {
            polyvec_t<T> a_p, b_p;
            a_p_ = std::move(a_p);
            b_p_ = std::move(b_p);
        }
    } else {
        dtype_ = DataType::PLAIN;
        level_ = level;
        polyvec_t<T> q;
        b_q_ = std::move(q);
        if (level) {
            polyvec_t<T> p;
            b_p_ = std::move(p);
        }
    }
}

template <DataType E, class T>
Matrix<E, T>::Matrix(polyvec_t<T> b_q) : dtype_(E) {
    if constexpr (E == DataType::CIPHER) {
        throw evi::InvalidAccessError("Cannot create Matrix with a polynomial");
    } else {
        level_ = 0;
        b_q_ = std::move(b_q);
    }
}

template <DataType E, class T>
Matrix<E, T>::Matrix(polyvec_t<T> a_q, polyvec_t<T> b_q) : dtype_(E) {
    if constexpr (E == DataType::CIPHER) {
        level_ = 0;
        a_q_ = std::move(a_q);
        b_q_ = std::move(b_q);
    } else {
        level_ = 1;
        b_q_ = std::move(a_q);
        b_p_ = std::move(b_q);
    }
}

template <DataType E, class T>
Matrix<E, T>::Matrix(polyvec_t<T> a_q, polyvec_t<T> a_p, polyvec_t<T> b_q, polyvec_t<T> b_p)
    : dtype_(DataType::CIPHER), level_(1), a_q_(std::move(a_q)), a_p_(std::move(a_p)), b_q_(std::move(b_q)),
      b_p_(std::move(b_p)) {
    if constexpr (E == DataType::PLAIN) {
        throw evi::InvalidAccessError("Cannot create plaintext with more than 2 polynomials");
    }
}

template <DataType E, class T>
void Matrix<E, T>::serializeTo(std::ostream &stream) const {
    // V2 adds preset (u8) after prime_p_bits. Readers dispatch on
    // version (V1 fallback treats preset as RUNTIME).
    serialization::writeHeader(stream, serialization::kVersionV2);
    stream.write(reinterpret_cast<const char *>(&level_), sizeof(int));
    stream.write(reinterpret_cast<const char *>(&n), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&degree), sizeof(u64));
    const u8 q_bits = prime_q_bits;
    const u8 p_bits = (level_ ? prime_p_bits : 0);
    if (!q_bits || (level_ && !p_bits)) {
        throw evi::InvalidInputError("Missing prime bit metadata for serialization");
    }
    stream.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    stream.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    // V2 field: preset so DecryptorMM can detect base-converted results
    // after wire round-trip. RUNTIME means "same as context" (default).
    const u8 res_preset_byte = static_cast<u8>(preset);
    stream.write(reinterpret_cast<const char *>(&res_preset_byte), sizeof(res_preset_byte));
    const std::size_t elem_count = static_cast<std::size_t>((n + degree - 1) / degree) * DEGREE;
    if constexpr (E == DataType::CIPHER) {
        serialization::writePacked<T>(stream, a_q_.data(), elem_count, q_bits);
        serialization::writePacked<T>(stream, b_q_.data(), elem_count, q_bits);
        if (level_) {
            serialization::writePacked<T>(stream, a_p_.data(), elem_count, p_bits);
            serialization::writePacked<T>(stream, b_p_.data(), elem_count, p_bits);
        }
    } else {
        serialization::writePacked<T>(stream, b_q_.data(), elem_count, q_bits);
        if (level_) {
            serialization::writePacked<T>(stream, b_p_.data(), elem_count, p_bits);
        }
    }
}

template <DataType E, class T>
void Matrix<E, T>::serializeTo(std::vector<u8> &buf) const {
    std::stringstream ss;
    serializeTo(ss);
    std::string str = ss.str();
    buf.insert(buf.end(), str.begin(), str.end());
}

template <DataType E, class T>
void Matrix<E, T>::deserializeFrom(std::istream &stream) {
    auto header = serialization::readHeader(stream);
    if (header.has_header) {
        if (header.version != serialization::kVersionV1 && header.version != serialization::kVersionV2) {
            throw evi::NotSupportedError("Unsupported Matrix serialization version");
        }
        stream.read(reinterpret_cast<char *>(&level_), sizeof(int));
        stream.read(reinterpret_cast<char *>(&n), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&degree), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&prime_q_bits), sizeof(prime_q_bits));
        stream.read(reinterpret_cast<char *>(&prime_p_bits), sizeof(prime_p_bits));
        if (header.version >= serialization::kVersionV2) {
            u8 res_preset_byte = 0;
            stream.read(reinterpret_cast<char *>(&res_preset_byte), sizeof(res_preset_byte));
            preset = static_cast<ParameterPreset>(res_preset_byte);
        } else {
            // V1 predates the base-conversion discriminator — no-op default.
            preset = ParameterPreset::RUNTIME;
        }
    } else {
        stream.read(reinterpret_cast<char *>(&level_), sizeof(int));
        stream.read(reinterpret_cast<char *>(&n), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&degree), sizeof(u64));
        prime_q_bits = 0;
        prime_p_bits = 0;
    }
    const std::size_t elem_count = static_cast<std::size_t>((n + degree - 1) / degree) * DEGREE;
    setSize((n + degree - 1) / degree * U64_DEGREE);
    if (header.has_header) {
        const u8 q_bits = prime_q_bits;
        const u8 p_bits = (level_ ? prime_p_bits : 0);
        if constexpr (E == DataType::CIPHER) {
            serialization::readPacked<T>(stream, a_q_.data(), elem_count, q_bits);
            serialization::readPacked<T>(stream, b_q_.data(), elem_count, q_bits);
            if (level_) {
                serialization::readPacked<T>(stream, a_p_.data(), elem_count, p_bits);
                serialization::readPacked<T>(stream, b_p_.data(), elem_count, p_bits);
            }
        } else {
            serialization::readPacked<T>(stream, b_q_.data(), elem_count, q_bits);
            if (level_) {
                serialization::readPacked<T>(stream, b_p_.data(), elem_count, p_bits);
            }
        }
    } else {
        if constexpr (E == DataType::CIPHER) {
            stream.read(reinterpret_cast<char *>(a_q_.data()), (n + degree - 1) / degree * U64_DEGREE);
            stream.read(reinterpret_cast<char *>(b_q_.data()), (n + degree - 1) / degree * U64_DEGREE);
            if (level_) {
                stream.read(reinterpret_cast<char *>(a_p_.data()), (n + degree - 1) / degree * U64_DEGREE);
                stream.read(reinterpret_cast<char *>(b_p_.data()), (n + degree - 1) / degree * U64_DEGREE);
            }
        } else {
            stream.read(reinterpret_cast<char *>(b_q_.data()), (n + degree - 1) / degree * U64_DEGREE);
            if (level_) {
                stream.read(reinterpret_cast<char *>(b_p_.data()), (n + degree - 1) / degree * U64_DEGREE);
            }
        }
    }
}

template <DataType E, class T>
void Matrix<E, T>::deserializeFrom(const std::vector<u8> &buf) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    deserializeFrom(ss);
}

template <DataType E, class T>
polyvec_t<T> &Matrix<E, T>::getPoly(const int pos, const int level, std::optional<const int> index) {
    if constexpr (E == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType E, class T>
const polyvec_t<T> &Matrix<E, T>::getPoly(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (E == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
            if (pos == 1) {
                return a_p_;
            } else if (!pos) {
                return b_p_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_;
            } else if (!pos) {
                return b_q_;
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_;
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
                }
                return b_p_;
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType E, class T>
polydata_t<T> Matrix<E, T>::getPolyData(const int pos, const int level, std::optional<const int> index) {
    if constexpr (E == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
            if (pos == 1) {
                return a_p_.data();
            } else if (!pos) {
                return b_p_.data();
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return a_q_.data();
            } else if (!pos) {
                return b_q_.data();
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return b_q_.data();
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
                }
                return b_p_.data();
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType E, class T>
polydata_t<T> Matrix<E, T>::getPolyData(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (E == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
            if (pos == 1) {
                return const_cast<polydata_t<T>>(a_p_.data());
            } else if (!pos) {
                return const_cast<polydata_t<T>>(b_p_.data());
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        } else {
            if (pos == 1) {
                return const_cast<polydata_t<T>>(a_q_.data());
            } else if (!pos) {
                return const_cast<polydata_t<T>>(b_q_.data());
            } else {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
            }
        }
    } else {
        if (!pos) {
            if (!level) {
                return const_cast<polydata_t<T>>(b_q_.data());
            } else {
                if (!level_) {
                    throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
                }
                return const_cast<polydata_t<T>>(b_p_.data());
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType E, class T>
void Matrix<E, T>::setSize(const int size, std::optional<int> a_size) {
    if constexpr (E == DataType::CIPHER) {
        if (!a_size.has_value()) {
            a_q_.resize(size);
            b_q_.resize(size);
            if (level_) {
                a_p_.resize(size);
                b_p_.resize(size);
            }
        } else {
            // for genSharedASwitchKey
            a_q_.resize(a_size.value());
            b_q_.resize(size);
            if (level_) {
                a_p_.resize(a_size.value());
                b_p_.resize(size);
            }
        }
    } else {
        b_q_.resize(size);
        if (level_) {
            b_p_.resize(size);
        }
    }
}

// ======================= PolyData<T> ===============================================

template <DataType T>
void PolyData<T>::setSize(const int size) {
    b_q.resize(size);
    a_q.resize(size);
    b_p.resize(size);
    a_p.resize(size);
}

template <DataType T>
int PolyData<T>::getSize() const {
    return b_q.size();
}

template <DataType T>
polydata &PolyData<T>::getPolyData(const int pos, const int level, std::optional<int> index) {
    if (pos == 0 && level == 0) {
        return b_q[index.value()];
    } else if (pos == 0 && level == 1) {
        return b_p[index.value()];
    } else if (pos == 1 && level == 0) {
        if constexpr (T == DataType::CIPHER) {
            return a_q[index.value()];
        } else {
            throw evi::InvalidAccessError("Invalid input");
        }
    } else if (pos == 1 && level == 1) {
        if constexpr (T == DataType::CIPHER) {
            return a_p[index.value()];
        } else {
            throw evi::InvalidAccessError("Invalid input");
        }

    } else {
        throw evi::InvalidAccessError("Invalid input");
    }
}

template struct SingleBlock<evi::DataType::PLAIN, u64>;
template struct SingleBlock<evi::DataType::CIPHER, u64>;
template struct SingleBlock<evi::DataType::CIPHER, u32>;
template struct Matrix<evi::DataType::PLAIN, u64>;
template struct Matrix<evi::DataType::CIPHER, u64>;
// Step 5 of the IData element-type axis refactor (B-hybrid). The IP3-only
// u32-native storage variant. IData<u32> instantiates the templated IData
// virtual surface for the u32 storage; Matrix<CIPHER, u32> is the producer-
// side concrete type built by ShaperImpl::deserializeAndTranspose on the IP3
// branch. No Matrix<PLAIN, u32> at this step — no PLAIN path requires u32
// storage (encryptor's Matrix<PLAIN> usages all default to u64).
template struct IData<u32>;
template struct Matrix<evi::DataType::CIPHER, u32>;
template struct PolyData<DataType::CIPHER>;
template struct PolyData<DataType::PLAIN>;
} // namespace detail
} // namespace evi
