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
#include <cassert>
#include <cstring>
#include <vector>

namespace evi {

// ======================= SingleBlock<T> ===============================================
namespace detail {

template <DataType T>
SingleBlock<T>::SingleBlock(const int level) : dtype_(T) {
    level_ = level;
    if constexpr (T == DataType::CIPHER) {
        poly a_q, b_q;
        a_q_ = a_q;
        b_q_ = b_q;
        if (level) {
            poly a_p, b_p;
            a_q_ = a_p;
            b_q_ = b_p;
        }
    } else {
        dtype_ = DataType::PLAIN;
        level_ = level;
        poly q;
        b_q_ = q;
        if (level) {
            poly p;
            b_p_ = p;
        }
    }
}

template <DataType T>
SingleBlock<T>::SingleBlock(const poly &b_q) : dtype_(T) {
    if constexpr (T == DataType::CIPHER) {
        throw evi::InvalidAccessError("Cannot create Ciphertext with a polynomial");
    } else {
        level_ = 0;
        b_q_ = b_q;
    }
}

template <DataType T>
SingleBlock<T>::SingleBlock(const poly &a_q, const poly &b_q) : dtype_(T) {
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

template <DataType T>
SingleBlock<T>::SingleBlock(const poly &a_q, const poly &a_p, const poly &b_q, const poly &b_p)
    : dtype_(T), level_(1), a_q_((a_q)), a_p_((a_p)), b_q_((b_q)), b_p_((b_p)) {
    if constexpr (T == DataType::PLAIN) {
        throw evi::InvalidAccessError("Cannot create plaintext with more than 2 polynomials");
    }
}

template <DataType T>
SingleBlock<T>::SingleBlock(std::istream &stream) : dtype_(T) {
    deserializeFrom(stream);
}

template <DataType T>
SingleBlock<T>::SingleBlock(std::vector<u8> &buf) : dtype_(T) {
    deserializeFrom(buf);
}

template <DataType T>
void SingleBlock<T>::serializeTo(std::ostream &stream) const {
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
        serialization::writePackedU64(stream, a_q_.data(), DEGREE, q_bits);
        serialization::writePackedU64(stream, b_q_.data(), DEGREE, q_bits);
        if (level_) {
            serialization::writePackedU64(stream, a_p_.data(), DEGREE, p_bits);
            serialization::writePackedU64(stream, b_p_.data(), DEGREE, p_bits);
        }
    } else {
        serialization::writePackedU64(stream, b_q_.data(), DEGREE, q_bits);
        if (level_) {
            serialization::writePackedU64(stream, b_p_.data(), DEGREE, p_bits);
        }
    }
}

template <DataType T>
void SingleBlock<T>::deserializeFrom(std::istream &stream) {
    auto header = serialization::readHeader(stream);
    if (header.has_header) {
        if (header.version != serialization::kVersionV1) {
            throw evi::NotSupportedError("Unsupported SingleBlock serialization version");
        }
        stream.read(reinterpret_cast<char *>(&level_), sizeof(int));
        stream.read(reinterpret_cast<char *>(&n), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&degree), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&show_dim), sizeof(u64));
        stream.read(reinterpret_cast<char *>(&scale_bit), sizeof(u64));
        std::underlying_type_t<evi::EncodeType> enc_type_raw = 0;
        stream.read(reinterpret_cast<char *>(&enc_type_raw), sizeof(enc_type_raw));
        encode_type = static_cast<evi::EncodeType>(enc_type_raw);
        stream.read(reinterpret_cast<char *>(&prime_q_bits), sizeof(prime_q_bits));
        stream.read(reinterpret_cast<char *>(&prime_p_bits), sizeof(prime_p_bits));
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
    }
    if (header.has_header) {
        const u8 q_bits = prime_q_bits;
        const u8 p_bits = (level_ ? prime_p_bits : 0);
        if constexpr (T == DataType::CIPHER) {
            serialization::readPackedU64(stream, a_q_.data(), DEGREE, q_bits);
            serialization::readPackedU64(stream, b_q_.data(), DEGREE, q_bits);
            if (level_) {
                serialization::readPackedU64(stream, a_p_.data(), DEGREE, p_bits);
                serialization::readPackedU64(stream, b_p_.data(), DEGREE, p_bits);
            }
        } else {
            serialization::readPackedU64(stream, b_q_.data(), DEGREE, q_bits);
            if (level_) {
                serialization::readPackedU64(stream, b_p_.data(), DEGREE, p_bits);
            }
        }
    } else {
        if constexpr (T == DataType::CIPHER) {
            stream.read(reinterpret_cast<char *>(a_q_.data()), U64_DEGREE);
            stream.read(reinterpret_cast<char *>(b_q_.data()), U64_DEGREE);
            if (level_) {
                stream.read(reinterpret_cast<char *>(a_p_.data()), U64_DEGREE);
                stream.read(reinterpret_cast<char *>(b_p_.data()), U64_DEGREE);
            }
        } else {
            stream.read(reinterpret_cast<char *>(b_q_.data()), U64_DEGREE);
            if (level_) {
                stream.read(reinterpret_cast<char *>(b_p_.data()), U64_DEGREE);
            }
        }
    }
}

template <DataType T>
void SingleBlock<T>::serializeTo(std::vector<u8> &buf) const {
    std::stringstream ss;
    serializeTo(ss);
    std::string str = ss.str();
    buf.insert(buf.end(), str.begin(), str.end());
}

template <DataType T>
void SingleBlock<T>::deserializeFrom(const std::vector<u8> &buf) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    deserializeFrom(ss);
}

template <DataType T>
poly &SingleBlock<T>::getPoly(const int pos, const int level, std::optional<const int> index) {
    if constexpr (T == DataType::CIPHER) {
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
template <DataType T>
const poly &SingleBlock<T>::getPoly(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
polydata SingleBlock<T>::getPolyData(const int pos, const int level, std::optional<const int> index) {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
polydata SingleBlock<T>::getPolyData(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
SerializedSingleQuery<T>::SerializedSingleQuery(polyvec128 &ptxt) : level_(0), ptxt_(std::move(ptxt)) {
    if constexpr (T != DataType::PLAIN) {
        throw InvalidAccessError("Check");
    }
    dtype_ = DataType::SERIALIZED_PLAIN;
}

template <DataType T>
polyvec128 &SerializedSingleQuery<T>::getPoly() {
    if constexpr (T != DataType::PLAIN) {
        throw InvalidAccessError("Check");
    }

    return ptxt_;
}

template <DataType T>
u128 *SerializedSingleQuery<T>::getPolyData() {
    if constexpr (T != DataType::PLAIN) {
        throw InvalidAccessError("Check");
    }

    return ptxt_.data();
}

// ======================= Matrix<T> ===============================================

template <DataType T>
Matrix<T>::Matrix(const int level) : dtype_(T) {
    level_ = level;
    if constexpr (T == DataType::CIPHER) {
        polyvec a_q, b_q;
        a_q_ = std::move(a_q);
        b_q_ = std::move(b_q);
        if (level) {
            polyvec a_p, b_p;
            a_p_ = std::move(a_p);
            b_p_ = std::move(b_p);
        }
    } else {
        dtype_ = DataType::PLAIN;
        level_ = level;
        polyvec q;
        b_q_ = std::move(q);
        if (level) {
            polyvec p;
            b_p_ = std::move(p);
        }
    }
}

template <DataType T>
Matrix<T>::Matrix(polyvec b_q) : dtype_(T) {
    if constexpr (T == DataType::CIPHER) {
        throw evi::InvalidAccessError("Cannot create Matrix with a polynomial");
    } else {
        level_ = 0;
        b_q_ = std::move(b_q);
    }
}

template <DataType T>
Matrix<T>::Matrix(polyvec a_q, polyvec b_q) : dtype_(T) {
    if constexpr (T == DataType::CIPHER) {
        level_ = 0;
        a_q_ = std::move(a_q);
        b_q_ = std::move(b_q);
    } else {
        level_ = 1;
        b_q_ = std::move(a_q);
        b_p_ = std::move(b_q);
    }
}

template <DataType T>
Matrix<T>::Matrix(polyvec a_q, polyvec a_p, polyvec b_q, polyvec b_p)
    : dtype_(DataType::CIPHER), level_(1), a_q_(std::move(a_q)), a_p_(std::move(a_p)), b_q_(std::move(b_q)),
      b_p_(std::move(b_p)) {
    if constexpr (T == DataType::PLAIN) {
        throw evi::InvalidAccessError("Cannot create plaintext with more than 2 polynomials");
    }
}

template <DataType T>
void Matrix<T>::serializeTo(std::ostream &stream) const {
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
    if constexpr (T == DataType::CIPHER) {
        serialization::writePackedU64(stream, a_q_.data(), elem_count, q_bits);
        serialization::writePackedU64(stream, b_q_.data(), elem_count, q_bits);
        if (level_) {
            serialization::writePackedU64(stream, a_p_.data(), elem_count, p_bits);
            serialization::writePackedU64(stream, b_p_.data(), elem_count, p_bits);
        }
    } else {
        serialization::writePackedU64(stream, b_q_.data(), elem_count, q_bits);
        if (level_) {
            serialization::writePackedU64(stream, b_p_.data(), elem_count, p_bits);
        }
    }
}

template <DataType T>
void Matrix<T>::serializeTo(std::vector<u8> &buf) const {
    std::stringstream ss;
    serializeTo(ss);
    std::string str = ss.str();
    buf.insert(buf.end(), str.begin(), str.end());
}

template <DataType T>
void Matrix<T>::deserializeFrom(std::istream &stream) {
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
        if constexpr (T == DataType::CIPHER) {
            serialization::readPackedU64(stream, a_q_.data(), elem_count, q_bits);
            serialization::readPackedU64(stream, b_q_.data(), elem_count, q_bits);
            if (level_) {
                serialization::readPackedU64(stream, a_p_.data(), elem_count, p_bits);
                serialization::readPackedU64(stream, b_p_.data(), elem_count, p_bits);
            }
        } else {
            serialization::readPackedU64(stream, b_q_.data(), elem_count, q_bits);
            if (level_) {
                serialization::readPackedU64(stream, b_p_.data(), elem_count, p_bits);
            }
        }
    } else {
        if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
void Matrix<T>::deserializeFrom(const std::vector<u8> &buf) {
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    deserializeFrom(ss);
}

template <DataType T>
polyvec &Matrix<T>::getPoly(const int pos, const int level, std::optional<const int> index) {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
const polyvec &Matrix<T>::getPoly(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
polydata Matrix<T>::getPolyData(const int pos, const int level, std::optional<const int> index) {
    if constexpr (T == DataType::CIPHER) {
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

template <DataType T>
polydata Matrix<T>::getPolyData(const int pos, const int level, std::optional<const int> index) const {
    if constexpr (T == DataType::CIPHER) {
        if (level) {
            if (!level_) {
                throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
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
                    throw evi::InvalidAccessError("Cannot access to poly other than 0 or 1");
                }
                return const_cast<polydata>(b_p_.data());
            }
        } else {
            throw evi::InvalidAccessError("--");
        }
    }
}

template <DataType T>
void Matrix<T>::setSize(const int size, std::optional<int> a_size) {
    if constexpr (T == DataType::CIPHER) {
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

template struct SingleBlock<evi::DataType::PLAIN>;
template struct SingleBlock<evi::DataType::CIPHER>;
template struct SerializedSingleQuery<evi::DataType::PLAIN>;
template struct SerializedSingleQuery<evi::DataType::CIPHER>;
template struct Matrix<evi::DataType::PLAIN>;
template struct Matrix<evi::DataType::CIPHER>;
template struct PolyData<DataType::CIPHER>;
template struct PolyData<DataType::PLAIN>;
} // namespace detail
} // namespace evi
