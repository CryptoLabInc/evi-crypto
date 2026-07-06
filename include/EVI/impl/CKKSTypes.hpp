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

#pragma once
#include "EVI/Enums.hpp"
#include "EVI/impl/Const.hpp"

#include "utils/Exceptions.hpp"
#include "utils/Serialization.hpp"
#include "utils/span.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

// Forward-declared so Query can hold a u32 transposed-matrix handle without
// pulling the heavy hem header here. Defined in hem/common/ModulusMatrix.hpp.
namespace hem {
template <typename T>
class CTMatrix;
} // namespace hem

namespace evi {
namespace detail {

// Forward declaration so Query can hold a shared_ptr<IDataBase> typed-data
// slot (Step 5 of the IData element-type axis refactor; defined later in this
// header).
struct IDataBase;

class Message : public std::vector<float> {
public:
    using std::vector<float>::vector;
    Message() : std::vector<float>() {}
    Message(u32 size, float val) : std::vector<float>(size, val) {}
};

// #define alignment_byte 256
template <typename T, std::size_t N>
struct alignas(alignment_byte) AlignedArray : public std::array<T, N> {};

using s_poly = AlignedArray<i64, DEGREE>;
using poly = AlignedArray<u64, DEGREE>;
using poly32 = AlignedArray<u32, DEGREE>;
template <typename T>
using poly_t = AlignedArray<T, DEGREE>;

using polyvec = std::vector<u64, AlignedAllocator<u64, alignment_byte>>;
using polyvec32 = std::vector<u32, AlignedAllocator<u32, alignment_byte>>;
using polyvec128 = std::vector<u128, AlignedAllocator<u128, alignment_byte>>;
using polydata = u64 *;
using polydata32 = u32 *;

// Element-type-templated aliases used by the templated IData<T>. polyvec_t<T>
// is the aligned coefficient vector for element type T; polydata_t<T> is the
// raw pointer counterpart. Static asserts below pin the u64/u32 specializations
// to the existing legacy typedefs so callers using IData<u64> see exactly the
// same return types as the pre-template IData.
template <typename T>
using polyvec_t = std::vector<T, AlignedAllocator<T, alignment_byte>>;
template <typename T>
using polydata_t = T *;
static_assert(std::is_same_v<polyvec_t<u64>, polyvec>, "polyvec_t<u64> must match polyvec");
static_assert(std::is_same_v<polyvec_t<u32>, polyvec32>, "polyvec_t<u32> must match polyvec32");
static_assert(std::is_same_v<polydata_t<u64>, polydata>, "polydata_t<u64> must match polydata");
static_assert(std::is_same_v<polydata_t<u32>, polydata32>, "polydata_t<u32> must match polydata32");

struct IQuery {
public:
    u64 dim;
    u64 show_dim;
    u64 degree;
    u64 n;
    u64 scale_bit;
    evi::EncodeType encode_type;
    u8 prime_q_bits = 0;
    u8 prime_p_bits = 0;

    virtual void serializeTo(std::vector<u8> &buf) const = 0;
    virtual void deserializeFrom(const std::vector<u8> &buf) = 0;
    virtual void serializeTo(std::ostream &stream) const = 0;
    virtual void deserializeFrom(std::istream &stream) = 0;

    virtual poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual const poly &getPoly(const int pos, const int level,
                                std::optional<const int> index = std::nullopt) const = 0;
    virtual poly32 &getPoly32(const int pos, const int level, std::optional<const int> index = std::nullopt) {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    }
    virtual const poly32 &getPoly32(const int pos, const int level,
                                    std::optional<const int> index = std::nullopt) const {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    }

    virtual polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual polydata getPolyData(const int pos, const int level,
                                 std::optional<const int> index = std::nullopt) const = 0;
    virtual polydata32 getPolyData32(const int pos, const int level, std::optional<const int> index = std::nullopt) {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    }
    virtual polydata32 getPolyData32(const int pos, const int level,
                                     std::optional<const int> index = std::nullopt) const {
        throw InvalidAccessError("Not compatible type to access to 32-bit array");
    }

    virtual DataType getDataType() const = 0;
    virtual int getLevel() const = 0;
    virtual bool isU32() const {
        return false;
    }
};

template <typename U>
inline void serializeCipherBlockRow(std::ostream &stream, const IQuery &meta, const U *a_q, const U *b_q, const U *a_p,
                                    const U *b_p, BTruncMode mode, u8 q_bits, u8 p_bits) {
    static_assert(std::is_same_v<U, u32> || std::is_same_v<U, u64>, "Serialized query word type must be u32 or u64");
    const bool b_part_trunc = (mode == BTruncMode::TRUNC);
    const uint8_t version = b_part_trunc ? serialization::kVersionV2 : serialization::kVersionV1;
    const std::size_t b_count = (version == serialization::kVersionV2 && meta.dim > 0 && meta.dim < DEGREE)
                                    ? static_cast<std::size_t>(meta.dim)
                                    : static_cast<std::size_t>(DEGREE);

    serialization::writeHeader(stream, version);
    const int level = meta.getLevel();
    stream.write(reinterpret_cast<const char *>(&level), sizeof(int));
    stream.write(reinterpret_cast<const char *>(&meta.n), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.degree), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.show_dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.scale_bit), sizeof(u64));
    auto enc_type = static_cast<std::underlying_type_t<evi::EncodeType>>(meta.encode_type);
    stream.write(reinterpret_cast<const char *>(&enc_type), sizeof(enc_type));
    if (!q_bits || (level && !p_bits)) {
        throw evi::InvalidInputError("Missing prime bit metadata for serialization");
    }
    stream.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    stream.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    serialization::writePacked<U>(stream, a_q, DEGREE, q_bits);
    serialization::writePacked<U>(stream, b_q, b_count, q_bits);
    if (level) {
        serialization::writePacked<U>(stream, a_p, DEGREE, p_bits);
        serialization::writePacked<U>(stream, b_p, b_count, p_bits);
    }
}

// Explicit-length b-part truncation (V3) for raw U* block-rows — the free-
// function counterpart to SingleBlock::serializeTo(stream, mode, b_trunc_len).
// V2 truncates b to meta.dim; this V3 form truncates b to an explicit
// b_trunc_len (the populated item count `n`), so the IP3 typed-query path emits
// the same wire shape as the non-typed SingleBlock V3 path (#703). NONE emits a
// full-width V1 block. readCipherBlockRowMeta auto-detects V1/V2/V3, so the read
// counterpart (readCipherBlockRowPolys<U>) is unchanged.
template <typename U>
inline void serializeCipherBlockRow(std::ostream &stream, const IQuery &meta, const U *a_q, const U *b_q, const U *a_p,
                                    const U *b_p, BTruncMode mode, u8 q_bits, u8 p_bits, std::uint32_t b_trunc_len) {
    static_assert(std::is_same_v<U, u32> || std::is_same_v<U, u64>, "Serialized query word type must be u32 or u64");
    const bool b_part_trunc = (mode == BTruncMode::TRUNC);
    if (b_part_trunc && b_trunc_len > DEGREE) {
        throw evi::InvalidInputError("b_trunc_len exceeds DEGREE");
    }
    const uint8_t version = b_part_trunc ? serialization::kVersionV3 : serialization::kVersionV1;
    const std::size_t b_count = b_part_trunc ? static_cast<std::size_t>(b_trunc_len) : static_cast<std::size_t>(DEGREE);

    serialization::writeHeader(stream, version);
    const int level = meta.getLevel();
    stream.write(reinterpret_cast<const char *>(&level), sizeof(int));
    stream.write(reinterpret_cast<const char *>(&meta.n), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.degree), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.show_dim), sizeof(u64));
    stream.write(reinterpret_cast<const char *>(&meta.scale_bit), sizeof(u64));
    auto enc_type = static_cast<std::underlying_type_t<evi::EncodeType>>(meta.encode_type);
    stream.write(reinterpret_cast<const char *>(&enc_type), sizeof(enc_type));
    if (!q_bits || (level && !p_bits)) {
        throw evi::InvalidInputError("Missing prime bit metadata for serialization");
    }
    stream.write(reinterpret_cast<const char *>(&q_bits), sizeof(q_bits));
    stream.write(reinterpret_cast<const char *>(&p_bits), sizeof(p_bits));
    if (version == serialization::kVersionV3) {
        stream.write(reinterpret_cast<const char *>(&b_trunc_len), sizeof(b_trunc_len));
    }
    serialization::writePacked<U>(stream, a_q, DEGREE, q_bits);
    serialization::writePacked<U>(stream, b_q, b_count, q_bits);
    if (level) {
        serialization::writePacked<U>(stream, a_p, DEGREE, p_bits);
        serialization::writePacked<U>(stream, b_p, b_count, p_bits);
    }
}

// Metadata recovered from a serialized CIPHER block-row header — the read
// counterpart to the fields serializeCipherBlockRow writes. `b_count` is the
// b-part coefficient count carried on the wire (V2 truncates to `dim`, V3 to an
// explicit b_trunc_len; the rest is zero padding restored on read). The header
// byte layout is identical for CIPHER and non-CIPHER blocks, so this also
// serves non-CIPHER header readers that only consume the metadata.
struct CipherBlockRowMeta {
    bool is_v2 = false;
    bool is_v3 = false;
    int level = 0;
    u64 n = 0, dim = 0, degree = 0, show_dim = 0, scale_bit = 0;
    evi::EncodeType encode_type = evi::EncodeType::ITEM;
    u8 q_bits = 0, p_bits = 0;
    std::size_t b_count = static_cast<std::size_t>(DEGREE);
};

// Reads the metadata block written by serializeCipherBlockRow (V1/V2) or by
// SingleBlock::serializeTo(stream, mode, b_trunc_len) (V3, #727), given the
// stream header the caller already consumed via serialization::readHeader.
// V3 carries an explicit u32 b_trunc_len directly after p_bits; it is read here
// and folded into b_count so readCipherBlockRowPolys restores the zero-padded
// tail uniformly for V2 and V3.
inline CipherBlockRowMeta readCipherBlockRowMeta(std::istream &stream, const serialization::HeaderInfo &header) {
    if (!header.has_header) {
        throw evi::NotSupportedError("Block row blob requires header");
    }
    if (header.version != serialization::kVersionV1 && header.version != serialization::kVersionV2 &&
        header.version != serialization::kVersionV3) {
        throw evi::NotSupportedError("Unsupported block row serialization version");
    }
    CipherBlockRowMeta m;
    m.is_v2 = (header.version == serialization::kVersionV2);
    m.is_v3 = (header.version == serialization::kVersionV3);
    stream.read(reinterpret_cast<char *>(&m.level), sizeof(int));
    stream.read(reinterpret_cast<char *>(&m.n), sizeof(u64));
    stream.read(reinterpret_cast<char *>(&m.dim), sizeof(u64));
    stream.read(reinterpret_cast<char *>(&m.degree), sizeof(u64));
    stream.read(reinterpret_cast<char *>(&m.show_dim), sizeof(u64));
    stream.read(reinterpret_cast<char *>(&m.scale_bit), sizeof(u64));
    std::underlying_type_t<evi::EncodeType> enc_type_raw = 0;
    stream.read(reinterpret_cast<char *>(&enc_type_raw), sizeof(enc_type_raw));
    m.encode_type = static_cast<evi::EncodeType>(enc_type_raw);
    stream.read(reinterpret_cast<char *>(&m.q_bits), sizeof(m.q_bits));
    stream.read(reinterpret_cast<char *>(&m.p_bits), sizeof(m.p_bits));
    if (m.is_v3) {
        std::uint32_t b_trunc_len = 0;
        stream.read(reinterpret_cast<char *>(&b_trunc_len), sizeof(b_trunc_len));
        if (b_trunc_len > DEGREE) {
            throw evi::InvalidInputError("V3 b_trunc_len exceeds DEGREE");
        }
        m.b_count = static_cast<std::size_t>(b_trunc_len);
    } else {
        m.b_count = (m.is_v2 && m.dim > 0 && m.dim < DEGREE) ? static_cast<std::size_t>(m.dim)
                                                             : static_cast<std::size_t>(DEGREE);
    }
    return m;
}

// Reads the packed a/b polynomials (q, and the p-part when meta.level > 0) that
// serializeCipherBlockRow emitted into caller buffers, restoring the truncated
// b-part tail with zeros. a_p/b_p are ignored (may be null) when level == 0.
// Mirrors serializeCipherBlockRow exactly, so it is the read counterpart for
// every CIPHER block-row consumer (SingleBlock and the IP3 CTMatrix path).
template <typename U>
inline void readCipherBlockRowPolys(std::istream &stream, const CipherBlockRowMeta &meta, U *a_q, U *b_q, U *a_p,
                                    U *b_p) {
    static_assert(std::is_same_v<U, u32> || std::is_same_v<U, u64>, "Serialized query word type must be u32 or u64");
    const u8 p_bits = (meta.level ? meta.p_bits : 0);
    serialization::readPacked<U>(stream, a_q, DEGREE, meta.q_bits);
    serialization::readPacked<U>(stream, b_q, meta.b_count, meta.q_bits);
    if (meta.b_count < DEGREE) {
        std::fill_n(b_q + meta.b_count, DEGREE - meta.b_count, U{0});
    }
    if (meta.level) {
        serialization::readPacked<U>(stream, a_p, DEGREE, p_bits);
        serialization::readPacked<U>(stream, b_p, meta.b_count, p_bits);
        if (meta.b_count < DEGREE) {
            std::fill_n(b_p + meta.b_count, DEGREE - meta.b_count, U{0});
        }
    }
}

template <DataType T, class U = u64>
struct SingleBlock : IQuery {
public:
    SingleBlock(const int level);
    SingleBlock(const poly_t<U> &a_q);
    SingleBlock(const poly_t<U> &a_q, const poly_t<U> &b_q);
    SingleBlock(const poly_t<U> &a_q, const poly_t<U> &a_p, const poly_t<U> &b_q, const poly_t<U> &b_p);

    SingleBlock(std::istream &stream);
    SingleBlock(std::vector<u8> &buf);

    poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    const poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) const override;
    poly32 &getPoly32(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    const poly32 &getPoly32(const int pos, const int level,
                            std::optional<const int> index = std::nullopt) const override;
    polydata getPolyData(const int pos, const int leve, std::optional<const int> index = std::nullopt) override;
    polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) const override;
    polydata32 getPolyData32(const int pos, const int leve, std::optional<const int> index = std::nullopt) override;
    polydata32 getPolyData32(const int pos, const int level,
                             std::optional<const int> index = std::nullopt) const override;

    void serializeTo(std::vector<u8> &buf) const override;
    void deserializeFrom(const std::vector<u8> &buf) override;
    void serializeTo(std::ostream &stream) const override;
    void deserializeFrom(std::istream &stream) override;

    /// Serialize with configurable b-part truncation (CIPHER only).
    /// - BTruncMode::NONE  writes the full-width b-part with a V1 header
    ///   (wire-identical to the legacy one-argument serializeTo).
    /// - BTruncMode::TRUNC writes `dim` coefficients and tags the blob with a
    ///   V2 header. Use for server-side row storage where b is in the
    ///   coefficient domain and b[dim..DEGREE) is zero-padding from the
    ///   encoder.
    /// The version reflects caller intent, not the current shape: TRUNC
    /// always emits V2 even when `dim == DEGREE` makes the byte payload
    /// equivalent to V1.
    void serializeTo(std::ostream &stream, BTruncMode mode) const;
    /// Serialize truncating b to an explicit `b_trunc_len` (CIPHER only); TRUNC
    /// writes a V3 header recording the length, NONE writes full-width V1.
    void serializeTo(std::ostream &stream, BTruncMode mode, std::uint32_t b_trunc_len) const;
    /// Deserialize counterpart. The `mode` must match the stream version
    /// (V1 <-> NONE, V2 <-> TRUNC); a mismatch throws InvalidInputError. For
    /// TRUNC, b is read with `dim` coefficients and zero-filled at
    /// [dim..DEGREE).
    void deserializeFrom(std::istream &stream, BTruncMode mode);

    DataType getDataType() const override {
        return dtype_;
    }
    int getLevel() const override {
        return level_;
    }
    bool isU32() const override {
        return std::is_same_v<U, u32>;
    }

private:
    DataType dtype_;
    int level_;
    poly_t<U> b_q_;
    poly_t<U> b_p_;
    poly_t<U> a_q_;
    poly_t<U> a_p_;
};

class Query {
public:
    using SingleQuery = std::shared_ptr<IQuery>;
    using SingleContainer = std::vector<SingleQuery>;

    Query() = default;

    explicit Query(SingleContainer container) : single_blocks_(std::move(container)) {}

    SingleContainer &single() {
        return single_blocks_;
    }
    const SingleContainer &single() const {
        return single_blocks_;
    }

    std::size_t size() const {
        return typed_block_count_ ? typed_block_count_ : single_blocks_.size();
    }
    bool empty() const {
        return single_blocks_.empty() && !typed_data_state_;
    }
    void reserve(std::size_t count) {
        single_blocks_.reserve(count);
    }

    SingleQuery &operator[](std::size_t index) {
        // IP3 typed query: size() reports typed_block_count_ (the matrix row
        // count) but single_blocks_ holds ONLY index 0 as metadata (the polys
        // live in typed_data_state_). A generic `for (i = 0; i < size(); ++i)
        // q[i]` consumer would index single_blocks_ out of range; fail loudly
        // instead of UB. Consumers needing all rows must read typed_data_state_.
        if (typed_data_state_ && index != 0) {
            throw InvalidAccessError("IP3 typed query exposes only index 0 via operator[]; rows live in typed state");
        }
        return single_blocks_[index];
    }
    const SingleQuery &operator[](std::size_t index) const {
        if (typed_data_state_ && index != 0) {
            throw InvalidAccessError("IP3 typed query exposes only index 0 via operator[]; rows live in typed state");
        }
        return single_blocks_[index];
    }

    SingleQuery &at(std::size_t index) {
        if (typed_data_state_ && index != 0) {
            throw InvalidAccessError("IP3 typed query exposes only index 0 via at(); rows live in typed state");
        }
        return single_blocks_.at(index);
    }
    const SingleQuery &at(std::size_t index) const {
        if (typed_data_state_ && index != 0) {
            throw InvalidAccessError("IP3 typed query exposes only index 0 via at(); rows live in typed state");
        }
        return single_blocks_.at(index);
    }

    SingleQuery &front() {
        return single_blocks_.front();
    }
    const SingleQuery &front() const {
        return single_blocks_.front();
    }

    SingleQuery &back() {
        return single_blocks_.back();
    }
    const SingleQuery &back() const {
        return single_blocks_.back();
    }

    void push_back(const SingleQuery &value) { // NOLINT(readability-identifier-naming)
        single_blocks_.push_back(value);
    }
    void push_back(SingleQuery &&value) { // NOLINT(readability-identifier-naming)
        single_blocks_.push_back(std::move(value));
    }

    void append(const Query &other) {
        single_blocks_.insert(single_blocks_.end(), other.single_blocks_.begin(), other.single_blocks_.end());
    }

    SingleQuery &emplace_back(SingleQuery value) { // NOLINT(readability-identifier-naming)
        single_blocks_.emplace_back(std::move(value));
        return single_blocks_.back();
    }

    void clear() {
        single_blocks_.clear();
        typed_data_state_.reset();
        typed_block_count_ = 0;
    }
    auto begin() {
        return single_blocks_.begin();
    }
    auto end() {
        return single_blocks_.end();
    }
    auto begin() const {
        return single_blocks_.begin();
    }
    auto end() const {
        return single_blocks_.end();
    }

    void setInnerItemCount(u32 count) {
        inner_item_count_ = count;
    }
    u32 getInnerItemCount() const {
        return inner_item_count_;
    }
    void setItemCount(u32 count) {
        total_item_count_ = count;
    }
    u32 getItemCount() const {
        return total_item_count_;
    }

    // Typed coefficient storage used by the IP3 CPU MM path. A single legacy
    // block may remain for metadata, while block_count preserves the public
    // Query shape and serialization materializes rows only as transient data.
    // Null on non-IP3 paths.
    void setTypedDataState(std::shared_ptr<IDataBase> state, std::size_t block_count = 0) {
        typed_data_state_ = std::move(state);
        typed_block_count_ = block_count;
    }
    const std::shared_ptr<IDataBase> &getTypedDataState() const {
        return typed_data_state_;
    }

private:
    SingleContainer single_blocks_;
    u32 inner_item_count_ = 0;
    u32 total_item_count_ = 0;
    std::shared_ptr<IDataBase> typed_data_state_;
    std::size_t typed_block_count_ = 0;
};

// Non-template base of IData. Owns the element-type-independent (T-independent)
// subset of IData's interface: scalar shape fields, the runtime preset tag,
// byte-stream (de)serialization, and the structural setSize/getLevel/getDataType
// virtuals. The T-dependent poly accessors stay on IData.
//
// Step 1 of the IData element-type axis refactor (B-hybrid). See
// envector-msa docs/design/crypto/idata-element-type-axis-v1.md.
struct IDataBase {
public:
    u64 dim;
    u64 degree;
    u64 n;
    u8 prime_q_bits = 0;
    u8 prime_p_bits = 0;
    // Scale bits associated with the underlying CKKS coefficients. Mirrors
    // IQuery::scale_bit / hem::CTMatrix::scaleBits(); needed by Step 6
    // consumers that rebuild a CTMatrix from typed IData<T> state (the
    // typed path's analogue of the legacy CTMatrix-carrier side channel).
    u64 scale_bit = 0;
    // The parameter preset this ciphertext's coefficients are in.
    // RUNTIME (default) means "same as the Decryptor's context preset"
    // (i.e., no base conversion occurred). An explicit value (e.g., IP0)
    // means the coefficients are in that prime space — set by the compute
    // pipeline after base conversion.
    //
    // Invariant: the Decryptor context preset must always match the
    // encryption preset. Base conversion is detected by comparing this
    // field against the context preset.
    ParameterPreset preset = ParameterPreset::RUNTIME;

    virtual ~IDataBase() = default;

    virtual void serializeTo(std::vector<u8> &buf) const = 0;
    virtual void deserializeFrom(const std::vector<u8> &buf) = 0;
    virtual void serializeTo(std::ostream &stream) const = 0;
    virtual void deserializeFrom(std::istream &stream) = 0;

    virtual void setSize(const int size, std::optional<int> = std::nullopt) = 0;

    virtual DataType getDataType() const = 0;
    virtual int getLevel() const = 0;
    // Element storage width discriminator so width-agnostic consumers (e.g.
    // DecryptorMM) can dispatch the u32-native result path without knowing the
    // concrete IData<T>. Overridden by IData<T>; defaults to u64 (false).
    virtual bool isU32() const {
        return false;
    }
};

// Step 2 of the IData element-type axis refactor (B-hybrid). IData becomes a
// class template parameterized on the storage element type T. The default
// T = u64 keeps the legacy spelling (`IData<>`) consistent with the original
// u64 contract; callers that previously spelled bare `IData` should write
// `IData<u64>` explicitly (no implicit class-template-name lookup outside the
// class body in C++). The T-dependent virtuals return polyvec_t<T> /
// polydata_t<T>; the T-independent surface is inherited from IDataBase.
template <class T = u64>
struct IData : public IDataBase {
public:
    virtual polyvec_t<T> &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual const polyvec_t<T> &getPoly(const int pos, const int level,
                                        std::optional<const int> index = std::nullopt) const = 0;
    virtual polydata_t<T> getPolyData(const int pos, const int level,
                                      std::optional<const int> index = std::nullopt) = 0;
    virtual polydata_t<T> getPolyData(const int pos, const int level,
                                      std::optional<const int> index = std::nullopt) const = 0;
    bool isU32() const override {
        return std::is_same_v<T, u32>;
    }
};

// Step 3 of the IData element-type axis refactor (B-hybrid). Matrix's first
// template parameter is the encryption-presence axis (DataType, named `E` to
// disambiguate from the storage-element letter `T` introduced on IData<T>).
// A second parameter `class T = u64` carries the storage element width;
// internal polyvec storage is now polyvec_t<T> and the parent is IData<T>.
// Existing callers spelling `Matrix<DataType::CIPHER>` keep compiling via the
// T = u64 default. The Matrix<E, u32> instantiation is intentionally NOT
// added at this step; it lands in Step 5 with the IP3 producer.
template <DataType E, class T = u64>
struct Matrix : public IData<T> {
public:
    // Pull inherited IDataBase members into Matrix's scope so unqualified
    // references in the (now dependent-base) method bodies resolve without
    // needing `this->` prefixes everywhere. Identical addressing as before
    // the template-on-T conversion; behavior unchanged.
    using IDataBase::degree;
    using IDataBase::dim;
    using IDataBase::n;
    using IDataBase::preset;
    using IDataBase::prime_p_bits;
    using IDataBase::prime_q_bits;

    Matrix(const int level);
    Matrix(polyvec_t<T> q);
    Matrix(polyvec_t<T> a_q, polyvec_t<T> b_q);
    Matrix(polyvec_t<T> a_q, polyvec_t<T> a_p, polyvec_t<T> b_q, polyvec_t<T> b_p);

    polyvec_t<T> &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    polydata_t<T> getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    const polyvec_t<T> &getPoly(const int pos, const int level,
                                std::optional<const int> index = std::nullopt) const override;
    polydata_t<T> getPolyData(const int pos, const int level,
                              std::optional<const int> index = std::nullopt) const override;

    void serializeTo(std::vector<u8> &buf) const override;
    void deserializeFrom(const std::vector<u8> &buf) override;
    void serializeTo(std::ostream &stream) const override;
    void deserializeFrom(std::istream &stream) override;

    void setSize(const int size, std::optional<int> = std::nullopt) override;
    DataType getDataType() const override {
        return dtype_;
    }
    int getLevel() const override {
        return level_;
    }

private:
    DataType dtype_;
    int level_;
    polyvec_t<T> a_q_;
    polyvec_t<T> a_p_;
    polyvec_t<T> b_q_;
    polyvec_t<T> b_p_;
};

struct IPSearchResult {
    std::shared_ptr<IDataBase> ip_data;
};

class SearchResult {
public:
    SearchResult() : ipsearch_(std::make_shared<IPSearchResult>()) {}
    explicit SearchResult(std::shared_ptr<IPSearchResult> impl) : ipsearch_(std::move(impl)) {}

    // Getter (IP)
    IPSearchResult *operator->() noexcept {
        return ipsearch_.get();
    }
    const IPSearchResult *operator->() const noexcept {
        return ipsearch_.get();
    }

    std::shared_ptr<IPSearchResult> get() const {
        return ipsearch_;
    }
    std::shared_ptr<IDataBase> getIP() const {
        return ipsearch_->ip_data;
    }

    // Setter (IP)
    void set(std::shared_ptr<IPSearchResult> impl) {
        ipsearch_ = std::move(impl);
    }
    void setIP(std::shared_ptr<IDataBase> ip) {
        ipsearch_->ip_data = std::move(ip);
    }

    u32 getTotalItemCount() const {
        return total_item_count;
    }

    u32 total_item_count = 0;

private:
    std::shared_ptr<IPSearchResult> ipsearch_;
};

// Step 4 of the IData element-type axis refactor (B-hybrid). DataState is the
// cross-T data-handle typedef: it carries the T-independent IDataBase
// interface, so the same shared_ptr can later hold either IData<u64> or
// IData<u32> uniformly. At this step no IData<u32> exists yet, so every
// instance behind a DataState is in practice an IData<u64> — but the storage
// is the non-template base, and T-dependent accessors (getPoly, getPolyData)
// require an explicit downcast at the consumer site. The asU64Data() helper
// below makes the cast greppable and uniform; Step 6 will replace it with a
// preset-driven selector that picks IData<u64> or IData<u32> at the IP3
// boundary.
// (The `Blob = std::vector<DataState>` alias was removed in #724 along with the
// bulk encrypt/setData path; DataState stays at the IP3-refactored IDataBase.)
using DataState = std::shared_ptr<IDataBase>;

// Step 4: downcast helper for T-dependent accessors when a caller has only an
// IDataBase pointer. Safe so long as the IDataBase actually points at an
// IData<u64> instance (which is the only IData<T> instantiation that exists
// at this step). Step 6 will replace these call sites with a preset-driven
// selector. Greppable on purpose.
inline IData<u64> *asU64Data(IDataBase *base) {
    return static_cast<IData<u64> *>(base);
}
inline const IData<u64> *asU64Data(const IDataBase *base) {
    return static_cast<const IData<u64> *>(base);
}

// Step 6: paired u32 downcast helper. The IP3 consumer (IndexBase::setMatrix)
// preset-gates on ParameterPreset::IP3 before applying this cast; the only
// IDataBase instance that legally satisfies that gate is a Matrix<CIPHER, u32>
// parked on Query::typed_data_state_ by the IP3 producer in ShaperImpl.
// Greppable, mirrors asU64Data style.
inline IData<u32> *asU32Data(IDataBase *base) {
    return static_cast<IData<u32> *>(base);
}
inline const IData<u32> *asU32Data(const IDataBase *base) {
    return static_cast<const IData<u32> *>(base);
}

struct VariadicKeyType : std::shared_ptr<Matrix<DataType::CIPHER>> {
    VariadicKeyType() : std::shared_ptr<Matrix<DataType::CIPHER>>(std::make_shared<Matrix<DataType::CIPHER>>(1)) {}
    VariadicKeyType(const VariadicKeyType &to_copy) : std::shared_ptr<Matrix<DataType::CIPHER>>(to_copy) {}
};

struct FixedKeyType : std::shared_ptr<SingleBlock<DataType::CIPHER>> {
    FixedKeyType()
        : std::shared_ptr<SingleBlock<DataType::CIPHER>>(std::make_shared<SingleBlock<DataType::CIPHER>>(1)) {}
    FixedKeyType(const FixedKeyType &to_copy) : std::shared_ptr<SingleBlock<DataType::CIPHER>>(to_copy) {}
};

template <DataType T>
struct PolyData {
    void setSize(const int size);
    int getSize() const;
    polydata &getPolyData(const int pos, const int level, std::optional<int> idx = std::nullopt);

    std::vector<polydata> a_q;
    std::vector<polydata> a_p;
    std::vector<polydata> b_q;
    std::vector<polydata> b_p;
};

template <DataType T>
using DeviceData = std::shared_ptr<PolyData<T>>;

} // namespace detail
} // namespace evi
