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

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/Type.hpp"

#include "EVI/Enums.hpp"
#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <variant>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Serialize.hpp>

namespace evi {

namespace fs = std::filesystem;

namespace detail {

class KeySwitcher;

// Backward L0 key-switch storage routing: u32-native for IP3, u64 for all
// other presets. After the IP2->u64 demotion this is exactly the invariant
// isU32Matrix() <=> preset==ParameterPreset::IP3, so the former centralized
// width predicate was collapsed away: sites with matrix context use
// isU32Matrix(); key-gen / (de)serialize sites (param only) gate directly
// on preset==ParameterPreset::IP3. NOT a prime-width gate (IP2's backward
// primes also fit 32 bits, but IP2 is now u64-numeric).

// Bitmask for selective eval key loading. Skipped components are read past but
// not stored — this lets compute nodes load only the backward L0 keys without
// allocating memory for huge transpose / forward key tables.
enum class EvalKeyComponents : uint32_t {
    Relin = 1u << 0,
    ModPack = 1u << 1,
    Transpose = 1u << 2,  // key_switching_key (DEGREE switch keys for MM/MMS)
    SharedAFwd = 1u << 3, // legacy shared-A + deb QPR forward + off-diagonal
    SharedABwd = 1u << 4, // backward L0 keys (post-PCMM key-switch)
    All = Relin | ModPack | Transpose | SharedAFwd | SharedABwd,
};

inline constexpr EvalKeyComponents operator|(EvalKeyComponents a, EvalKeyComponents b) {
    return static_cast<EvalKeyComponents>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr bool hasComponent(EvalKeyComponents mask, EvalKeyComponents component) {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(component)) != 0;
}

class IKeyPack {
public:
    virtual ~IKeyPack() = default;

    virtual void saveEncKeyFile(const std::string &path) const = 0;
    virtual void getEncKeyBuffer(std::ostream &os) const = 0;
    virtual void loadEncKeyFile(const std::string &path) = 0;
    virtual void loadEncKeyBuffer(std::istream &is) = 0;

    virtual void saveEvalKeyFile(const std::string &path) const = 0;
    virtual void getEvalKeyBuffer(std::ostream &os) const = 0;
    virtual void loadEvalKeyFile(const std::string &path) = 0;
    virtual void loadEvalKeyBuffer(std::istream &is) = 0;
};

class KeyPackData : public IKeyPack {
public:
    KeyPackData() = delete;
    KeyPackData(const evi::detail::Context &context);
    KeyPackData(const evi::detail::Context &context, std::istream &in);
    KeyPackData(const evi::detail::Context &context, const std::string &dir_path);
    ~KeyPackData() = default;

    // override func
    void saveEncKeyFile(const std::string &path) const override;
    void getEncKeyBuffer(std::ostream &os) const override;
    void loadEncKeyFile(const std::string &path) override;
    void loadEncKeyBuffer(std::istream &is) override;

    void saveEvalKeyFile(const std::string &path) const override;
    void getEvalKeyBuffer(std::ostream &os) const override;
    void loadEvalKeyFile(const std::string &path) override;
    void loadEvalKeyBuffer(std::istream &is) override;

    // Selective loading — skips components not in the mask. Skipped data is
    // advanced past in the stream but not allocated/populated.
    void loadEvalKeyFile(const std::string &path, EvalKeyComponents components);
    void loadEvalKeyBuffer(std::istream &is, EvalKeyComponents components);

    // Probe `is` to see whether its remaining payload is a multi-rank archive
    // (utils::serializeEvalKey output) instead of a raw KeyPackData buffer.
    // The stream position is restored before returning.
    //
    // Archive detection mirrors the file-path loader: either the first byte
    // is 'D'/'F' (header-less), or a successful EVIS header read is followed
    // by 'D'/'F'. Returning true means the caller should dispatch to the
    // bundle-handling path; false means continue with raw deserialization.
    static bool peekIsArchive(std::istream &is);

    void serialize(std::ostream &os) const;
    void deserialize(std::istream &is);

    void saveModPackKeyFile(const std::string &path) const;
    void getModPackKeyBuffer(std::ostream &os) const;
    void saveRelinKeyFile(const std::string &path) const;
    void getRelinKeyBuffer(std::ostream &os) const;

    void loadRelinKeyFile(const std::string &path);
    void loadRelinKeyBuffer(std::istream &is);
    void loadModPackKeyFile(const std::string &path);
    void loadModPackKeyBuffer(std::istream &is);

    void save(const std::string &path);

    std::shared_ptr<KeySwitcher> getKeySwitcher(evi::DeviceType device_type = evi::DeviceType::CPU,
                                                bool keyload = true);

    FixedKeyType enckey;
    VariadicKeyType relin_key;
    deb::SwitchKey deb_enc_key;
    // u32-native enc key for u32-native presets (IP3). When engaged, `enckey`
    // / `deb_enc_key` (u64) are left empty: the key lives only as u32, end to
    // end (keygen -> serialize -> load -> encrypt). The packed wire format is
    // byte-identical to the u64 path, so files stay interchangeable.
    std::optional<deb::SwitchKey32> deb_enc_key32;
    deb::SwitchKey deb_relin_key;

    VariadicKeyType mod_pack_key;
    VariadicKeyType shared_a_mod_pack_key;
    VariadicKeyType cc_shared_a_mod_pack_key;
    VariadicKeyType switch_key;
    VariadicKeyType shared_a_key;
    VariadicKeyType reverse_switch_key;
    using TransposeKey32 = std::shared_ptr<Matrix<DataType::CIPHER, u32>>;
    using TransposeKey = std::variant<VariadicKeyType, TransposeKey32>;
    std::vector<TransposeKey> key_switching_key;
    std::vector<VariadicKeyType> additive_shared_a_key;
    deb::SwitchKey deb_mod_pack_key;
    std::vector<deb::SwitchKey> shared_a_fwd_keys;      // nss diagonal QPR keys (s→s_j)
    std::vector<deb::SwitchKey> shared_a_off_diag_keys; // nss*nss off-diagonal bx

    // Backward L0 keys for post-PCMM key-switch (s_j → s), CRT-consistent.
    // One representation per key (variant); routing/rationale: u32 alternative
    // for IP3, u64 for all others (preset==IP3 gate; the IP2->u64 demotion
    // invariant isU32Matrix() <=> IP3). Producer emplaces only the active
    // alternative (no dead second copy); wire format is identical for both
    // widths (bit-packed at bitLength(prime)), so no version bump.
    struct BackwardL0Key {
        // Each: DEGREE values, NTT domain. Exactly one alternative engaged.
        using Poly = std::variant<polyvec, polyvec32>;
        Poly ax_q, ax_p, bx_q, bx_p;

        // Single width-generic accessor. polyvec_t<u64>==polyvec,
        // polyvec_t<u32>==polyvec32, so std::get<polyvec_t<T>> selects the
        // active alternative; it throws std::bad_variant_access on a wrong-T
        // access (loud, vs. the old silent dual-residency bug). Both generic-T
        // consumers (backward-KS) and width-explicit sites (KeyValidationTest's
        // IP2->poly<u64> / IP3->poly<u32> checks) use this one accessor.
        template <class T>
        static polyvec_t<T> &poly(Poly &m) {
            return std::get<polyvec_t<T>>(m);
        }
        template <class T>
        static const polyvec_t<T> &poly(const Poly &m) {
            return std::get<polyvec_t<T>>(m);
        }
    };
    std::vector<BackwardL0Key> shared_a_bwd_l0_keys; // nss keys

    int num_shared_secret;

    bool shared_a_key_loaded_;
    bool shared_a_mod_pack_loaded_;
    bool cc_shared_a_mod_pack_loaded_;
    bool enc_loaded_;
    bool eval_loaded_;
    bool keyswitcher_cpu_loaded_;
    bool keyswitcher_gpu_loaded_;
    std::shared_ptr<KeySwitcher> keyswitcher_cpu_;
    std::shared_ptr<KeySwitcher> keyswitcher_gpu_;

private:
    // Bit-packs the 4 enc-key polys (ax_q, ax_p, bx_q, bx_p). Picks the u32
    // (IP3, deb_enc_key32) or u64 (enckey) source; the packed wire is byte-
    // identical for both widths. Shared by getEncKeyBuffer and serialize.
    void writeEncKeyPacked(std::ostream &os, uint8_t q_bits, uint8_t p_bits) const;

    mutable std::mutex keyswitcher_mtx_;

    const evi::detail::Context context_;
};

using KeyPack = std::shared_ptr<IKeyPack>;

KeyPack makeKeyPack(const evi::detail::Context &context);
KeyPack makeKeyPack(const evi::detail::Context &context, std::istream &in);
KeyPack makeKeyPack(const evi::detail::Context &context, const std::string &dir_path);

} // namespace detail
} // namespace evi
