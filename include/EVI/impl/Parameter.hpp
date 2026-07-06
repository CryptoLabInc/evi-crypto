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
#include "EVI/impl/Basic.cuh"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Type.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace evi {
namespace detail {

// NOLINTBEGIN(readability-identifier-naming)
//
// Prime storage layout (CKKS RNS chain).
//
// Each preset exposes its primes via two compile-time arrays:
//   PRIMES_Q[] - ciphertext-limb (chain) primes, in deb-param order.
//   PRIMES_P[] - key-switch (auxiliary) primes, in deb-param order.
//
// Mapping per preset (matches external/deb-param.json):
//   IP0: PRIMES_Q = [old_Q, old_T],   PRIMES_P = []
//        (deb calls old_T a "T-prime" / NUM_TP=1; evi reinterprets it as a
//         second limb — IP0 is IP-only, no relin/key-switch, so there
//         is no genuine key-switch aux. PRIMES_P is empty for IP0.)
//   IP1: PRIMES_Q = [old_Q, old_P],   PRIMES_P = [old_R]
//   IP2: PRIMES_Q = [old_Q, old_P],   PRIMES_P = [old_R]
//   QF : PRIMES_Q = [old_Q],          PRIMES_P = [old_P]
//
// EVIS v1 wire compatibility (HARD CONSTRAINT):
//   deb_primes[0] = PRIMES_Q[0]           (q_bits header byte)
//   deb_primes[1] = (NUM_Q>1) ? PRIMES_Q[1] : PRIMES_P[0]  (p_bits header byte)
//
// Use the deb_prime_at(param, i) helper (defined at the bottom of this
// header) to retrieve the i-th deb-flat prime in a preset-agnostic way.
//
// New code must use the indexed accessors getQ(i) / getP(i) / getNumQ() /
// getNumP() directly. The legacy scalar aliases (PRIME_Q, PRIME_P, PRIME_R,
// TWO_PRIME_Q/P, HALF_PRIME_Q/P, TWO_TO_64_Q/P, TWO_TO_64_SHOUP_Q/P,
// BARRETT_RATIO_FOR_U64_Q/P, INV_DEGREE_Q/P, INV_DEGREE_SHOUP_Q/P) and the
// virtual methods getPrimeQ() / getPrimeP() / getPrimeR() / getTwoPrimeQ() /
// getTwoPrimeP() (no-arg) etc. have all been removed. Use the indexed forms
// getTwoPrimeQ(i) / getTwoPrimeP(i) / getBarrRatioQ(i) etc. instead.
struct ConstantPreset {
    virtual u64 getPsiQ() const = 0;
    virtual u64 getPsiP() const = 0;
    // Indexed derived-constant accessors.
    // getTwoPrimeQ(i)   = TWO_PRIMES_Q[i]  (2 * PRIMES_Q[i])
    // getTwoPrimeP(i)   = TWO_PRIMES_P[i]  (2 * PRIMES_P[i])
    // Same for getHalfPrime, getTwoTo64, getTwoTo64Shoup,
    // getBarrRatio, getInvDegree, getInvDegreeShoup.
    //
    // NOTE: For IP1+, PRIMES_P[0] is the aux key-switch prime (old R).
    // deb-flat[1] is PRIMES_Q[1] for IP0/IP1+, PRIMES_P[0] for QF.
    // IP0 is now a multi-Q preset (NumQ=2, NumP=0); QF is single-Q (NumQ=1, NumP=1).
    // Code that wants deb-flat[1] must use:
    //   (getNumQ() > 1 ? getTwoPrimeQ(1) : getTwoPrimeP(0))
    // or the deb_prime_at() helper.
    virtual u64 getTwoPrimeQ(uint32_t i) const = 0;
    virtual u64 getTwoPrimeP(uint32_t i) const = 0;
    virtual u64 getHalfPrimeQ(uint32_t i) const = 0;
    virtual u64 getHalfPrimeP(uint32_t i) const = 0;
    virtual u64 getTwoTo64Q(uint32_t i) const = 0;
    virtual u64 getTwoTo64P(uint32_t i) const = 0;
    virtual u64 getTwoTo64ShoupQ(uint32_t i) const = 0;
    virtual u64 getTwoTo64ShoupP(uint32_t i) const = 0;

    virtual u64 getBarrRatioQ(uint32_t i) const = 0;
    virtual u64 getBarrRatioP(uint32_t i) const = 0;
    virtual u64 getPModQ() const = 0;
    virtual u64 getModDownProdInverseModEnd() const = 0;
    virtual u64 getInvDegreeQ(uint32_t i) const = 0;
    virtual u64 getInvDegreeP(uint32_t i) const = 0;
    virtual u64 getInvDegreeShoupQ(uint32_t i) const = 0;
    virtual u64 getInvDegreeShoupP(uint32_t i) const = 0;

    virtual u32 getHW() const = 0;
    virtual double getScaleFactor() const = 0;
    virtual double getDBScaleFactor() const {
        return getScaleFactor();
    }
    virtual double getQueryScaleFactor() const {
        return getScaleFactor();
    }

    virtual ParameterPreset getPreset() const = 0;

    // ----- Indexed prime accessors -------------------------------------------
    //
    // Per-preset RNS chain (PRIMES_Q[]) and aux key-switch primes (PRIMES_P[]).
    // Indices are in deb-param order; getNumQ()+getNumP() == NUM_DEB_PRIMES.
    virtual u64 getQ(uint32_t i) const = 0;
    virtual u64 getP(uint32_t i) const = 0;
    virtual uint32_t getNumQ() const = 0;
    virtual uint32_t getNumP() const = 0;

    // Backward L0 key primes for MMS post-PCMM key-switch.
    //
    // IP1 MMS flow uses base conversion IP1→IP0, so the backward keys are
    // stored mod IP0 primes. IP2 MMS has no base conversion — backward keys
    // stay in IP2 primes. IP0 has no MMS flow today; default falls back to
    // own primes.
    //
    // Centralizing this avoids the `q <= UINT32_MAX` heuristic leaking into
    // serialization, keygen, and runtime KS sites.
    virtual u64 getBackwardKeyQ() const {
        return getQ(0);
    }
    virtual u64 getBackwardKeyP() const {
        // deb-flat[1]: the second prime in the deb-param chain.
        // For multi-Q presets (IP0/IP1/IP2/IP3) this is PRIMES_Q[1].
        // For single-Q presets (QF) this is the aux prime PRIMES_P[0].
        return getNumQ() > 1 ? getQ(1) : getP(0);
    }
    virtual ParameterPreset getBackwardKeyPreset() const {
        return getPreset();
    }
};

struct IPBase : ConstantPreset {
public:
    IPBase() = default;
    ~IPBase() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ(uint32_t i) const override {
        return TWO_PRIMES_Q[i];
    }
    u64 getTwoPrimeP(uint32_t i) const override {
        return TWO_PRIMES_P[i];
    }
    u64 getHalfPrimeQ(uint32_t i) const override {
        return HALF_PRIMES_Q[i];
    }
    u64 getHalfPrimeP(uint32_t i) const override {
        return HALF_PRIMES_P[i];
    }
    u64 getTwoTo64Q(uint32_t i) const override {
        return TWO_TO_64S_Q[i];
    }
    u64 getTwoTo64P(uint32_t i) const override {
        return TWO_TO_64S_P[i];
    }
    u64 getTwoTo64ShoupQ(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_Q[i];
    }
    u64 getTwoTo64ShoupP(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_P[i];
    }
    u64 getBarrRatioQ(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_Q[i];
    }
    u64 getBarrRatioP(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_P[i];
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t i) const override {
        return INV_DEGREES_Q[i];
    }
    u64 getInvDegreeP(uint32_t i) const override {
        return INV_DEGREES_P[i];
    }
    u64 getInvDegreeShoupQ(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_Q[i];
    }
    u64 getInvDegreeShoupP(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_P[i];
    }

    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }

    ParameterPreset getPreset() const override {
        return preset;
    }

    // Prime arrays (deb-param order).
    //
    // IP0 has two chain primes (Q[0]=51b, Q[1]=55b) and no aux key-switch primes.
    // deb-param.json calls Q[1] a "T-prime" (NUM_TP=1); evi reinterprets it as a
    // second limb. IP0 is IP-only (no relin/key-switch), so PRIMES_P = [].
    // EVIS v1 wire: q_bits = bitLen(PRIMES_Q[0]), p_bits = bitLen(PRIMES_Q[1]).
    static constexpr std::array<u64, 2> PRIMES_Q = {2251799813554177ULL,   // [Q=51b]
                                                    36028797014376449ULL}; // [T=55b, rebranded limb]
    static constexpr std::array<u64, 0> PRIMES_P = {};

    static constexpr u64 PSI_Q = 278055349447;
    static constexpr u64 PSI_P = 115736144453; // twiddle for PRIMES_Q[1] (kept for NTT init)

    // Indexed accessors.
    u64 getQ(uint32_t i) const override {
        return PRIMES_Q[i];
    }
    u64 getP(uint32_t /*i*/) const override {
        return 0; // IP0 has no aux key-switch primes
    }
    uint32_t getNumQ() const override {
        return PRIMES_Q.size();
    }
    uint32_t getNumP() const override {
        return 0;
    }

    // ----- Per-prime derived constants (array form; deb-param order) ----------
    //
    // IP0 has NumQ=2, NumP=0.
    //   TWO_PRIMES_Q[i]                 = PRIMES_Q[i] << 1
    //   HALF_PRIMES_Q[i]                = PRIMES_Q[i] >> 1
    //   TWO_TO_64S_Q[i]                 = 2^64 mod PRIMES_Q[i]
    //   TWO_TO_64_SHOUPS_Q[i]           = Shoup form of 2^64 mod PRIMES_Q[i]
    //   BARRETT_RATIOS_FOR_U64_Q[i]     = floor(2^128 / PRIMES_Q[i]) lo word
    //   INV_DEGREES_Q[i]                = N^(-1) mod PRIMES_Q[i]
    //   INV_DEGREES_SHOUPS_Q[i]         = Shoup form of INV_DEGREES_Q[i]
    //
    // P-side derived constants are empty (NumP=0). GPU/CPU kernel template
    // parameters that previously used IPBase::PRIMES_P[0] / TWO_PRIMES_P[0] etc.
    // now use IPBase::PRIMES_Q[1] / TWO_PRIMES_Q[1] etc. directly.
    static constexpr std::array<u64, 2> TWO_PRIMES_Q = {PRIMES_Q[0] << 1, PRIMES_Q[1] << 1};
    static constexpr std::array<u64, 0> TWO_PRIMES_P = {};
    static constexpr std::array<u64, 2> HALF_PRIMES_Q = {PRIMES_Q[0] >> 1, PRIMES_Q[1] >> 1};
    static constexpr std::array<u64, 0> HALF_PRIMES_P = {};
    static constexpr std::array<u64, 2> TWO_TO_64S_Q = {powModSimple(2, 64, PRIMES_Q[0]),
                                                        powModSimple(2, 64, PRIMES_Q[1])};
    static constexpr std::array<u64, 0> TWO_TO_64S_P = {};
    static constexpr std::array<u64, 2> TWO_TO_64_SHOUPS_Q = {divide128By64Lo(TWO_TO_64S_Q[0], 0, PRIMES_Q[0]),
                                                              divide128By64Lo(TWO_TO_64S_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 0> TWO_TO_64_SHOUPS_P = {};
    static constexpr std::array<u64, 2> BARRETT_RATIOS_FOR_U64_Q = {divide128By64Lo(1, 0, PRIMES_Q[0]),
                                                                    divide128By64Lo(1, 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 0> BARRETT_RATIOS_FOR_U64_P = {};
    static constexpr std::array<u64, 2> INV_DEGREES_Q = {powModSimple(DEGREE, PRIMES_Q[0] - 2, PRIMES_Q[0]),
                                                         powModSimple(DEGREE, PRIMES_Q[1] - 2, PRIMES_Q[1])};
    static constexpr std::array<u64, 0> INV_DEGREES_P = {};
    static constexpr std::array<u64, 2> INV_DEGREES_SHOUPS_Q = {divide128By64Lo(INV_DEGREES_Q[0], 0, PRIMES_Q[0]),
                                                                divide128By64Lo(INV_DEGREES_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 0> INV_DEGREES_SHOUPS_P = {};

    // Cross-prime constants (single use sites).
    // IP0: deb-flat[1] = PRIMES_Q[1] (multi-Q preset, second limb).
    static constexpr u64 PMOD_Q = reduceBarrett(PRIMES_Q[0], BARRETT_RATIOS_FOR_U64_Q[0], PRIMES_Q[1]);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIMES_Q[1], PRIMES_Q[0] - 2, PRIMES_Q[0]);

    static constexpr u32 HAMMING_WEIGHT = 2730;
    static constexpr double SCALE_FACTOR = 24.0;
    static constexpr ParameterPreset preset = ParameterPreset::IP0;
};

// IPBase is historically the IP0 preset struct (it predates IP1/IP2/IP3).
// IP0Base is the preferred name in new code; IPBase is kept as the canonical
// definition for now to avoid churning hundreds of in-tree references.
using IP0Base = IPBase;

struct IP1Base : ConstantPreset {
public:
    IP1Base() = default;
    ~IP1Base() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ(uint32_t i) const override {
        return TWO_PRIMES_Q[i];
    }
    u64 getTwoPrimeP(uint32_t i) const override {
        return TWO_PRIMES_P[i];
    }
    u64 getHalfPrimeQ(uint32_t i) const override {
        return HALF_PRIMES_Q[i];
    }
    u64 getHalfPrimeP(uint32_t i) const override {
        return HALF_PRIMES_P[i];
    }
    u64 getTwoTo64Q(uint32_t i) const override {
        return TWO_TO_64S_Q[i];
    }
    u64 getTwoTo64P(uint32_t i) const override {
        return TWO_TO_64S_P[i];
    }
    u64 getTwoTo64ShoupQ(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_Q[i];
    }
    u64 getTwoTo64ShoupP(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_P[i];
    }
    u64 getBarrRatioQ(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_Q[i];
    }
    u64 getBarrRatioP(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_P[i];
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t i) const override {
        return INV_DEGREES_Q[i];
    }
    u64 getInvDegreeP(uint32_t i) const override {
        return INV_DEGREES_P[i];
    }
    u64 getInvDegreeShoupQ(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_Q[i];
    }
    u64 getInvDegreeShoupP(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_P[i];
    }

    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }

    double getDBScaleFactor() const override {
        return DB_SCALE_FACTOR;
    }

    double getQueryScaleFactor() const override {
        return QUERY_SCALE_FACTOR;
    }

    ParameterPreset getPreset() const override {
        return preset;
    }

    // IP1 MMS base-converts to IP0 before backward KS, so backward keys
    // use IP0 primes (not own IP1 primes).
    u64 getBackwardKeyQ() const override {
        return IPBase::PRIMES_Q[0];
    }
    u64 getBackwardKeyP() const override {
        // IP0 is now a multi-Q preset (NumQ=2, NumP=0), so deb-flat[1] = PRIMES_Q[1].
        return IPBase::PRIMES_Q[1];
    }
    ParameterPreset getBackwardKeyPreset() const override {
        return ParameterPreset::IP0;
    }

    // Prime arrays (deb-param order).
    //
    // IP1 chain has 2 primes (Q[0], Q[1]), aux has 1 prime (P[0] = old R).
    // EVIS v1 wire: q_bits = bitLen(PRIMES_Q[0]), p_bits = bitLen(PRIMES_Q[1]).
    static constexpr std::array<u64, 2> PRIMES_Q = {17179754497ULL, 17179672577ULL};
    static constexpr std::array<u64, 1> PRIMES_P = {274877562881ULL};

    static constexpr u64 PSI_Q = 0;
    static constexpr u64 PSI_P = 0;
    static constexpr u64 PSI_R = 0;

    // Indexed accessors.
    u64 getQ(uint32_t i) const override {
        return PRIMES_Q[i];
    }
    u64 getP(uint32_t i) const override {
        return PRIMES_P[i];
    }
    uint32_t getNumQ() const override {
        return PRIMES_Q.size();
    }
    uint32_t getNumP() const override {
        return PRIMES_P.size();
    }

    // ----- Per-prime derived constants (array form; deb-param order) ----------
    //
    // IP1 has NumQ=2, NumP=1.
    // getTwoPrimeP(0) = TWO_PRIMES_P[0] = 2 * PRIMES_P[0] (aux R prime).
    // deb-flat[1] = PRIMES_Q[1]; use getNumQ()>1 ? getTwoPrimeQ(1) : getTwoPrimeP(0) for chain[1].
    static constexpr std::array<u64, 2> TWO_PRIMES_Q = {PRIMES_Q[0] << 1, PRIMES_Q[1] << 1};
    static constexpr std::array<u64, 1> TWO_PRIMES_P = {PRIMES_P[0] << 1};
    static constexpr std::array<u64, 2> HALF_PRIMES_Q = {PRIMES_Q[0] >> 1, PRIMES_Q[1] >> 1};
    static constexpr std::array<u64, 1> HALF_PRIMES_P = {PRIMES_P[0] >> 1};
    static constexpr std::array<u64, 2> TWO_TO_64S_Q = {powModSimple(2, 64, PRIMES_Q[0]),
                                                        powModSimple(2, 64, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> TWO_TO_64S_P = {powModSimple(2, 64, PRIMES_P[0])};
    static constexpr std::array<u64, 2> TWO_TO_64_SHOUPS_Q = {divide128By64Lo(TWO_TO_64S_Q[0], 0, PRIMES_Q[0]),
                                                              divide128By64Lo(TWO_TO_64S_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> TWO_TO_64_SHOUPS_P = {divide128By64Lo(TWO_TO_64S_P[0], 0, PRIMES_P[0])};
    static constexpr std::array<u64, 2> BARRETT_RATIOS_FOR_U64_Q = {divide128By64Lo(1, 0, PRIMES_Q[0]),
                                                                    divide128By64Lo(1, 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> BARRETT_RATIOS_FOR_U64_P = {divide128By64Lo(1, 0, PRIMES_P[0])};
    static constexpr std::array<u64, 2> INV_DEGREES_Q = {powModSimple(DEGREE, PRIMES_Q[0] - 2, PRIMES_Q[0]),
                                                         powModSimple(DEGREE, PRIMES_Q[1] - 2, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> INV_DEGREES_P = {powModSimple(DEGREE, PRIMES_P[0] - 2, PRIMES_P[0])};
    static constexpr std::array<u64, 2> INV_DEGREES_SHOUPS_Q = {divide128By64Lo(INV_DEGREES_Q[0], 0, PRIMES_Q[0]),
                                                                divide128By64Lo(INV_DEGREES_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> INV_DEGREES_SHOUPS_P = {divide128By64Lo(INV_DEGREES_P[0], 0, PRIMES_P[0])};

    // Cross-prime constants (single use sites).
    // IP1: deb-flat[1] = PRIMES_Q[1] (multi-Q preset, so P-side is chain[1]).
    static constexpr u64 PMOD_Q = reduceBarrett(PRIMES_Q[0], BARRETT_RATIOS_FOR_U64_Q[0], PRIMES_Q[1]);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIMES_Q[1], PRIMES_Q[0] - 2, PRIMES_Q[0]);

    static constexpr u32 HAMMING_WEIGHT = 2730;
    static constexpr double SCALE_FACTOR = 32.41502786830222504477205802686512470245361328125L;
    static constexpr double DB_SCALE_FACTOR = 50.207497423806131564560928381979465484619140625L;
    static constexpr double QUERY_SCALE_FACTOR = 16.207513934151112522386029013432562351226806640625L;

    static constexpr ParameterPreset preset = ParameterPreset::IP1;
};

struct IP2Base : ConstantPreset {
public:
    IP2Base() = default;
    ~IP2Base() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }
    u64 getTwoPrimeQ(uint32_t i) const override {
        return TWO_PRIMES_Q[i];
    }
    u64 getTwoPrimeP(uint32_t i) const override {
        return TWO_PRIMES_P[i];
    }
    u64 getHalfPrimeQ(uint32_t i) const override {
        return HALF_PRIMES_Q[i];
    }
    u64 getHalfPrimeP(uint32_t i) const override {
        return HALF_PRIMES_P[i];
    }
    u64 getTwoTo64Q(uint32_t i) const override {
        return TWO_TO_64S_Q[i];
    }
    u64 getTwoTo64P(uint32_t i) const override {
        return TWO_TO_64S_P[i];
    }
    u64 getTwoTo64ShoupQ(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_Q[i];
    }
    u64 getTwoTo64ShoupP(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_P[i];
    }
    u64 getBarrRatioQ(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_Q[i];
    }
    u64 getBarrRatioP(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_P[i];
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t i) const override {
        return INV_DEGREES_Q[i];
    }
    u64 getInvDegreeP(uint32_t i) const override {
        return INV_DEGREES_P[i];
    }
    u64 getInvDegreeShoupQ(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_Q[i];
    }
    u64 getInvDegreeShoupP(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_P[i];
    }
    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }
    double getDBScaleFactor() const override {
        return DB_SCALE_FACTOR;
    }
    double getQueryScaleFactor() const override {
        return QUERY_SCALE_FACTOR;
    }
    ParameterPreset getPreset() const override {
        return preset;
    }

    // Prime arrays (deb-param order).
    //
    // IP2 chain has 2 primes (Q[0], Q[1]), aux has a single 42-bit prime P[0].
    // EVIS v1 wire: q_bits = bitLen(PRIMES_Q[0]), p_bits = bitLen(PRIMES_Q[1]).
    // NTT primes: p = 1 (mod 8192).
    //
    // The IP2 aux P is NOT split into two 32-bit limbs (unlike IP3). IP2 is
    // already deployed; splitting P would change the on-disk eval-key wire
    // layout (eval keys serialize all deb primes including aux — see
    // crypto/src/KeyPackImpl.cpp), and re-derivation of new aux primes from
    // the old single-P-limb wire is not possible (different prime domain).
    // IP3 is greenfield and uses the split-P layout for its u32-native path.
    // logQPR for IP2 = 32 + 32 + 42 = 106 (security ~2^130.2).
    static constexpr std::array<u64, 2> PRIMES_Q = {4294828033ULL, 4294729729ULL};
    static constexpr std::array<u64, 1> PRIMES_P = {4398046486529ULL};

    static constexpr u64 PSI_Q = 567303915;
    // PSI_P here is the NTT twiddle for the second deb-flat limb, which for
    // multi-Q presets (IP0/IP1/IP2/IP3) is PRIMES_Q[1] — NOT for PRIMES_P.
    // Per-PRIMES_P twiddles are precomputed per-prime by ModArith<4096>(prime)
    // at construction; no consumer reads PSI_P against the aux P prime.
    static constexpr u64 PSI_P = 228263120; // twiddle for PRIMES_Q[1] (kept for NTT init)
    static constexpr u64 PSI_R = 0;

    // Indexed accessors.
    u64 getQ(uint32_t i) const override {
        return PRIMES_Q[i];
    }
    u64 getP(uint32_t i) const override {
        return PRIMES_P[i];
    }
    uint32_t getNumQ() const override {
        return PRIMES_Q.size();
    }
    uint32_t getNumP() const override {
        return PRIMES_P.size();
    }

    // ----- Per-prime derived constants (array form; deb-param order) ----------
    //
    // IP2 has NumQ=2, NumP=1.
    // getTwoPrimeP(0) = TWO_PRIMES_P[0] = 2 * PRIMES_P[0] (aux R prime).
    // deb-flat[1] = PRIMES_Q[1]; use getNumQ()>1 ? getTwoPrimeQ(1) : getTwoPrimeP(0) for chain[1].
    static constexpr std::array<u64, 2> TWO_PRIMES_Q = {PRIMES_Q[0] << 1, PRIMES_Q[1] << 1};
    static constexpr std::array<u64, 1> TWO_PRIMES_P = {PRIMES_P[0] << 1};
    static constexpr std::array<u64, 2> HALF_PRIMES_Q = {PRIMES_Q[0] >> 1, PRIMES_Q[1] >> 1};
    static constexpr std::array<u64, 1> HALF_PRIMES_P = {PRIMES_P[0] >> 1};
    static constexpr std::array<u64, 2> TWO_TO_64S_Q = {powModSimple(2, 64, PRIMES_Q[0]),
                                                        powModSimple(2, 64, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> TWO_TO_64S_P = {powModSimple(2, 64, PRIMES_P[0])};
    static constexpr std::array<u64, 2> TWO_TO_64_SHOUPS_Q = {divide128By64Lo(TWO_TO_64S_Q[0], 0, PRIMES_Q[0]),
                                                              divide128By64Lo(TWO_TO_64S_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> TWO_TO_64_SHOUPS_P = {divide128By64Lo(TWO_TO_64S_P[0], 0, PRIMES_P[0])};
    static constexpr std::array<u64, 2> BARRETT_RATIOS_FOR_U64_Q = {divide128By64Lo(1, 0, PRIMES_Q[0]),
                                                                    divide128By64Lo(1, 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> BARRETT_RATIOS_FOR_U64_P = {divide128By64Lo(1, 0, PRIMES_P[0])};
    static constexpr std::array<u64, 2> INV_DEGREES_Q = {powModSimple(DEGREE, PRIMES_Q[0] - 2, PRIMES_Q[0]),
                                                         powModSimple(DEGREE, PRIMES_Q[1] - 2, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> INV_DEGREES_P = {powModSimple(DEGREE, PRIMES_P[0] - 2, PRIMES_P[0])};
    static constexpr std::array<u64, 2> INV_DEGREES_SHOUPS_Q = {divide128By64Lo(INV_DEGREES_Q[0], 0, PRIMES_Q[0]),
                                                                divide128By64Lo(INV_DEGREES_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 1> INV_DEGREES_SHOUPS_P = {divide128By64Lo(INV_DEGREES_P[0], 0, PRIMES_P[0])};

    // Cross-prime constants (single use sites).
    // IP2: deb-flat[1] = PRIMES_Q[1] (multi-Q preset, so P-side is chain[1]).
    static constexpr u64 PMOD_Q = reduceBarrett(PRIMES_Q[0], BARRETT_RATIOS_FOR_U64_Q[0], PRIMES_Q[1]);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIMES_Q[1], PRIMES_Q[0] - 2, PRIMES_Q[0]);

    static constexpr u32 HAMMING_WEIGHT = 2730;

    // AM-GM optimal for 32-bit primes
    // Total = log2(Q*P) - log2(3) = 62.415
    // Post-rescale: total - log2(P) = 30.415 (single 42-bit P).
    static constexpr double SCALE_FACTOR = 30.4149907195753;
    static constexpr double DB_SCALE_FACTOR = 50.0610951224477;
    static constexpr double QUERY_SCALE_FACTOR = 12.353815795306446;

    static constexpr ParameterPreset preset = ParameterPreset::IP2;
};

struct IP3Base : ConstantPreset {
public:
    IP3Base() = default;
    ~IP3Base() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }
    u64 getTwoPrimeQ(uint32_t i) const override {
        return TWO_PRIMES_Q[i];
    }
    u64 getTwoPrimeP(uint32_t i) const override {
        return TWO_PRIMES_P[i];
    }
    u64 getHalfPrimeQ(uint32_t i) const override {
        return HALF_PRIMES_Q[i];
    }
    u64 getHalfPrimeP(uint32_t i) const override {
        return HALF_PRIMES_P[i];
    }
    u64 getTwoTo64Q(uint32_t i) const override {
        return TWO_TO_64S_Q[i];
    }
    u64 getTwoTo64P(uint32_t i) const override {
        return TWO_TO_64S_P[i];
    }
    u64 getTwoTo64ShoupQ(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_Q[i];
    }
    u64 getTwoTo64ShoupP(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_P[i];
    }
    u64 getBarrRatioQ(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_Q[i];
    }
    u64 getBarrRatioP(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_P[i];
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t i) const override {
        return INV_DEGREES_Q[i];
    }
    u64 getInvDegreeP(uint32_t i) const override {
        return INV_DEGREES_P[i];
    }
    u64 getInvDegreeShoupQ(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_Q[i];
    }
    u64 getInvDegreeShoupP(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_P[i];
    }
    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }
    double getDBScaleFactor() const override {
        return DB_SCALE_FACTOR;
    }
    double getQueryScaleFactor() const override {
        return QUERY_SCALE_FACTOR;
    }
    ParameterPreset getPreset() const override {
        return preset;
    }

    // Prime arrays (deb-param order).
    //
    // IP3 NTT primes (Q[0],Q[1] = 30-bit; P[0],P[1] = 23-bit):
    // p = 1 (mod 8192), Q close to 2^30 for max precision while still fitting u32.
    // Like IP2, IP3 MMS has no base conversion — backward keys stay in IP3 primes.
    // The aux key-switch modulus is now split into TWO 23-bit primes (P[0]*P[1]
    // ≈ 46-bit, matching the prior single 46-bit P) so every P-side limb fits
    // u32 storage and the u32 Barrett path (4*p < 2^32) is usable on P as well.
    // logQPR = 30+30+23+23 = 106, identical to the prior layout
    // (security ~2^130.2).
    //
    // IP3 chain has 2 primes (Q[0], Q[1]), aux has 2 primes (P[0], P[1]).
    // EVIS v1 wire: q_bits = bitLen(PRIMES_Q[0]), p_bits = bitLen(PRIMES_Q[1]).
    //
    // Every IP3 prime (Q[0]=30b, Q[1]=30b, P[0]=23b, P[1]=23b) fits u32.
    // The eventual goal is a u32-native storage path so the encrypt ->
    // transpose -> shared-A -> PCMM -> decrypt flow never widens to u64.
    // Storage stays u64 in this PR; the u32 narrow is deferred until the
    // dependent code paths (rescale loop, toSharedA, deb<->evi key
    // interface) are audited for NumP=2 correctness.
    static constexpr std::array<u64, 2> PRIMES_Q = {1073692673ULL, 1073668097ULL};
    static constexpr std::array<u64, 2> PRIMES_P = {8380417ULL, 8273921ULL};

    static constexpr u64 PSI_Q = 0; // populated by NTT precompute pass
    static constexpr u64 PSI_P = 0;
    static constexpr u64 PSI_R = 0;

    // Indexed accessors.
    u64 getQ(uint32_t i) const override {
        return PRIMES_Q[i];
    }
    u64 getP(uint32_t i) const override {
        return PRIMES_P[i];
    }
    uint32_t getNumQ() const override {
        return PRIMES_Q.size();
    }
    uint32_t getNumP() const override {
        return PRIMES_P.size();
    }

    // ----- Per-prime derived constants (array form; deb-param order) ----------
    //
    // IP3 has NumQ=2, NumP=2.
    // getTwoPrimeP(i) = TWO_PRIMES_P[i] = 2 * PRIMES_P[i] (aux primes).
    // deb-flat[1] = PRIMES_Q[1]; use getNumQ()>1 ? getTwoPrimeQ(1) : getTwoPrimeP(0) for chain[1].
    static constexpr std::array<u64, 2> TWO_PRIMES_Q = {PRIMES_Q[0] << 1, PRIMES_Q[1] << 1};
    static constexpr std::array<u64, 2> TWO_PRIMES_P = {PRIMES_P[0] << 1, PRIMES_P[1] << 1};
    static constexpr std::array<u64, 2> HALF_PRIMES_Q = {PRIMES_Q[0] >> 1, PRIMES_Q[1] >> 1};
    static constexpr std::array<u64, 2> HALF_PRIMES_P = {PRIMES_P[0] >> 1, PRIMES_P[1] >> 1};
    static constexpr std::array<u64, 2> TWO_TO_64S_Q = {powModSimple(2, 64, PRIMES_Q[0]),
                                                        powModSimple(2, 64, PRIMES_Q[1])};
    static constexpr std::array<u64, 2> TWO_TO_64S_P = {powModSimple(2, 64, PRIMES_P[0]),
                                                        powModSimple(2, 64, PRIMES_P[1])};
    static constexpr std::array<u64, 2> TWO_TO_64_SHOUPS_Q = {divide128By64Lo(TWO_TO_64S_Q[0], 0, PRIMES_Q[0]),
                                                              divide128By64Lo(TWO_TO_64S_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 2> TWO_TO_64_SHOUPS_P = {divide128By64Lo(TWO_TO_64S_P[0], 0, PRIMES_P[0]),
                                                              divide128By64Lo(TWO_TO_64S_P[1], 0, PRIMES_P[1])};
    static constexpr std::array<u64, 2> BARRETT_RATIOS_FOR_U64_Q = {divide128By64Lo(1, 0, PRIMES_Q[0]),
                                                                    divide128By64Lo(1, 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 2> BARRETT_RATIOS_FOR_U64_P = {divide128By64Lo(1, 0, PRIMES_P[0]),
                                                                    divide128By64Lo(1, 0, PRIMES_P[1])};
    static constexpr std::array<u64, 2> INV_DEGREES_Q = {powModSimple(DEGREE, PRIMES_Q[0] - 2, PRIMES_Q[0]),
                                                         powModSimple(DEGREE, PRIMES_Q[1] - 2, PRIMES_Q[1])};
    static constexpr std::array<u64, 2> INV_DEGREES_P = {powModSimple(DEGREE, PRIMES_P[0] - 2, PRIMES_P[0]),
                                                         powModSimple(DEGREE, PRIMES_P[1] - 2, PRIMES_P[1])};
    static constexpr std::array<u64, 2> INV_DEGREES_SHOUPS_Q = {divide128By64Lo(INV_DEGREES_Q[0], 0, PRIMES_Q[0]),
                                                                divide128By64Lo(INV_DEGREES_Q[1], 0, PRIMES_Q[1])};
    static constexpr std::array<u64, 2> INV_DEGREES_SHOUPS_P = {divide128By64Lo(INV_DEGREES_P[0], 0, PRIMES_P[0]),
                                                                divide128By64Lo(INV_DEGREES_P[1], 0, PRIMES_P[1])};

    // Cross-prime constants (single use sites).
    // IP3: deb-flat[1] = PRIMES_Q[1] (multi-Q preset, so P-side is chain[1]).
    static constexpr u64 PMOD_Q = reduceBarrett(PRIMES_Q[0], BARRETT_RATIOS_FOR_U64_Q[0], PRIMES_Q[1]);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIMES_Q[1], PRIMES_Q[0] - 2, PRIMES_Q[0]);

    static constexpr u32 HAMMING_WEIGHT = 2730;

    // AM-GM optimal for 30-bit primes
    // Total = log2(Q*P) - log2(3) = 58.415
    // Post-rescale: total - log2(P) = 28.415
    // (DB, QUERY) split tuned empirically via pcmm_bench MMS32 sweep at dim=1024.
    static constexpr double SCALE_FACTOR = 28.4149706;
    static constexpr double DB_SCALE_FACTOR = 47.0000000;
    static constexpr double QUERY_SCALE_FACTOR = 11.4149706;

    static constexpr ParameterPreset preset = ParameterPreset::IP3;
};

struct QFBase : ConstantPreset {
public:
    QFBase() = default;
    ~QFBase() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ(uint32_t i) const override {
        return TWO_PRIMES_Q[i];
    }
    u64 getTwoPrimeP(uint32_t i) const override {
        return TWO_PRIMES_P[i];
    }
    u64 getHalfPrimeQ(uint32_t i) const override {
        return HALF_PRIMES_Q[i];
    }
    u64 getHalfPrimeP(uint32_t i) const override {
        return HALF_PRIMES_P[i];
    }
    u64 getTwoTo64Q(uint32_t i) const override {
        return TWO_TO_64S_Q[i];
    }
    u64 getTwoTo64P(uint32_t i) const override {
        return TWO_TO_64S_P[i];
    }
    u64 getTwoTo64ShoupQ(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_Q[i];
    }
    u64 getTwoTo64ShoupP(uint32_t i) const override {
        return TWO_TO_64_SHOUPS_P[i];
    }
    u64 getBarrRatioQ(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_Q[i];
    }
    u64 getBarrRatioP(uint32_t i) const override {
        return BARRETT_RATIOS_FOR_U64_P[i];
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t i) const override {
        return INV_DEGREES_Q[i];
    }
    u64 getInvDegreeP(uint32_t i) const override {
        return INV_DEGREES_P[i];
    }
    u64 getInvDegreeShoupQ(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_Q[i];
    }
    u64 getInvDegreeShoupP(uint32_t i) const override {
        return INV_DEGREES_SHOUPS_P[i];
    }

    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }
    ParameterPreset getPreset() const override {
        return preset;
    }

    // Prime arrays (deb-param order).
    //
    // QF has a single chain prime (Q) and a single aux key-switch prime (P).
    static constexpr std::array<u64, 1> PRIMES_Q = {288230376135196673ULL};
    static constexpr std::array<u64, 1> PRIMES_P = {2251799810670593ULL};

    static constexpr u64 PSI_Q = 60193018759093;
    static constexpr u64 PSI_P = 254746317487;

    // Indexed accessors.
    u64 getQ(uint32_t i) const override {
        return PRIMES_Q[i];
    }
    u64 getP(uint32_t i) const override {
        return PRIMES_P[i];
    }
    uint32_t getNumQ() const override {
        return PRIMES_Q.size();
    }
    uint32_t getNumP() const override {
        return PRIMES_P.size();
    }

    // ----- Per-prime derived constants (array form; deb-param order) ----------
    //
    // QF has NumQ=1, NumP=1. getTwoPrimeP(i) indexes TWO_PRIMES_P[i].
    static constexpr std::array<u64, 1> TWO_PRIMES_Q = {PRIMES_Q[0] << 1};
    static constexpr std::array<u64, 1> TWO_PRIMES_P = {PRIMES_P[0] << 1};
    static constexpr std::array<u64, 1> HALF_PRIMES_Q = {PRIMES_Q[0] >> 1};
    static constexpr std::array<u64, 1> HALF_PRIMES_P = {PRIMES_P[0] >> 1};
    static constexpr std::array<u64, 1> TWO_TO_64S_Q = {powModSimple(2, 64, PRIMES_Q[0])};
    static constexpr std::array<u64, 1> TWO_TO_64S_P = {powModSimple(2, 64, PRIMES_P[0])};
    static constexpr std::array<u64, 1> TWO_TO_64_SHOUPS_Q = {divide128By64Lo(TWO_TO_64S_Q[0], 0, PRIMES_Q[0])};
    static constexpr std::array<u64, 1> TWO_TO_64_SHOUPS_P = {divide128By64Lo(TWO_TO_64S_P[0], 0, PRIMES_P[0])};
    static constexpr std::array<u64, 1> BARRETT_RATIOS_FOR_U64_Q = {divide128By64Lo(1, 0, PRIMES_Q[0])};
    static constexpr std::array<u64, 1> BARRETT_RATIOS_FOR_U64_P = {divide128By64Lo(1, 0, PRIMES_P[0])};
    static constexpr std::array<u64, 1> INV_DEGREES_Q = {powModSimple(DEGREE, PRIMES_Q[0] - 2, PRIMES_Q[0])};
    static constexpr std::array<u64, 1> INV_DEGREES_P = {powModSimple(DEGREE, PRIMES_P[0] - 2, PRIMES_P[0])};
    static constexpr std::array<u64, 1> INV_DEGREES_SHOUPS_Q = {divide128By64Lo(INV_DEGREES_Q[0], 0, PRIMES_Q[0])};
    static constexpr std::array<u64, 1> INV_DEGREES_SHOUPS_P = {divide128By64Lo(INV_DEGREES_P[0], 0, PRIMES_P[0])};

    // Cross-prime constants (single use sites).
    // QF: deb-flat[1] = PRIMES_P[0] (single-Q preset, so P-side is aux).
    static constexpr u64 PMOD_Q = reduceBarrett(PRIMES_Q[0], BARRETT_RATIOS_FOR_U64_Q[0], PRIMES_P[0]);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIMES_P[0], PRIMES_Q[0] - 2, PRIMES_Q[0]);

    static constexpr u32 HAMMING_WEIGHT = 2730;
    static constexpr double SCALE_FACTOR = 25.0;
    static constexpr ParameterPreset preset = ParameterPreset::QF0;
};

// RuntimeParam: a 2-prime (single-Q, single-P) runtime-configured preset.
// PRIMES_Q = [prime_q], PRIMES_P = [prime_p].
struct RuntimeParam : ConstantPreset {
public:
    RuntimeParam(u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p, double scale_factor, u32 hw) {
        q_ = prime_q;
        p_ = prime_p;
        PSI_Q = psi_q;
        PSI_P = psi_p;

        TWO_PRIME_Q = q_ << 1;
        TWO_PRIME_P = p_ << 1;
        HALF_PRIME_Q = q_ >> 1;
        HALF_PRIME_P = p_ >> 1;
        TWO_TO_64_Q = powModSimple(2, 64, q_);
        TWO_TO_64_P = powModSimple(2, 64, p_);
        TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, q_);
        TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, p_);
        BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, q_);
        BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, p_);
        PMOD_Q = reduceBarrett(q_, BARRETT_RATIO_FOR_U64_Q, p_);
        MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(p_, q_ - 2, q_);
        INV_DEGREE_Q = powModSimple(DEGREE, q_ - 2, q_);
        INV_DEGREE_P = powModSimple(DEGREE, p_ - 2, p_);
        INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, q_);
        INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, p_);

        SCALE_FACTOR = scale_factor;
        HAMMING_WEIGHT = hw;
        preset_ = ParameterPreset::RUNTIME;
    }
    ~RuntimeParam() = default;

    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    // RuntimeParam is single-Q single-P; i must be 0 for all accessors.
    u64 getTwoPrimeQ(uint32_t /*i*/) const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP(uint32_t /*i*/) const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ(uint32_t /*i*/) const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP(uint32_t /*i*/) const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q(uint32_t /*i*/) const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P(uint32_t /*i*/) const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ(uint32_t /*i*/) const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP(uint32_t /*i*/) const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ(uint32_t /*i*/) const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP(uint32_t /*i*/) const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ(uint32_t /*i*/) const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP(uint32_t /*i*/) const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ(uint32_t /*i*/) const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP(uint32_t /*i*/) const override {
        return INV_DEGREE_SHOUP_P;
    }

    u32 getHW() const override {
        return HAMMING_WEIGHT;
    }

    double getScaleFactor() const override {
        return SCALE_FACTOR;
    }

    ParameterPreset getPreset() const override {
        return preset_;
    }

    // Indexed prime accessors: RuntimeParam is a single-Q, single-P preset.
    // Reject out-of-range indices instead of silently returning 0 — that would
    // be indistinguishable from a valid prime in downstream Barrett / scale
    // computations and could mask caller bugs.
    u64 getQ(uint32_t i) const override {
        if (i != 0) {
            throw std::out_of_range("RuntimeParam::getQ: index out of range (NumQ=1)");
        }
        return q_;
    }
    u64 getP(uint32_t i) const override {
        if (i != 0) {
            throw std::out_of_range("RuntimeParam::getP: index out of range (NumP=1)");
        }
        return p_;
    }
    uint32_t getNumQ() const override {
        return 1;
    }
    uint32_t getNumP() const override {
        return 1;
    }

    // Public member variables: used directly by serialization/key-provider code
    // (e.g. KeyEnvelope.hpp KeyEntryParameter). Use getQ(0)/getP(0) for new code.
    // These remain as public fields since RuntimeParam configures them at
    // construction time (no static constexpr arrays available at runtime).
    u64 PSI_Q;
    u64 PSI_P;

    u64 TWO_PRIME_Q;
    u64 TWO_PRIME_P;
    u64 HALF_PRIME_Q;
    u64 HALF_PRIME_P;
    u64 TWO_TO_64_Q;
    u64 TWO_TO_64_P;
    u64 TWO_TO_64_SHOUP_Q;
    u64 TWO_TO_64_SHOUP_P;
    u64 BARRETT_RATIO_FOR_U64_Q;
    u64 BARRETT_RATIO_FOR_U64_P;
    u64 PMOD_Q;
    u64 MOD_DOWN_PROD_INVERSE_MOD_END;
    u64 INV_DEGREE_Q;
    u64 INV_DEGREE_P;
    u64 INV_DEGREE_SHOUP_Q;
    u64 INV_DEGREE_SHOUP_P;

    u32 HAMMING_WEIGHT;
    double SCALE_FACTOR;

private:
    u64 q_;
    u64 p_;
    ParameterPreset preset_;
};
// NOLINTEND(readability-identifier-naming)

using Parameter = std::shared_ptr<evi::detail::ConstantPreset>;

Parameter setPreset(evi::ParameterPreset name);
Parameter setPreset(evi::ParameterPreset name, u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p, double scale_factor,
                    u32 hw);

// ---------------------------------------------------------------------------
// deb_prime_at(param, i) - EVIS v1 serialization helper
//
// Returns the i-th prime in the deb-flat ordering:
//   deb_primes[0] = PRIMES_Q[0]
//   deb_primes[1] = (NumQ > 1) ? PRIMES_Q[1] : PRIMES_P[0]
//   deb_primes[j] = ... (future extension)
//
// This is the only correct way to derive q_bits / p_bits header bytes for
// EVIS v1 serialization in a preset-agnostic way.
// ---------------------------------------------------------------------------
inline u64 deb_prime_at(const ConstantPreset *param, uint32_t i) {
    // Reject out-of-range indices at runtime (not only in debug builds), since
    // a wrong i would otherwise call getP/getQ with an invalid index and either
    // throw (RuntimeParam) or hit UB on static_array indexing (IPBase/QFBase).
    const uint32_t total = param->getNumQ() + param->getNumP();
    if (i >= total) {
        throw std::out_of_range("deb_prime_at: index out of range");
    }
    if (i < param->getNumQ()) {
        return param->getQ(i);
    }
    return param->getP(i - param->getNumQ());
}

inline u64 deb_prime_at(const Parameter &param, uint32_t i) {
    return deb_prime_at(param.get(), i);
}

} // namespace detail
} // namespace evi
