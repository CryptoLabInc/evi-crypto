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
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace evi {
namespace detail {

// NOLINTBEGIN(readability-identifier-naming)
struct ConstantPreset {
    virtual u64 getPrimeQ() const = 0;
    virtual u64 getPrimeP() const = 0;
    virtual u64 getPsiQ() const = 0;
    virtual u64 getPsiP() const = 0;
    virtual u64 getTwoPrimeQ() const = 0;
    virtual u64 getTwoPrimeP() const = 0;
    virtual u64 getHalfPrimeQ() const = 0;
    virtual u64 getHalfPrimeP() const = 0;
    virtual u64 getTwoTo64Q() const = 0;
    virtual u64 getTwoTo64P() const = 0;
    virtual u64 getTwoTo64ShoupQ() const = 0;
    virtual u64 getTwoTo64ShoupP() const = 0;

    virtual u64 getBarrRatioQ() const = 0;
    virtual u64 getBarrRatioP() const = 0;
    virtual u64 getPModQ() const = 0;
    virtual u64 getModDownProdInverseModEnd() const = 0;
    virtual u64 getInvDegreeQ() const = 0;
    virtual u64 getInvDegreeP() const = 0;
    virtual u64 getInvDegreeShoupQ() const = 0;
    virtual u64 getInvDegreeShoupP() const = 0;

    virtual u32 getHW() const = 0;
    virtual double getScaleFactor() const = 0;
    virtual double getDBScaleFactor() const {
        return getScaleFactor();
    }
    virtual double getQueryScaleFactor() const {
        return getScaleFactor();
    }

    virtual ParameterPreset getPreset() const = 0;

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
        return getPrimeQ();
    }
    virtual u64 getBackwardKeyP() const {
        return getPrimeP();
    }
    virtual ParameterPreset getBackwardKeyPreset() const {
        return getPreset();
    }
};

struct IPBase : ConstantPreset {
public:
    IPBase() = default;
    ~IPBase() = default;

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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

    static constexpr u64 PRIME_Q = 2251799813554177; // 51bit
    static constexpr u64 PSI_Q = 278055349447;

    static constexpr u64 PRIME_P = 36028797014376449; // 55bit
    static constexpr u64 PSI_P = 115736144453;

    static constexpr u64 TWO_PRIME_Q = PRIME_Q << 1;
    static constexpr u64 TWO_PRIME_P = PRIME_P << 1;
    static constexpr u64 HALF_PRIME_Q = PRIME_Q >> 1;
    static constexpr u64 HALF_PRIME_P = PRIME_P >> 1;
    static constexpr u64 TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
    static constexpr u64 TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
    static constexpr u64 TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
    static constexpr u64 TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
    static constexpr u64 BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
    static constexpr u64 BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
    static constexpr u64 PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
    static constexpr u64 INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
    static constexpr u64 INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

    static constexpr u32 HAMMING_WEIGHT = 2730;
    static constexpr double SCALE_FACTOR = 24.0;
    static constexpr ParameterPreset preset = ParameterPreset::IP0;
};

struct IP1Base : ConstantPreset {
public:
    IP1Base() = default;
    ~IP1Base() = default;

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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
        return IPBase::PRIME_Q;
    }
    u64 getBackwardKeyP() const override {
        return IPBase::PRIME_P;
    }
    ParameterPreset getBackwardKeyPreset() const override {
        return ParameterPreset::IP0;
    }

    static constexpr u64 PRIME_Q = 17179754497;
    static constexpr u64 PSI_Q = 0;

    static constexpr u64 PRIME_P = 17179672577;
    static constexpr u64 PSI_P = 0;

    static constexpr u64 PRIME_R = 274877562881;
    static constexpr u64 PSI_R = 0;

    static constexpr u64 TWO_PRIME_Q = PRIME_Q << 1;
    static constexpr u64 TWO_PRIME_P = PRIME_P << 1;
    static constexpr u64 HALF_PRIME_Q = PRIME_Q >> 1;
    static constexpr u64 HALF_PRIME_P = PRIME_P >> 1;
    static constexpr u64 TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
    static constexpr u64 TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
    static constexpr u64 TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
    static constexpr u64 TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
    static constexpr u64 BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
    static constexpr u64 BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
    static constexpr u64 PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
    static constexpr u64 INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
    static constexpr u64 INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

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

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }
    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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

    // 32-bit NTT primes: p = 1 (mod 8192), fits u32
    static constexpr u64 PRIME_Q = 4294828033; // 32 bits
    static constexpr u64 PSI_Q = 567303915;

    static constexpr u64 PRIME_P = 4294729729; // 32 bits
    static constexpr u64 PSI_P = 228263120;

    static constexpr u64 TWO_PRIME_Q = PRIME_Q << 1;
    static constexpr u64 TWO_PRIME_P = PRIME_P << 1;
    static constexpr u64 HALF_PRIME_Q = PRIME_Q >> 1;
    static constexpr u64 HALF_PRIME_P = PRIME_P >> 1;
    static constexpr u64 TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
    static constexpr u64 TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
    static constexpr u64 TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
    static constexpr u64 TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
    static constexpr u64 BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
    static constexpr u64 BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
    static constexpr u64 PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
    static constexpr u64 INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
    static constexpr u64 INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

    static constexpr u32 HAMMING_WEIGHT = 2730;

    // AM-GM optimal for 32-bit primes
    // Total = log2(Q*P) - log2(3) = 62.415
    // Post-rescale: total - log2(P) = 30.415
    static constexpr double SCALE_FACTOR = 30.4149907195753;
    static constexpr double DB_SCALE_FACTOR = 50.0610951224477;
    static constexpr double QUERY_SCALE_FACTOR = 12.353815795306446;

    static constexpr ParameterPreset preset = ParameterPreset::IP2;
};

struct IP3Base : ConstantPreset {
public:
    IP3Base() = default;
    ~IP3Base() = default;

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }
    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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

    // IP3 NTT primes (Q,P = 30-bit; R = 46-bit):
    // p = 1 (mod 8192), Q/P close to 2^30 for max precision while still fitting u32.
    // Like IP2, IP3 MMS has no base conversion — backward keys stay in IP3 primes.
    // R 46-bit (vs Q,P 30-bit, vs IP2 R=42-bit): R is keyswitch-only (transient
    // buffer, no permanent storage), so a wider R adds noise budget for the
    // transpose / shared-A flow without affecting CtMatrix Q/P u32 storage.
    // logQPR = 30+30+46 = 106, matching IP2 (security ~2^130.2).
    static constexpr u64 PRIME_Q = 1073692673ULL; // 30 bits
    static constexpr u64 PSI_Q = 0;               // populated by NTT precompute pass

    static constexpr u64 PRIME_P = 1073668097ULL; // 30 bits
    static constexpr u64 PSI_P = 0;

    static constexpr u64 PRIME_R = 70368743669761ULL; // 46 bits (k=8589934530, p=k*8192+1)
    static constexpr u64 PSI_R = 0;

    static constexpr u64 TWO_PRIME_Q = PRIME_Q << 1;
    static constexpr u64 TWO_PRIME_P = PRIME_P << 1;
    static constexpr u64 HALF_PRIME_Q = PRIME_Q >> 1;
    static constexpr u64 HALF_PRIME_P = PRIME_P >> 1;
    static constexpr u64 TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
    static constexpr u64 TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
    static constexpr u64 TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
    static constexpr u64 TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
    static constexpr u64 BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
    static constexpr u64 BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
    static constexpr u64 PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
    static constexpr u64 INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
    static constexpr u64 INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

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

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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

    static constexpr u64 PRIME_Q = 288230376135196673;
    static constexpr u64 PRIME_P = 2251799810670593;
    static constexpr u64 PSI_Q = 60193018759093;
    static constexpr u64 PSI_P = 254746317487;

    static constexpr u64 TWO_PRIME_Q = PRIME_Q << 1;
    static constexpr u64 TWO_PRIME_P = PRIME_P << 1;
    static constexpr u64 HALF_PRIME_Q = PRIME_Q >> 1;
    static constexpr u64 HALF_PRIME_P = PRIME_P >> 1;
    static constexpr u64 TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
    static constexpr u64 TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
    static constexpr u64 TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
    static constexpr u64 TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
    static constexpr u64 BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
    static constexpr u64 BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
    static constexpr u64 PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
    static constexpr u64 MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
    static constexpr u64 INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
    static constexpr u64 INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
    static constexpr u64 INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

    static constexpr u32 HAMMING_WEIGHT = 2730;
    static constexpr double SCALE_FACTOR = 25.0;
    static constexpr ParameterPreset preset = ParameterPreset::QF0;
};

struct RuntimeParam : ConstantPreset {
public:
    RuntimeParam(u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p, double scale_factor, u32 hw) {
        PRIME_Q = prime_q;
        PRIME_P = prime_p;
        PSI_Q = psi_q;
        PSI_P = psi_p;

        TWO_PRIME_Q = PRIME_Q << 1;
        TWO_PRIME_P = PRIME_P << 1;
        HALF_PRIME_Q = PRIME_Q >> 1;
        HALF_PRIME_P = PRIME_P >> 1;
        TWO_TO_64_Q = powModSimple(2, 64, PRIME_Q);
        TWO_TO_64_P = powModSimple(2, 64, PRIME_P);
        TWO_TO_64_SHOUP_Q = divide128By64Lo(TWO_TO_64_Q, 0, PRIME_Q);
        TWO_TO_64_SHOUP_P = divide128By64Lo(TWO_TO_64_P, 0, PRIME_P);
        BARRETT_RATIO_FOR_U64_Q = divide128By64Lo(1, 0, PRIME_Q);
        BARRETT_RATIO_FOR_U64_P = divide128By64Lo(1, 0, PRIME_P);
        PMOD_Q = reduceBarrett(PRIME_Q, BARRETT_RATIO_FOR_U64_Q, PRIME_P);
        MOD_DOWN_PROD_INVERSE_MOD_END = powModSimple(PRIME_P, PRIME_Q - 2, PRIME_Q);
        INV_DEGREE_Q = powModSimple(DEGREE, PRIME_Q - 2, PRIME_Q);
        INV_DEGREE_P = powModSimple(DEGREE, PRIME_P - 2, PRIME_P);
        INV_DEGREE_SHOUP_Q = divide128By64Lo(INV_DEGREE_Q, 0, PRIME_Q);
        INV_DEGREE_SHOUP_P = divide128By64Lo(INV_DEGREE_P, 0, PRIME_P);

        SCALE_FACTOR = scale_factor;
        HAMMING_WEIGHT = hw;
        preset = ParameterPreset::RUNTIME;
    }
    ~RuntimeParam() = default;

    u64 getPrimeQ() const override {
        return PRIME_Q;
    }
    u64 getPrimeP() const override {
        return PRIME_P;
    }
    u64 getPsiQ() const override {
        return PSI_Q;
    }
    u64 getPsiP() const override {
        return PSI_P;
    }

    u64 getTwoPrimeQ() const override {
        return TWO_PRIME_Q;
    }
    u64 getTwoPrimeP() const override {
        return TWO_PRIME_P;
    }
    u64 getHalfPrimeQ() const override {
        return HALF_PRIME_Q;
    }
    u64 getHalfPrimeP() const override {
        return HALF_PRIME_P;
    }
    u64 getTwoTo64Q() const override {
        return TWO_TO_64_Q;
    }
    u64 getTwoTo64P() const override {
        return TWO_TO_64_P;
    }
    u64 getTwoTo64ShoupQ() const override {
        return TWO_TO_64_SHOUP_Q;
    }
    u64 getTwoTo64ShoupP() const override {
        return TWO_TO_64_SHOUP_P;
    }
    u64 getBarrRatioQ() const override {
        return BARRETT_RATIO_FOR_U64_Q;
    }
    u64 getBarrRatioP() const override {
        return BARRETT_RATIO_FOR_U64_P;
    }
    u64 getPModQ() const override {
        return PMOD_Q;
    }
    u64 getModDownProdInverseModEnd() const override {
        return MOD_DOWN_PROD_INVERSE_MOD_END;
    }
    u64 getInvDegreeQ() const override {
        return INV_DEGREE_Q;
    }
    u64 getInvDegreeP() const override {
        return INV_DEGREE_P;
    }
    u64 getInvDegreeShoupQ() const override {
        return INV_DEGREE_SHOUP_Q;
    }
    u64 getInvDegreeShoupP() const override {
        return INV_DEGREE_SHOUP_P;
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
    u64 PRIME_Q;
    u64 PRIME_P;
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
    ParameterPreset preset;
};
// NOLINTEND(readability-identifier-naming)

using Parameter = std::shared_ptr<evi::detail::ConstantPreset>;

Parameter setPreset(evi::ParameterPreset name);
Parameter setPreset(evi::ParameterPreset name, u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p, double scale_factor,
                    u32 hw);
} // namespace detail
} // namespace evi
