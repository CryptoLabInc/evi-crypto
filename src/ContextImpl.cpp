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

#include "EVI/impl/ContextImpl.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/Basic.cuh"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Parameter.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace evi {
namespace detail {
ContextImpl::ContextImpl(const evi::ParameterPreset preset, const evi::DeviceType device_type, const u64 rank,
                         const evi::EvalMode eval_mode, std::optional<const int> device_id)
    : param_(setPreset(preset)), dtype_(device_type), mode_(eval_mode), ntt_q_{DEGREE, param_->getPrimeQ()},
      ntt_q_rank_{DEGREE, param_->getPrimeQ(), DEGREE / rank}, ntt_p_{DEGREE, param_->getPrimeP()},
      ntt_p_rank_{DEGREE, param_->getPrimeP(), DEGREE / rank} {
    switch (eval_mode) {
    case evi::EvalMode::RMP:
        show_rank_ = rank;
        rank_ = getInnerRank(rank);
        num_input_cipher_ = (show_rank_ + rank_ - 1) / rank_;
        break;
    case evi::EvalMode::RMS:
        show_rank_ = rank;
        rank_ = getInnerRank(rank);
        num_input_cipher_ = (show_rank_ + rank_ - 1) / rank_;
        break;
    case evi::EvalMode::MS:
        rank_ = rank;
        show_rank_ = 0;
        break;
    case EvalMode::FLAT:
        rank_ = rank;
        show_rank_ = rank;
        break;
    case EvalMode::MM:
        show_rank_ = rank;
        rank_ = rank;
        // impl ciphertext size
        num_input_cipher_ = rank;
        break;
    default:
        throw evi::NotSupportedError("Not supported eval mode!");
    }

    pad_rank_ = isPowerOfTwo(rank_) ? rank_ : nextPowerOfTwo(rank_);
    log_pad_rank_ = (u64)log2(pad_rank_);
    items_per_ctxt_ = DEGREE / pad_rank_;
    precomputeShiftNTT();

    if (device_type == DeviceType::GPU) {
#ifdef BUILD_WITH_CUDA
        device_id_ = device_id.value_or(0);
        initGPU();
#else
        throw evi::NotSupportedError("DeviceType::GPU is not supported in this build");
#endif
    }
}

ContextImpl::ContextImpl(evi::ParameterPreset preset, const u64 rank, u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p,
                         double scale_factor, u32 hamming_weight)
    : param_(setPreset(preset, prime_q, prime_p, psi_q, psi_p, scale_factor, hamming_weight)), dtype_(DeviceType::CPU),
      mode_(EvalMode::FLAT), ntt_q_{DEGREE, param_->getPrimeQ()}, ntt_p_{DEGREE, param_->getPrimeP()}, rank_(rank) {

    show_rank_ = 0;
    pad_rank_ = isPowerOfTwo(rank_) ? rank_ : nextPowerOfTwo(rank_);
    log_pad_rank_ = (u64)log2(pad_rank_);
    items_per_ctxt_ = DEGREE / pad_rank_;
    precomputeShiftNTT();
}

ContextImpl::~ContextImpl() {
    if (dtype_ == DeviceType::GPU) {
#ifdef BUILD_WITH_CUDA
        releaseGPU();
#endif
    }
}

void ContextImpl::negateModQ(span<u64> poly) {
    for (u64 i = 0; i < DEGREE; i++) {
        poly[i] = param_->getPrimeQ() - poly[i];
    }
}

void ContextImpl::negateModP(span<u64> poly) {
    for (int i = 0; i < DEGREE; i++) {
        poly[i] = param_->getPrimeP() - poly[i];
    }
}

void ContextImpl::addModQ(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] = op1[i] + op2[i];
        res[i] = subIfGEModI64(res[i], param_->getPrimeQ());
    }
}

void ContextImpl::addModP(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] = op1[i] + op2[i];
        res[i] = subIfGEModI64(res[i], param_->getPrimeP());
    }
}

void ContextImpl::multModQ(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] = mulMod(param_->getPrimeQ(), param_->getTwoPrimeQ(), param_->getTwoTo64Q(), param_->getTwoTo64ShoupQ(),
                        param_->getBarrRatioQ(), op1[i], op2[i]);
    }
}

void ContextImpl::multModP(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] = mulMod(param_->getPrimeP(), param_->getTwoPrimeP(), param_->getTwoTo64P(), param_->getTwoTo64ShoupP(),
                        param_->getBarrRatioP(), op1[i], op2[i]);
    }
}

void ContextImpl::madModQ(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] += mulMod(param_->getPrimeQ(), param_->getTwoPrimeQ(), param_->getTwoTo64Q(), param_->getTwoTo64ShoupQ(),
                         param_->getBarrRatioQ(), op1[i], op2[i]);
        res[i] = subIfGEModI64(res[i], param_->getPrimeQ());
    }
}

void ContextImpl::madModQ(const span<u64> op1, const u64 op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] += mulMod(param_->getPrimeQ(), param_->getTwoPrimeQ(), param_->getTwoTo64Q(), param_->getTwoTo64ShoupQ(),
                         param_->getBarrRatioQ(), op1[i], op2);
        res[i] = subIfGEModI64(res[i], param_->getPrimeQ());
    }
}

void ContextImpl::madModP(const span<u64> op1, const span<u64> op2, span<u64> res) {
    for (u64 i = 0; i < DEGREE; ++i) {
        res[i] += mulMod(param_->getPrimeP(), param_->getTwoPrimeP(), param_->getTwoTo64P(), param_->getTwoTo64ShoupP(),
                         param_->getBarrRatioP(), op1[i], op2[i]);
        res[i] = subIfGEModI64(res[i], param_->getPrimeP());
    }
}

void ContextImpl::precomputeShiftNTT() {
    for (int i = 0; i < items_per_ctxt_; i++) {
        // TODO: remove inplace operation in NTT
        poly q{}, p{};
        q[i * pad_rank_] = 1;
        p[i * pad_rank_] = 1;

        nttModQ(q);
        nttModP(p);

        shift_ctxt_q_.emplace_back(q);
        shift_ctxt_p_.emplace_back(p);
    }
}

void ContextImpl::shiftIndexQ(const u64 index, const span<u64> ptxt_q, span<u64> out_q) {
    u64 idx = index % items_per_ctxt_;
    multModQ(ptxt_q, shift_ctxt_q_[idx], out_q);
}

void ContextImpl::shiftIndexP(const u64 index, const span<u64> ptxt_p, span<u64> out_p) {
    u64 idx = index % items_per_ctxt_;
    multModP(ptxt_p, shift_ctxt_p_[idx], out_p);
}

void ContextImpl::shiftIndexQ(const u64 index, const span<u64> ctxt_input_a, const span<u64> ctxt_input_b,
                              span<u64> out_a, span<u64> out_b) {
    u64 idx = index % items_per_ctxt_;
    multModQ(ctxt_input_a, shift_ctxt_q_[idx], out_a);
    multModQ(ctxt_input_b, shift_ctxt_q_[idx], out_b);
}

void ContextImpl::shiftIndexP(const u64 index, const span<u64> ctxt_input_a, const span<u64> ctxt_input_b,
                              span<u64> out_a, span<u64> out_b) {
    u64 idx = index % items_per_ctxt_;
    multModP(ctxt_input_a, shift_ctxt_p_[idx], out_a);
    multModP(ctxt_input_b, shift_ctxt_p_[idx], out_b);
}

void ContextImpl::nttModQ(span<u64> poly) {
    ntt_q_.computeForward(poly.data());
}

void ContextImpl::nttModQMini(span<u64> poly, const u64 pad_rank) {
    if (pad_rank == 0) {
        ntt_q_rank_.computeForward(poly.data());
        return;
    }
    ntt_q_.computeForward(poly.data(), pad_rank);
}

void ContextImpl::nttModP(span<u64> poly) {
    ntt_p_.computeForward(poly.data());
}

void ContextImpl::nttModPMini(span<u64> poly, const u64 pad_rank) {
    if (pad_rank == 0) {
        ntt_p_rank_.computeForward(poly.data());
        return;
    }
    ntt_p_.computeForward(poly.data(), pad_rank);
}

void ContextImpl::inttModQ(span<u64> poly) {
    ntt_q_.computeBackward(poly.data());
}
void ContextImpl::inttModP(span<u64> poly) {

    ntt_p_.computeBackward(poly.data());
}

void ContextImpl::inttModQ(span<u64> poly, u64 fullmod) {
    ntt_q_.computeBackward(poly.data(), fullmod);
}

void ContextImpl::modDown(span<u64> poly_q, span<u64> poly_p) {
    inttModP(poly_p);
    normalizeMod(poly_p, poly_p, param_->getPrimeP(), param_->getPrimeQ(), param_->getBarrRatioQ());
    nttModQ(poly_p);
    u64 approx_quotient = divide128By64Lo(param_->getModDownProdInverseModEnd(), 0, param_->getPrimeQ());
    for (u64 i = 0; i < DEGREE; i++) {
        u64 tmp = param_->getPrimeQ() - poly_p[i] + poly_q[i];
        poly_q[i] = mulModLazy(tmp, param_->getModDownProdInverseModEnd(), approx_quotient, param_->getPrimeQ());
        if (poly_q[i] >= param_->getPrimeQ()) {
            poly_q[i] -= param_->getPrimeQ();
        }
    }
}

void ContextImpl::modUp(const span<u64> poly_q, span<u64> poly_p) {
    std::memcpy(poly_p.data(), poly_q.data(), U64_DEGREE);
    inttModQ(poly_p);
    normalizeMod(poly_p, poly_p, param_->getPrimeQ(), param_->getPrimeP(), param_->getBarrRatioP());
    nttModP(poly_p);
}

void ContextImpl::normalizeMod(const span<u64> in, span<u64> out, u64 mod_in, u64 mod_out, u64 barr_out) {
    const u64 half_mod = mod_in >> 1;
    bool is_small_prime = half_mod <= mod_out;
    u64 diff = mod_out - (is_small_prime ? mod_in : reduceBarrett(mod_out, barr_out, mod_in));
    for (u64 i = 0; i < DEGREE; ++i) {
        u64 temp = in[i];
        if (temp > half_mod) {
            temp += diff;
        }
        if (!is_small_prime) {
            temp = reduceBarrett(mod_out, barr_out, temp);
        }
        out[i] = temp;
    }
}

#ifndef BUILD_WITH_CUDA
namespace {
[[noreturn]] void throwGpuUnsupported() {
    throw evi::NotSupportedError("GPU backend is not available in this build");
}
} // namespace

void ContextImpl::addModQGpu(u64 *, const u64 *, const u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttModQ(const u64 *, u64 *, const u32, bool) {
    throwGpuUnsupported();
}
void ContextImpl::nttModP(const u64 *, u64 *, const u32, bool) {
    throwGpuUnsupported();
}
void ContextImpl::inttModQ(const u64 *, u64 *, const u32, bool) {
    throwGpuUnsupported();
}
void ContextImpl::inttModP(const u64 *, u64 *, const u32, bool) {
    throwGpuUnsupported();
}
void ContextImpl::inttP2ModP(const u64 *, u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::inttP2ModQ(const u64 *, u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::inttP1ModP(u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::inttP1ModQ(u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttP1ModP(const u64 *, u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttP1ModQ(const u64 *, u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttP2ModP(u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttP2ModQ(u64 *, const u32) {
    throwGpuUnsupported();
}
void ContextImpl::nttP2ModDown(u64 *, u64 *, const u32) {
    throwGpuUnsupported();
}
#ifdef ENABLE_IVF
void ContextImpl::getShiftGPU() {
    throwGpuUnsupported();
}
void ContextImpl::shiftAddTensor(const u64 *, const u64 *, u64 **, u64 **, u64 *, u64 *, u64 *, u64 *, const u64 *,
                                 const u32) {
    throwGpuUnsupported();
}
#endif

void ContextImpl::initGPU() {
    throwGpuUnsupported();
}

void ContextImpl::releaseGPU() {}
#endif

Parameter setPreset(evi::ParameterPreset name) {
    if (name == evi::ParameterPreset::QF0) {
        return std::make_shared<QFBase>();
    } else if (name == evi::ParameterPreset::QF1) {
        return std::make_shared<QFBase>();
    } else if (name == evi::ParameterPreset::IP0) {
        return std::make_shared<IPBase>();
    } else if (name == evi::ParameterPreset::IP1) {
        return std::make_shared<IP1Base>();
    } else {
        throw evi::NotSupportedError("Not supported preset type!");
        return nullptr;
    }
};

Parameter setPreset(evi::ParameterPreset name, u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p, double sf, u32 hw) {
    if (name != evi::ParameterPreset::RUNTIME) {
        return nullptr;
    } else {
        return std::make_shared<RuntimeParam>(prime_q, prime_p, psi_q, psi_p, sf, hw);
    }
}

Context makeContext(evi::ParameterPreset preset, const evi::DeviceType device_type, const u64 rank,
                    const evi::EvalMode eval_mode, std::optional<const int> device_id) {
#ifdef ENABLE_EVI_LICENSE
    const char *env_token = std::getenv("ES2_LICENSE_TOKEN");
    std::string token = env_token ? env_token : "";
    detail::utils::verifyToken(token);
#endif
#ifndef BUILD_WITH_CUDA
    if (device_type == DeviceType::GPU) {
        throw NotSupportedError("Unable to set device type to GPU with current build configuration");
    }
#endif
    return std::make_shared<ContextImpl>(preset, device_type, rank, eval_mode, device_id);
}
} // namespace detail
} // namespace evi
