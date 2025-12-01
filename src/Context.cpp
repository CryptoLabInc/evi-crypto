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

#include "EVI/Context.hpp"
#include "EVI/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"

namespace evi {

Context::Context(std::shared_ptr<detail::Context> impl) noexcept : impl_(std::move(impl)) {}

Context makeContext(evi::ParameterPreset preset, const evi::DeviceType device_type, const uint64_t dim,
                    const evi::EvalMode eval_mode, std::optional<const int> device_id) {
    auto impl = std::make_shared<detail::Context>(detail::makeContext(preset, device_type, dim, eval_mode, device_id));
    return Context(std::move(impl));
}

DeviceType Context::getDeviceType() {
    return impl_->getDeviceType();
}

double Context::getScaleFactor() const {
    return impl_->getScaleFactor();
}

double Context::getPadRank() const {
    return impl_->getPadRank();
}

uint32_t Context::getShowDim() const {
    return impl_->getShowRank();
}

EvalMode Context::getEvalMode() const {
    return impl_->getEvalMode();
}

std::vector<Context> makeMultiContext(ParameterPreset preset, DeviceType type, EvalMode mode,
                                      std::optional<const int> device_id) {
    std::vector<Context> contexts;

    for (int i = evi::MIN_CONTEXT_SIZE; i <= evi::MAX_CONTEXT_SIZE; i *= 2) {
        contexts.emplace_back(makeContext(preset, type, i, mode, device_id));
    }
    return std::move(contexts);
}

std::shared_ptr<detail::Context> &getImpl(Context &sec) noexcept {
    return sec.impl_;
}

const std::shared_ptr<detail::Context> &getImpl(const Context &sec) noexcept {
    return sec.impl_;
}

std::uint32_t getRank(const evi::Context &ctx) noexcept {
    auto &nc = const_cast<evi::Context &>(ctx);
    return (*getImpl(nc))->getRank();
}

} // namespace evi
