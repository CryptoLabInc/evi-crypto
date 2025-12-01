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

#include "evi_c/context.h"
#include "evi_c/internal/common_internal.hpp"

#include <cmath>

using namespace evi::c_api::detail;

extern "C" {

evi_status_t evi_context_create(evi_parameter_preset_t preset, evi_device_type_t device, uint64_t dim,
                                evi_eval_mode_t eval_mode, const int32_t *device_id, evi_context_t **out_context) {
    if (!out_context) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "out_context is null");
    }

    return invoke_and_catch([&]() {
        std::optional<int> dev_id = std::nullopt;
        if (device_id) {
            dev_id = *device_id;
        }
        evi::Context ctx =
            evi::makeContext(static_cast<evi::ParameterPreset>(preset), static_cast<evi::DeviceType>(device), dim,
                             static_cast<evi::EvalMode>(eval_mode), dev_id);
        *out_context = new evi_context(std::move(ctx));
    });
}

void evi_context_destroy(evi_context_t *context) {
    delete context;
}

// getters
evi_device_type_t evi_context_get_device_type(const evi_context_t *context) {
    if (!context)
        return EVI_DEVICE_TYPE_INVALID;
    auto ctx = context->impl;
    return static_cast<evi_device_type_t>(ctx.getDeviceType());
}

evi_eval_mode_t evi_context_get_eval_mode(const evi_context_t *context) {
    if (!context)
        return EVI_EVAL_MODE_INVALID;
    return static_cast<evi_eval_mode_t>(context->impl.getEvalMode());
}

uint32_t evi_context_get_pad_rank(const evi_context_t *context) {
    if (!context)
        return 0;
    return static_cast<uint32_t>(std::lround(context->impl.getPadRank()));
}

uint32_t evi_context_get_show_dim(const evi_context_t *context) {
    if (!context)
        return -1;
    return context->impl.getShowDim();
}

double evi_context_get_scale_factor(const evi_context_t *context) {
    if (!context)
        return -1;
    return context->impl.getScaleFactor();
}

} // extern "C"
