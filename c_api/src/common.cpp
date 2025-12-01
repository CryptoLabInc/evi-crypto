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

#include "evi_c/internal/common_internal.hpp"

#include <exception>

namespace evi::c_api::detail {

thread_local std::string g_last_error;

evi_status_t set_error(evi_status_t status, const char *message) {
    g_last_error = message ? message : "";
    return status;
}

evi_status_t translate_exception() {
    try {
        throw;
    } catch (const evi::InvalidInputError &ex) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, ex.what());
    } catch (const evi::FileNotFoundError &ex) {
        return set_error(EVI_STATUS_RUNTIME_ERROR, ex.what());
    } catch (const evi::NotSupportedError &ex) {
        return set_error(EVI_STATUS_NOT_IMPLEMENTED, ex.what());
    } catch (const std::out_of_range &ex) {
        return set_error(EVI_STATUS_OUT_OF_RANGE, ex.what());
    } catch (const std::exception &ex) {
        return set_error(EVI_STATUS_RUNTIME_ERROR, ex.what());
    } catch (...) {
        return set_error(EVI_STATUS_RUNTIME_ERROR, "unknown error");
    }
}

std::optional<float> to_optional(const float *value) {
    if (!value) {
        return std::nullopt;
    }
    return *value;
}

std::optional<double> to_optional(const double *value) {
    if (!value) {
        return std::nullopt;
    }
    return *value;
}

} // namespace evi::c_api::detail

extern "C" {

const char *evi_last_error_message(void) {
    return evi::c_api::detail::g_last_error.c_str();
}

} // extern "C"
