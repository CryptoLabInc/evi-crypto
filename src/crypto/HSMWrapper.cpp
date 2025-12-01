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

#ifdef BUILD_YUBIHSM
#include "utils/crypto/HSMWrapper.hpp"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

HSMWrapper::HSMWrapper(evi::detail::SealInfo &s_info) : s_info_(s_info) {
    string addr;
    if (s_info_.sMode == evi::SealMode::HSM_PORT) {
        addr = string(CONNECTOR_URL) + ":" + to_string(s_info.h_con_num);
    } else if (s_info_.sMode == evi::SealMode::HSM_SERIAL) {
        addr = string(USB_URL) + "=" + to_string(s_info.h_con_num);
    } else {
        std::cerr << "Invalid SealMode" << std::endl;
    }
    yh_rc rc = Initialize(s_info.h_auth_id, s_info.h_auth_pw.c_str(), addr.c_str());
    if (rc != YHR_SUCCESS) {
        Deinitialize();
        exit(1);
    }
}

// login, authkey_id (need to open session), password (password)
yh_rc HSMWrapper::Initialize(int authId, const char *authPw, const char *addr) {
    size_t pwLen = 0;
    yh_rc rc = YHR_GENERIC_ERROR;
    if (isInit_)
        return rc;

    rc = yh_init();
    if (rc != YHR_SUCCESS) {
        cerr << "Failed to initialize lib" << endl;
        return rc;
    }
    rc = yh_init_connector(addr, &connector_);
    if (rc != YHR_SUCCESS) {
        cerr << "Failed to initialize connector" << endl;
        return rc;
    }
    rc = yh_connect(connector_, 0);
    if (rc != YHR_SUCCESS) {
        cerr << "Failed to initialize :" << endl;
        return rc;
    }

    rc = yh_create_session_derived(connector_, authId, (const uint8_t *)authPw, sizeof(authPw), false, &session_);
    if (rc != YHR_SUCCESS) {
        yh_disconnect(connector_);
        connector_ = nullptr;
        yh_exit();
        cerr << "Failed to create session. Check your id and password" << endl;
        return rc;
    }
    isInit_ = true;
    return rc;
}

void HSMWrapper::Deinitialize() {
    if (isInit_) {
        yh_util_close_session(session_);
        yh_destroy_session(&session_);
        session_ = nullptr;
        yh_disconnect(connector_);
        connector_ = nullptr;
        yh_exit();
    }
}

yh_rc HSMWrapper::GetRandomNum(uint8_t *buffer, size_t size) {
    size_t result = size;
    yh_rc rc;
    if (!isInit_) {
        cerr << "Not initialized" << endl;
        return rc;
    }
    rc = yh_util_get_pseudo_random(session_, size, buffer, &result);
    if (rc != YHR_SUCCESS || result != size) {
        cerr << "Fail to get random number " << endl;
        return rc;
    }
    return rc;
}

// kek : K_ek
// wrapKek : E(K_ek, K_KMS)
yh_rc HSMWrapper::GetWrapKek(uint16_t *objId, uint8_t *kek, size_t kekLen, uint8_t *wrapKek, size_t *wrapKekLen) {
    yh_rc rc;
    uint16_t domain = 0;
    yh_capabilities capabilities = {{0}};
    yh_capabilities delegatedCapabilities = {{0}};

    GetRandomNum(kek, kekLen);
    rc = yh_string_to_capabilities("wrap-data:unwrap-data", &capabilities);
    rc = yh_string_to_domains("1", &domain);
    rc = yh_util_generate_wrap_key(session_, objId, LABEL, domain, &capabilities, YH_ALGO_AES256_CCM_WRAP,
                                   &delegatedCapabilities);
    if (rc != YHR_SUCCESS) {
        cerr << "Fail to generate wrap key\n";
        return rc;
    }

    yh_util_wrap_data(session_, *objId, kek, kekLen, wrapKek, wrapKekLen);
    if (rc != YHR_SUCCESS) {
        cerr << "Fail to wrap data\n";
        return rc;
    }
    return rc;
}

yh_rc HSMWrapper::GetUnwrapKek(uint16_t objId, uint8_t *wrapKek, size_t wrapKekLen, uint8_t *kek, size_t *kekLen) {
    yh_rc rc;
    rc = yh_util_unwrap_data(session_, objId, wrapKek, wrapKekLen, kek, kekLen);
    if (rc != YHR_SUCCESS) {
        cerr << "Fail to unwrap data\n";
        return rc;
    }
    Deinitialize();
    return rc;
}
#endif
