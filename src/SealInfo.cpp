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

#include "EVI/SealInfo.hpp"
#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"

namespace evi {

SealInfo::SealInfo(SealMode m) : impl_(std::make_shared<detail::SealInfo>(m)) {}
SealInfo::SealInfo(SealMode m, std::vector<uint8_t> aes_key) {
    if (aes_key.size() != AES256_KEY_SIZE) {
        throw evi::InvalidInputError("aes key size must be 32 bytes");
    }
    impl_ = std::make_shared<detail::SealInfo>(m, std::move(aes_key));
}
SealInfo::SealInfo(SealMode m, int hsm_con_num, int auth_id, const std::string &auth_pw)
    : impl_(std::make_shared<detail::SealInfo>(m, hsm_con_num, auth_id, auth_pw)) {}

SealMode SealInfo::getSealMode() const {
    return impl_->s_mode;
}

std::shared_ptr<detail::SealInfo> &getImpl(SealInfo &seal) noexcept {
    return seal.impl_;
}

const std::shared_ptr<detail::SealInfo> &getImpl(const SealInfo &seal) noexcept {
    return seal.impl_;
}

} // namespace evi
