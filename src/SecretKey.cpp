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

#include "EVI/SecretKey.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"

namespace evi {

SecretKey makeSecKey(const evi::Context &context) {
    return SecretKey(std::make_shared<detail::SecretKey>(detail::makeSecKey(*getImpl(context))));
}

SecretKey makeSecKey(const std::string &path, const std::optional<SealInfo> &s_info) {
    std::optional<detail::SealInfo> inner;
    if (s_info.has_value()) {
        inner.emplace(*getImpl(s_info.value()));
    }
    return SecretKey(std::make_shared<detail::SecretKey>(detail::makeSecKey(path, inner)));
}

SecretKey makeSecKey(std::istream &stream, std::optional<SealInfo> s_info) {
    std::optional<detail::SealInfo> inner;
    if (s_info.has_value()) {
        inner.emplace(*getImpl(s_info.value()));
    }
    return SecretKey(std::make_shared<detail::SecretKey>(detail::makeSecKey(stream, std::move(inner))));
}

std::shared_ptr<detail::SecretKey> &getImpl(SecretKey &sec) noexcept {
    return sec.impl_;
}

const std::shared_ptr<detail::SecretKey> &getImpl(const SecretKey &sec) noexcept {
    return sec.impl_;
}
} // namespace evi
