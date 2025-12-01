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

#include "EVI/KeyGenerator.hpp"
#include "EVI/SecretKey.hpp"
#include "EVI/impl/KeyGeneratorImpl.hpp"

namespace evi {

KeyGenerator makeKeyGenerator(const Context &context, const std::optional<std::vector<uint8_t>> &seed) {
    return KeyGenerator(std::make_shared<detail::KeyGenerator>(detail::makeKeyGenerator(*getImpl(context), seed)));
}

KeyGenerator makeKeyGenerator(const Context &context, KeyPack &pack, const std::optional<std::vector<uint8_t>> &seed) {
    return KeyGenerator(
        std::make_shared<detail::KeyGenerator>(detail::makeKeyGenerator(*getImpl(context), getImpl(pack), seed)));
}

KeyGenerator::KeyGenerator(std::shared_ptr<detail::KeyGenerator> impl) noexcept : impl_(std::move(impl)) {}

SecretKey KeyGenerator::genSecKey() {
    std::shared_ptr<detail::SecretKey> sk_ptr = std::make_shared<detail::SecretKey>();
    *sk_ptr = (*impl_)->genSecKey();
    return sk_ptr;
}

void KeyGenerator::genPubKeys(SecretKey &sec_key) {
    (*impl_)->genPubKeys(*getImpl(sec_key));
}

MultiKeyGenerator::MultiKeyGenerator(const std::vector<Context> &contexts, const std::string &store_path,
                                     SealInfo &s_info, const std::optional<std::vector<uint8_t>> &seed) {
    std::vector<detail::Context> ctxs;
    ctxs.reserve(contexts.size());
    for (const auto &context : contexts) {
        ctxs.emplace_back(*getImpl(context));
    }
    auto seal_impl = getImpl(s_info);
    impl_ = std::make_shared<detail::MultiKeyGenerator>(ctxs, store_path, *seal_impl, seed);
}

SecretKey MultiKeyGenerator::generateKeys() {
    std::shared_ptr<detail::SecretKey> sk_ptr = std::make_shared<detail::SecretKey>();
    *sk_ptr = impl_->generateKeys();
    return sk_ptr;
}

SecretKey MultiKeyGenerator::generateKeys(std::ostream &os) {
    std::shared_ptr<detail::SecretKey> sk_ptr = std::make_shared<detail::SecretKey>();
    *sk_ptr = impl_->generateKeys(os);
    return sk_ptr;
}

bool MultiKeyGenerator::checkFileExist() const {
    return impl_->checkFileExist();
}
} // namespace evi
