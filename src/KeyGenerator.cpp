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

#include <stdexcept>

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

KeyPack KeyGenerator::genPubKeys(SecretKey &sec_key) {
    (*impl_)->genPubKeys(*getImpl(sec_key));
    return KeyPack((*impl_)->getKeyPack());
}

void KeyGenerator::genSharedAKeys(SecretKey &sec_from, const std::vector<SecretKey> &sec_to) {
    std::vector<detail::SecretKey> detail_sec_to;
    detail_sec_to.reserve(sec_to.size());
    for (const auto &sk : sec_to) {
        detail_sec_to.push_back(*getImpl(sk));
    }
    (*impl_)->genSharedASwitchKey(*getImpl(sec_from), detail_sec_to);
    (*impl_)->genAdditiveSharedASwitchKey(*getImpl(sec_from), detail_sec_to);
    (*impl_)->genSharedAModPackKey(*getImpl(sec_from), detail_sec_to);
    (*impl_)->genCCSharedAModPackKey(*getImpl(sec_from), detail_sec_to);
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

SecretKey MultiKeyGenerator::generateKeys(std::ostream &seckey, std::ostream &enckey, std::ostream &evalkey) {
    std::shared_ptr<detail::SecretKey> sk_ptr = std::make_shared<detail::SecretKey>();
    *sk_ptr = impl_->generateKeys(seckey, enckey, evalkey);
    return sk_ptr;
}

SecretKey MultiKeyGenerator::generateKeys(SecretKey &seckey, std::ostream &enckey, std::ostream &evalkey) {
    if (!getImpl(seckey) || !(*getImpl(seckey))) {
        throw std::logic_error("SecretKey impl is null");
    }
    impl_->generateKeys(*getImpl(seckey), enckey, evalkey);
    return seckey;
}

bool MultiKeyGenerator::checkFileExist() const {
    return impl_->checkFileExist();
}
} // namespace evi
