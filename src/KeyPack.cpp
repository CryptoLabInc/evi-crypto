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

#include "EVI/KeyPack.hpp"
#include "EVI/impl/KeyPackImpl.hpp"

namespace evi {
KeyPack makeKeyPack(const evi::Context &context) {
    // TODO : return heaan keypack
    return KeyPack(detail::makeKeyPack(*getImpl(context)));
}

KeyPack makeKeyPack(const evi::Context &context, const std::string &dir_path) {
    return KeyPack(detail::makeKeyPack(*getImpl(context), dir_path));
}

KeyPack makeKeyPack(const evi::Context &context, std::istream &in) {
    return KeyPack(detail::makeKeyPack(*getImpl(context), in));
}

KeyPack::KeyPack(std::shared_ptr<detail::IKeyPack> impl) noexcept : impl_(std::move(impl)) {}

std::shared_ptr<detail::IKeyPack> &getImpl(KeyPack &kp) noexcept {
    return kp.impl_;
}
const std::shared_ptr<detail::IKeyPack> &getImpl(const KeyPack &kp) noexcept {
    return kp.impl_;
}

void KeyPack::saveEncKey(const std::string &dir_path) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->saveEncKeyFile(dir_path);
}

void KeyPack::saveEncKey(std::ostream &os) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->getEncKeyBuffer(os);
}

void KeyPack::loadEncKey(const std::string &file_path) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->loadEncKeyFile(file_path);
}

void KeyPack::loadEncKey(std::istream &stream) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->loadEncKeyBuffer(stream);
}

void KeyPack::saveEvalKey(const std::string &dir_path) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->saveEvalKeyFile(dir_path);
}

void KeyPack::saveEvalKey(std::ostream &os) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->getEvalKeyBuffer(os);
}

void KeyPack::loadEvalKey(const std::string &file_path) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->loadEvalKeyFile(file_path);
}

void KeyPack::loadEvalKey(std::istream &stream) {
    if (!impl_) {
        throw std::logic_error("KeyPack impl is null");
    }
    getImpl(*this)->loadEvalKeyBuffer(stream);
}

} // namespace evi
