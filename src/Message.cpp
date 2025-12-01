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

#include "EVI/Message.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include <vector>
namespace evi {

Message::Message() : impl_(std::make_shared<detail::Message>()) {}
Message::Message(std::shared_ptr<detail::Message> impl) : impl_(std::move(impl)) {}

void Message::resize(size_t n) {
    impl_->resize(n);
}
void Message::push_back(float value) {
    impl_->push_back(value);
}
void Message::clear() {
    impl_->clear();
}
void Message::reserve(size_t n) {
    impl_->reserve(n);
}
void Message::emplace_back(float value) {
    impl_->emplace_back(value);
}
float *Message::data() {
    return impl_ ? impl_->data() : nullptr;
}
const float *Message::data() const {
    return impl_ ? impl_->data() : nullptr;
}
size_t Message::size() const {
    return impl_ ? impl_->size() : 0;
}
float &Message::operator[](size_t index) {
    return (*impl_)[index];
}

} // namespace evi
