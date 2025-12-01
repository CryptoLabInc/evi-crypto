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

#include "EVI/Decryptor.hpp"
#include "EVI/impl/DecryptorImpl.hpp"

namespace evi {

Decryptor::Decryptor(std::shared_ptr<detail::Decryptor> impl) noexcept : impl_(std::move(impl)) {}

Message Decryptor::decrypt(const SearchResult &item, const SecretKey &key) {
    return decrypt(item, key, true);
}

Message Decryptor::decrypt(const SearchResult &item, const SecretKey &key, bool is_score, std::optional<double> scale) {
    return Message(
        std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(item), *getImpl(key), is_score, scale)));
}

Message Decryptor::decrypt(const SearchResult &item, const std::string &key_path, bool is_score,
                           std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(item), key_path, is_score, scale)));
}

Message Decryptor::decrypt(const SearchResult &item, std::istream &key_stream, bool is_score,
                           std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(item), key_stream, is_score, scale)));
}

Message Decryptor::decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(ctxt), *getImpl(key), scale)));
}

Message Decryptor::decrypt(const Query &ctxt, const std::string &key_path, std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(ctxt), key_path, scale)));
}

Message Decryptor::decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(*getImpl(ctxt), key_stream, scale)));
}

Message Decryptor::decrypt(int idx, const Query &ctxt, const SecretKey &key, std::optional<double> scale) {
    return Message(std::make_shared<detail::Message>((*impl_)->decrypt(idx, *getImpl(ctxt), *getImpl(key), scale)));
}

Decryptor makeDecryptor(const Context &context) {
    return Decryptor(std::make_shared<detail::Decryptor>(detail::makeDecryptor(*getImpl(context))));
}

} // namespace evi
