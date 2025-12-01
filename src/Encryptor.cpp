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

#include "EVI/Encryptor.hpp"
#include "EVI/impl/EncryptorImpl.hpp"
#include "utils/Exceptions.hpp"
namespace evi {

Encryptor::Encryptor(std::shared_ptr<detail::Encryptor> impl) noexcept : impl_(std::move(impl)) {}

Encryptor makeEncryptor(const Context &context, const std::optional<std::vector<uint8_t>> &seed) {
    return Encryptor(std::make_shared<detail::Encryptor>(detail::makeEncryptor(*getImpl(context), seed)));
}

Encryptor makeEncryptor(const Context &context, const KeyPack &key_pack) {
    return Encryptor(std::make_shared<detail::Encryptor>(detail::makeEncryptor(*getImpl(context), getImpl(key_pack))));
}

Encryptor makeEncryptor(const Context &context, const std::string &key_path) {
    return Encryptor(std::make_shared<detail::Encryptor>(detail::makeEncryptor(*getImpl(context), key_path)));
}

[[deprecated("encryptBulk will be removed soon; migrate to encrypt(data, keypack, type, level, scale)")]]
std::vector<Query> Encryptor::encryptBulk(const std::vector<std::vector<float>> &data, evi::EncodeType type,
                                          int level) {
    std::vector<detail::Query> queries = (*impl_)->encrypt(data, type, level);
    std::vector<Query> res;
    res.reserve(queries.size());
    for (auto &item : queries) {
        res.emplace_back(std::make_shared<detail::Query>(std::move(item)));
    }
    return res;
}

[[deprecated("encrypt(data, type, level) will be removed soon; migrate to encrypt(data, keypack, type, level, scale)")]]
Query Encryptor::encrypt(const std::vector<float> &data, evi::EncodeType type, int level) const {
    return Query(std::make_shared<detail::Query>((*impl_)->encrypt(data, type, level)));
}

Query Encryptor::encrypt(const std::vector<float> &data, std::istream &enckey_stream, evi::EncodeType type, int level,
                         std::optional<float> scale) const {
    return Query(std::make_shared<detail::Query>((*impl_)->encrypt(data, enckey_stream, type, level, scale)));
}

Query Encryptor::encrypt(const std::vector<float> &data, const std::string &enckey_path, evi::EncodeType type,
                         int level, std::optional<float> scale) const {
    return Query(std::make_shared<detail::Query>((*impl_)->encrypt(data, enckey_path, type, level, scale)));
}

Query Encryptor::encrypt(const std::vector<float> &data, const KeyPack &keypack, evi::EncodeType type, int level,
                         std::optional<float> scale) const {
    return Query(std::make_shared<detail::Query>((*impl_)->encrypt(data, getImpl(keypack), type, level, scale)));
}

[[deprecated("encrypt(data, type, level) will be removed soon; migrate to encrypt(data, keypack, type, level, scale)")]]
std::vector<Query> Encryptor::encrypt(const std::vector<std::vector<float>> &data, evi::EncodeType type,
                                      int level) const {
    std::vector<detail::Query> queries = (*impl_)->encrypt(data, type, level);
    std::vector<Query> res;
    res.reserve(queries.size());
    for (auto &item : queries) {
        res.emplace_back(std::make_shared<detail::Query>(std::move(item)));
    }
    return res;
}

std::vector<Query> Encryptor::encrypt(const std::vector<std::vector<float>> &data, const std::string &enckey_path,
                                      evi::EncodeType type, int level, std::optional<float> scale) const {
    std::vector<detail::Query> queries = (*impl_)->encrypt(data, enckey_path, type, level, scale);
    std::vector<Query> res;
    res.reserve(queries.size());
    for (auto &item : queries) {
        res.emplace_back(std::make_shared<detail::Query>(std::move(item)));
    }
    return res;
}

std::vector<Query> Encryptor::encrypt(const std::vector<std::vector<float>> &data, std::istream &enckey_stream,
                                      evi::EncodeType type, int level, std::optional<float> scale) const {
    std::vector<detail::Query> queries = (*impl_)->encrypt(data, enckey_stream, type, level, scale);
    std::vector<Query> res;
    res.reserve(queries.size());
    for (auto &item : queries) {
        res.emplace_back(std::make_shared<detail::Query>(std::move(item)));
    }
    return res;
}

std::vector<Query> Encryptor::encrypt(const std::vector<std::vector<float>> &data, const KeyPack &keypack,
                                      evi::EncodeType type, int level, std::optional<float> scale) const {
    std::vector<detail::Query> queries = (*impl_)->encrypt(data, getImpl(keypack), type, level, scale);
    std::vector<Query> res;
    res.reserve(queries.size());
    for (auto &item : queries) {
        res.emplace_back(std::make_shared<detail::Query>(std::move(item)));
    }
    return res;
}

Query Encryptor::encode(const std::vector<float> &data, evi::EncodeType type, int level,
                        std::optional<float> scale) const {
    return Query(std::make_shared<detail::Query>((*impl_)->encode(data, type, level, scale)));
}

std::vector<Query> Encryptor::encode(const std::vector<std::vector<float>> &data, evi::EncodeType type,
                                     int level) const {
    std::vector<Query> result;
    result.reserve(data.size());
    for (const auto &item : data) {
        result.emplace_back(this->encode(item, type, level));
    }
    return result;
}

Query Encryptor::encode(const std::vector<std::vector<float>> &msg, const EncodeType type, const int level,
                        std::optional<float> scale) {
    return Query(std::make_shared<detail::Query>((*impl_)->encode(msg, type, level, scale)));
}

} // namespace evi
