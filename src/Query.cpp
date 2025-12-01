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

#include "EVI/Query.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "utils/Utils.hpp"

namespace evi {

Query::Query(std::shared_ptr<detail::Query> impl) noexcept : impl_(std::move(impl)) {}

std::shared_ptr<detail::Query> &getImpl(Query &query) noexcept {
    return query.impl_;
}
const std::shared_ptr<detail::Query> &getImpl(const Query &query) noexcept {
    return query.impl_;
}

uint32_t Query::getLevel() const {
    if (!impl_) {
        throw std::runtime_error("Query::block: empty Query implementation");
    }
    return impl_->at(0)->getLevel();
}

uint32_t Query::getShowDim() const {
    if (!impl_) {
        throw std::runtime_error("Query::block: empty Query implementation");
    }
    return impl_->at(0)->show_dim;
}

uint32_t Query::getInnerItemCount() const {
    if (!impl_) {
        throw std::runtime_error("Query::block: empty Query implementation");
    }
    return impl_->at(0)->n;
}

std::size_t Query::size() const {
    return impl_ ? impl_->size() : 0;
}

Query Query::deserializeFrom(std::istream &is) {
    auto impl = std::make_shared<detail::Query>(detail::utils::deserializeQueryFrom(is));
    return Query(std::move(impl));
}

Query Query::deserializeFromString(const std::string &data) {
    std::istringstream iss(data, std::ios::binary);
    return deserializeFrom(iss);
}

void Query::serializeTo(const Query &query, std::ostream &os) {
    detail::utils::serializeQueryTo(*query.impl_, os);
}

void Query::serializeToString(const Query &query, std::string &out) {
    std::ostringstream oss(std::ios::binary);
    Query::serializeTo(query, oss);
    out = oss.str();
}

void Query::serializeVectorTo(const std::vector<Query> &queries, std::ostream &os) {
    uint32_t count = static_cast<uint32_t>(queries.size());
    os.write(reinterpret_cast<const char *>(&count), sizeof(count));
    for (const auto &q : queries) {
        Query::serializeTo(q, os);
    }
}

void Query::serializeVectorToString(const std::vector<Query> &queries, std::string &out) {
    std::ostringstream oss(std::ios::binary);
    Query::serializeVectorTo(queries, oss);
    out = oss.str();
}

std::vector<Query> Query::deserializeVectorFrom(std::istream &is) {
    uint32_t count = 0;
    is.read(reinterpret_cast<char *>(&count), sizeof(count));
    std::vector<Query> queries;
    queries.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        queries.emplace_back(Query::deserializeFrom(is));
    }
    return queries;
}

std::vector<Query> Query::deserializeVectorFromString(const std::string &data) {
    std::istringstream iss(data, std::ios::binary);
    return deserializeVectorFrom(iss);
}

} // namespace evi
