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

#include "EVI/SearchResult.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "utils/Utils.hpp"

namespace evi {

SearchResult::SearchResult(std::shared_ptr<detail::SearchResult> impl) : impl_(std::move(impl)) {}

uint32_t SearchResult::getItemCount() {
    const auto *handle = impl_.get();
    if (!handle) {
        throw NotSupportedError("Handle is null");
    }

    auto ip = handle->get();
    if (!ip || !ip->ip_data) {
        throw NotSupportedError("ip value is null");
    } else {
        return static_cast<uint32_t>(ip->ip_data->n);
    }

    std::cerr << "Invalid access" << std::endl;
    return -1;
}

std::shared_ptr<detail::SearchResult> &getImpl(SearchResult &res) noexcept {
    return res.impl_;
}

const std::shared_ptr<detail::SearchResult> &getImpl(const SearchResult &res) noexcept {
    return res.impl_;
}

SearchResult SearchResult::deserializeFrom(std::istream &is) {
    auto impl = std::make_shared<detail::SearchResult>(detail::utils::deserializeResultFrom(is));
    return SearchResult(std::move(impl));
}

void SearchResult::serializeTo(const SearchResult &res, std::ostream &os) {
    detail::utils::serializeResultTo(*getImpl(res), os);
}

} // namespace evi
