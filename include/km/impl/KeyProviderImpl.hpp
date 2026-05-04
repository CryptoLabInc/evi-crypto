////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "km/KeyEnvelope.hpp"
#include "utils/SealInfo.hpp"

#include "nlohmann/json.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace evi {
namespace detail {

class KeyProvider {
public:
    KeyProvider() = default;
    ~KeyProvider() = default;

    nlohmann::ordered_json encapEncKey(const std::string &key_id, const std::string &key_file_path);
    nlohmann::ordered_json encapEvalKey(const std::string &key_id, const std::string &key_file_path);
    nlohmann::ordered_json encapSecKey(const std::string &key_id, std::istream &key_stream,
                                       const SealInfo &s_info = SealInfo(SealMode::NONE));
    nlohmann::ordered_json encapEncKey(const std::string &key_id, std::istream &key_stream);
    nlohmann::ordered_json encapEvalKey(const std::string &key_id, std::istream &key_stream);
    nlohmann::ordered_json encapMetadataKey(const std::string &key_id, std::istream &key_stream,
                                            const SealInfo &s_info = SealInfo(SealMode::NONE));

    void decapSecKey(const std::string &key_file_path, const std::string &out_file_path, const SealInfo &s_info);
    void decapEncKey(const std::string &key_file_path, const std::string &out_file_path);
    void decapEvalKey(const std::string &key_file_path, const std::string &out_file_path);
    void decapMetadataKey(const std::string &key_file_path, const std::string &out_file_path);
    void decapMetadataKey(const std::string &key_file_path, const std::string &out_file_path, const SealInfo &s_info);
    void decapSecKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info);
    void decapEncKey(std::istream &key_stream, std::ostream &out_stream);
    void decapEvalKey(std::istream &key_stream, std::ostream &out_stream);
    void decapMetadataKey(std::istream &key_stream, std::ostream &out_stream);
    void decapMetadataKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info);
};

} // namespace detail
} // namespace evi
