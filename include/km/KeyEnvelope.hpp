////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
// This software and/or source code may be commercially used and/or           //
// disseminated only with the written permission of CryptoLab Inc,            //
// or in accordance with the terms and conditions stipulated in the           //
// agreement/contract under which the software and/or source code has been    //
// supplied by CryptoLab Inc. Any unauthorized commercial use and/or          //
// dissemination of this file is strictly prohibited and will constitute      //
// an infringement of copyright.                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "utils/Exceptions.hpp"

#include "km/KeyStorageConfig.hpp"
#include "nlohmann/json.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace evi {

enum class KeyFormatVersion : uint8_t {
    V1 = 1,
    Latest = V1,
};

// TODO : change prime list
struct KeyEntryParameter {
    uint64_t Q{0};
    uint64_t P{0};
    double DB_SCALE_FACTOR{0};
    double QUERY_SCALE_FACTOR{0};
    std::string preset;
};

struct KeyEntryMetadata {
    KeyEntryParameter parameter;
    std::string eval_mode;          // for only eval mode
    std::optional<std::string> dim; // optional
};

enum class KeyLifecycleState : uint8_t {
    Preparing, // Reserved for a future staged key-generation flow; not emitted today.
    Active,
    Deactivated,
    Destroyed,
};

std::string toString(KeyLifecycleState state);
KeyLifecycleState parseKeyLifecycleState(std::string_view value);

struct KeyState {
    KeyLifecycleState value{KeyLifecycleState::Active};
    std::optional<std::string> reason;
    std::string updated_at;

    static std::string sanitizeReason(const std::string &reason);
    nlohmann::ordered_json toJson() const;
    static KeyState fromJson(const nlohmann::ordered_json &node, const std::string &owner_name);
};

struct ProviderEntry {
    std::string name;
    std::string format_version;
    std::string role;
    std::string hash;
    KeyEntryMetadata metadata;
    std::string key_data;

    std::optional<std::string> alg; // -> for local wrap secretkey using kek
    std::optional<std::string> iv;
    std::optional<std::string> tag;
};

struct KeyType {
    std::string name;
    std::string role;

    static const KeyType SecKey;
    static const KeyType SecKeySealed;
    static const KeyType EncKey;
    static const KeyType EvalKey;
    static const KeyType MetadataKey;
    static const KeyType MetadataKeySealed;
};

inline const KeyType KeyType::SecKey{"seckey", "decryption key"};
inline const KeyType KeyType::SecKeySealed{"seckey.sealed", "decryption key"};
inline const KeyType KeyType::EncKey{"enckey", "encryption key"};
inline const KeyType KeyType::EvalKey{"evalkey", "evaluation key"};
inline const KeyType KeyType::MetadataKey{"metadatakey", "metadata key"};
inline const KeyType KeyType::MetadataKeySealed{"metadatakey.sealed", "metadata key"};

struct ProviderEnvelope {
    std::vector<ProviderEntry> entries;
};

} // namespace evi
