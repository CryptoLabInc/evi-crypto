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

#pragma once
#include "EVI/Enums.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/Query.hpp"
#include "EVI/SecretKey.hpp"

#include <cstddef>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace evi {

class EVI_API Utils {
public:
    static SealMode stringToSealMode(const std::string &str);
    static ParameterPreset stringToPreset(const std::string &str);
    static EvalMode stringToEvalMode(const std::string &str);
    static void serializeEvalKey(const std::string &dir_path, const std::string &out_key_path);
    static void deserializeEvalKey(const std::string &keyPath, const std::string &output_dir, bool delete_after = true);
    static void serializeKeyFiles(const std::string &key_dir, std::ostream &out);
    static void deserializeKeyFiles(std::istream &in, SecretKey &secKey, KeyPack &keypack);
    static std::string encryptMetadata(const std::string &metadata, const std::vector<uint8_t> &key,
                                       const std::vector<uint8_t> &aad = {});
    static std::string decryptMetadata(const std::string &encrypted, const std::vector<uint8_t> &key,
                                       const std::vector<uint8_t> &aad = {});
    static std::vector<uint8_t> generateRandomBytes(std::size_t size,
                                                    const std::optional<std::vector<uint8_t>> &seed = std::nullopt);
};
} // namespace evi
