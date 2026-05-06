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

#include "EVI/Const.hpp"
#include "EVI/Utils.hpp"
#include "nlohmann/json.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {
int printUsageAndExit() {
    std::cout << "Usage: metadata-endecryption [--metadata <value>] [--aad <value>]\n"
              << "  --metadata <value>  Plain metadata string to encrypt\n"
              << "  --aad <value>   Optional AAD string\n"
              << "If no option is provided, --metadata \"Hello World~!\" is used.\n";
    return 0;
}
} // namespace

int main(int argc, char **argv) {
    try {
        std::string metadata_text = "Hello World~!";
        std::string aad_text;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                return printUsageAndExit();
            }
            if ((arg == "--metadata" || arg == "--text") && i + 1 < argc) {
                metadata_text = argv[++i];
                continue;
            }
            if (arg == "--aad" && i + 1 < argc) {
                aad_text = argv[++i];
                continue;
            }
            std::cerr << "Unknown or incomplete option: " << arg << std::endl;
            return 2;
        }

        const std::vector<uint8_t> aad(aad_text.begin(), aad_text.end());
        const std::vector<uint8_t> key = evi::Utils::generateRandomBytes(evi::AES256_KEY_SIZE);

        const std::string encrypted = evi::Utils::encryptMetadata(metadata_text, key, aad);
        const std::string decrypted_text = evi::Utils::decryptMetadata(encrypted, key, aad);

        std::cout << "[input metadata]\n" << metadata_text << "\n\n";
        std::cout << "[encrypted json]\n" << nlohmann::json::parse(encrypted).dump(2) << "\n\n";
        std::cout << "[decrypted metadata]\n" << decrypted_text << "\n\n";
        std::cout << "[round-trip]\n" << (decrypted_text == metadata_text ? "PASS" : "FAIL") << std::endl;
        return decrypted_text == metadata_text ? 0 : 1;
    } catch (const std::exception &ex) {
        std::cerr << "ERROR: " << ex.what() << std::endl;
        return 1;
    }
}
