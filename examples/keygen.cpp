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

#include "CLI/CLI.hpp"
#include "EVI/EVI.hpp"

#ifdef BUILD_DEBUG
#include "utils/Utils.hpp"
#endif

#include <fcntl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <unistd.h>
#include <vector>

using json = nlohmann::json;

bool checkContinue();

int main(int argc, char **argv) {
    CLI::App app;

    // add parameter option
    std::string store_path;
    app.add_option("-p, --path", store_path, "Path to directory to store generated keys")->default_val("keys");
    std::string preset_str;
    app.add_option("-r, --preset", preset_str, "Preset name for key parameters: IP0/IP1/QF0/QF1")->default_val("IP0");
    std::string seal_mode{""};
    auto mode_opt = app.add_option("-m, --seal-mode", seal_mode,
                                   "Select \"NONE\", \"AES-KEK\", \"HSM-PORT\", or \"HSM-SERUAL\" mode")
                        ->default_val("NONE");
    int hsm_con_num{0};
    auto con_num_opt = app.add_option("-n, --num", hsm_con_num, "Insert HSM Port or HSM Serial Number.");
    int auth_id{0};
    auto auth_id_opt = app.add_option("-i, --auth-id", auth_id, "HSM auth id");
    std::string auth_pw{""};
    auto auth_pw_opt = app.add_option("-w, --auth-pw", auth_pw, "HSM auth pw");

    std::string mode = "";
    app.add_option("-e, --eval-mode", mode, "Select evaluation mode: NONE/RMP/RMS/MS defualt is RMP")
        ->default_val("RMP");

    CLI11_PARSE(app, argc, argv);

    // std::vector<int> ranks;
    // app.add_option("-R, --ranks", ranks, "Multiple dimensions (e.g., --ranks 32 512 4096)");

#ifdef BUILD_DEBUG
    bool to_serialize;
    app.add_option("-s, --serialize", to_serialize, "[DEBUG] Set output evaluation key to be serialized")
        ->default_val(true);
#endif

    mode_opt->check([&](const std::string &mode) {
        if (mode == "HSM-PORT" || mode == "HSM-SERUAL") {
            con_num_opt->required(true);
            auth_id_opt->required(true);
            auth_pw_opt->required(true);
        }
        return std::string();
    });

    evi::EvalMode mode_t;
    if (mode == "RMP") {
        mode_t = evi::EvalMode::RMP;
    } else if (mode == "NONE") {
        mode_t = evi::EvalMode::FLAT;
    } else if (mode == "RMS") {
        mode_t = evi::EvalMode::RMS;
    } else if (mode == "MS") {
        mode_t = evi::EvalMode::MS;
    } else if (mode == "MM") {
        mode_t = evi::EvalMode::MM;
    } else {
        std::cerr << "Unsupported eval mode. Select from NONE/RMP/RMS/MS/MM" << std::endl;
        return 1;
    }

    // input seal mode
    std::vector<uint8_t> kek(evi::AES256_KEY_SIZE);
    evi::SealInfo s_info = evi::SealInfo(evi::Utils::stringToSealMode(seal_mode));

    switch (s_info.getSealMode()) {
    case evi::SealMode::AES_KEK:
        if (!isatty(STDIN_FILENO)) {
            std::cin.read(reinterpret_cast<char *>(kek.data()), kek.size());
            kek.resize(std::cin.gcount());
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            freopen("/dev/tty", "r", stdin);
        } else {
            std::cout << "Input your 32 byte aes key using pipe\n";
            return 1;
        }
        s_info = evi::SealInfo(evi::SealMode::AES_KEK, kek);
        break;
    case evi::SealMode::HSM_PORT:
        s_info = evi::SealInfo(evi::SealMode::HSM_PORT, hsm_con_num, auth_id, auth_pw);
        break;
    case evi::SealMode::HSM_SERIAL:
        if (hsm_con_num == 0) {
            std::cout << "Insert hsm prot or serial number\n";
        }
        s_info = evi::SealInfo(evi::SealMode::HSM_SERIAL, hsm_con_num, auth_id, auth_pw);
        break;
    }

    // generate key
    evi::ParameterPreset preset = evi::Utils::stringToPreset(preset_str);
    std::cout << "Target Key path: " << store_path << std::endl;
    // evi::MultiKeyGenerator keygen(store_path, preset, s_info, ranks);
    std::vector<evi::Context> contexts = makeMultiContext(preset, evi::DeviceType::CPU, mode_t);

    evi::MultiKeyGenerator keygen(contexts, store_path, s_info);
    bool rc = keygen.checkFileExist();
    if (rc == false && checkContinue() == false) {
        std::cout << "Action canceled \n";
        exit(1);
    }

    if (s_info.getSealMode() == evi::SealMode::NONE) {
        std::cout << "Generate keys NONE mode " << std::endl;
    } else {
        std::cout << "Generate keys AES-KEK mode " << std::endl;
    }
    auto sec_key = keygen.generateKeys();
    std::cout << "Saving to target directory" << std::endl;
    std::cout << "Done!" << std::endl;

    // // save key info
    // json j;
    // j["heaan_preset"] = evi::utils::assignParameterString(preset);
    // j["seal_type"] = evi::utils::assignSealModeString(s_info.s_mode);
    // std::filesystem::path metaname = "metadata.json";
    // std::filesystem::path filepath = store_path / metaname;
    // std::ofstream meta(filepath);
    // meta << std::setw(4) << j << std::endl;

#ifdef BUILD_DEBUG
    if (!to_serialize) {
        std::cout << "Deserializing EvalKey to debug" << std::endl;
        evi::Utils::deserializeEvalKey(store_path + "/EvalKey.bin", store_path);
    }
#endif

    return 0;
}

bool checkContinue() {
    std::string str;
    std::cout << "⚠ WARNING: If you continue, the existing key file will be overwritten.\n"
              << "Do you want to proceed?(y/n): ";

    if (std::cin.eof()) {
        std::cerr << "Error: No input stream available.\n";
        return 1;
    }

    std::getline(std::cin, str);
    transform(str.begin(), str.end(), str.begin(), ::tolower);
    if (str == "y" || str == "yes") {
        return true;
    } else {
        return false;
    }
}
