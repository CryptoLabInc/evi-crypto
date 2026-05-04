#include "CLI/CLI.hpp"
#include "EVI/EVI.hpp"
#include "km/KeyManager.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static void printBanner(const std::string &title) {
    std::cout << "==============================\n";
    std::cout << " " << title << "\n";
    std::cout << "==============================\n";
}

static std::vector<uint8_t> readKekFile(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::invalid_argument("Failed to open KEK file: " + path);
    }
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (key.size() != evi::AES256_KEY_SIZE) {
        throw std::invalid_argument("KEK file must contain exactly 32 bytes: " + path);
    }
    return key;
}

static evi::SealInfo makeSecKeySealInfo(const std::string &mode_str, const std::string &kek_file) {
    const auto mode = evi::Utils::stringToSealMode(mode_str);
    if (mode == evi::SealMode::NONE) {
        return evi::SealInfo(evi::SealMode::NONE);
    }
    if (mode != evi::SealMode::AES_KEK) {
        throw std::invalid_argument("Only NONE or AES-KEK is supported in this example");
    }
    if (kek_file.empty()) {
        throw std::invalid_argument("--kek-file is required when --sec-seal-mode=AES-KEK");
    }
    return evi::SealInfo(evi::SealMode::AES_KEK, readKekFile(kek_file));
}

int main(int argc, char **argv) {
    CLI::App app{"KeyManager wrap/unwrap example"};

    std::string key_dir = "keys";
    app.add_option("-p,--path", key_dir, "Key directory")->default_val("keys");

    std::string key_id = "CL:envector:demo:vector_sk:apne2";
    app.add_option("--key-id", key_id, "Key ID used for wrapping")->default_val("CL:envector:demo:vector_sk:apne2");

    std::string preset_str = "IP1";
    app.add_option("-r,--preset", preset_str, "Preset for key generation (IP0/IP1/QF0/QF1)")->default_val("IP0");

    std::string eval_mode_str = "MM";
    app.add_option("-e,--eval-mode", eval_mode_str, "Eval mode for key generation (FLAT/SINGLE/RMP/RMS/MS/MM)")
        ->default_val("RMP");

    std::string sec_seal_mode = "NONE";
    app.add_option("--sec-seal-mode", sec_seal_mode, "SecKey seal mode for wrap/unwrap (NONE|AES-KEK)")
        ->default_val("NONE");
    std::string kek_file;
    app.add_option("--kek-file", kek_file, "Path to AES-256 KEK file used when --sec-seal-mode=AES-KEK");

    bool keygen = false;
    bool unwrap = false;
    app.add_flag("--keygen", keygen, "Generate keys and wrap them");
    app.add_flag("--unwrap", unwrap, "Unwrap *.json keys into *.bin");
    bool cleanup = false;
    app.add_flag("--cleanup", cleanup, "Remove existing output key files before writing");

    std::string audit_path;
    app.add_option("--audit", audit_path, "Write audit log to this JSONL file (e.g. kms_audit.jsonl)");

    CLI11_PARSE(app, argc, argv);

    const fs::path key_path = key_dir;
    fs::create_directories(key_path);

    const fs::path sec_bin = key_path / "SecKey.bin";
    const fs::path enc_bin = key_path / "EncKey.bin";
    const fs::path eval_bin = key_path / "EvalKey.bin";
    const fs::path metadata_bin = key_path / "MetadataKey.bin";

    const fs::path sec_json = key_path / "SecKey.json";
    const fs::path enc_json = key_path / "EncKey.json";
    const fs::path eval_json = key_path / "EvalKey.json";
    const fs::path metadata_json = key_path / "MetadataKey.json";

    evi::KeyManager manager = evi::makeKeyManager();
    if (!audit_path.empty()) {
        manager.setAuditStore(audit_path);
        std::cout << "Audit log -> " << audit_path << "\n";
    }
    const evi::SealInfo sec_seal_info = makeSecKeySealInfo(sec_seal_mode, kek_file);

    if (unwrap) {
        printBanner("UNWRAP");
        if (cleanup) {
            fs::remove(sec_bin);
            fs::remove(enc_bin);
            fs::remove(eval_bin);
            fs::remove(metadata_bin);
        }
        manager.unwrapSecKey(sec_json.string(), sec_bin.string(), sec_seal_info);
        manager.unwrapEncKey(enc_json.string(), enc_bin.string());
        manager.unwrapEvalKey(eval_json.string(), eval_bin.string());
        if (fs::exists(metadata_json)) {
            manager.unwrapMetadataKey(metadata_json.string(), metadata_bin.string(), sec_seal_info);
        }
        std::cout << "Unwrapped keys to: " << key_path.string() << std::endl;
        return 0;
    }

    if (keygen) {
        printBanner("KEYGEN + WRAP");
        const auto preset = evi::Utils::stringToPreset(preset_str);
        const auto eval_mode = evi::Utils::stringToEvalMode(eval_mode_str);
        std::vector<evi::Context> contexts = evi::makeMultiContext(preset, evi::DeviceType::CPU, eval_mode);
        evi::SealInfo s_info(evi::SealMode::NONE);
        evi::MultiKeyGenerator keygen_impl(contexts, key_path.string(), s_info);
        keygen_impl.generateKeys();
    } else {
        printBanner("WRAP");
    }

    if (!fs::exists(sec_bin) || !fs::exists(enc_bin) || !fs::exists(eval_bin)) {
        std::cerr << "Missing key files in: " << key_path.string() << std::endl;
        std::cerr << "Expected: SecKey.bin / EncKey.bin / EvalKey.bin" << std::endl;
        return 1;
    }

    if (cleanup) {
        fs::remove(sec_json);
        fs::remove(enc_json);
        fs::remove(eval_json);
        fs::remove(metadata_json);
    }
    manager.wrapSecKey(key_id, sec_bin.string(), sec_json.string(), sec_seal_info);
    manager.wrapEncKey(key_id, enc_bin.string(), enc_json.string());
    manager.wrapEvalKey(key_id, eval_bin.string(), eval_json.string());
    if (fs::exists(metadata_bin)) {
        manager.wrapMetadataKey(key_id, metadata_bin.string(), metadata_json.string(), sec_seal_info);
    }

    std::cout << "Wrapped keys to: " << key_path.string() << std::endl;
    return 0;
}
