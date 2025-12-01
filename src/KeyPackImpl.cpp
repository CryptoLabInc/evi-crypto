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

#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/Basic.cuh"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

using json = nlohmann::json;

namespace evi {
namespace detail {

KeyPackData::KeyPackData(const Context &context)
    : context_(context), deb_enc_key(utils::getDebContext(context), deb::SWK_ENC),
      deb_relin_key(utils::getDebContext(context), deb::SWK_MULT),
      deb_mod_pack_key(utils::getDebContext(context), deb::SWK_MODPACK_SELF) {
    mod_pack_key->setSize(context->getPadRank() * DEGREE);
    enc_loaded_ = false;
    eval_loaded_ = false;
}

KeyPackData::KeyPackData(const Context &context, std::istream &in) : KeyPackData(context) {
    this->deserialize(in);
}

KeyPackData::KeyPackData(const Context &context, const std::string &dir_path) : KeyPackData(context) {
    loadEncKeyFile(dir_path);

    if (context->getEvalMode() != EvalMode::MM) {
        loadEvalKeyFile(dir_path);
    }
}

void KeyPackData::saveEncKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios::out | std::ios_base::binary);
    if (!out.is_open()) {
        throw evi::FileNotFoundError("Failed to save encryption key");
    }
    getEncKeyBuffer(out);
    out.close();
}

void KeyPackData::getEncKeyBuffer(std::ostream &os) const {
    if (!enc_loaded_) {
        throw evi::KeyNotLoadedError("Encryption key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    os.write(reinterpret_cast<const char *>(&enc_loaded_), sizeof(bool));
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
}

void KeyPackData::getEvalKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_relin_key, out);
    // deb::serializeToStream(deb_mod_pack_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 0)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 1)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 0)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 1)), U64_DEGREE);
    mod_pack_key->setSize(DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
}

void KeyPackData::getModPackKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }
    // Is it required?
    mod_pack_key->setSize(DEGREE * context_->getPadRank());

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_mod_pack_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    out.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
}

void KeyPackData::getRelinKeyBuffer(std::ostream &out) const {
    if (!eval_loaded_) {
        throw evi::KeyNotLoadedError("evaluation key is not loaded to be saved");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_relin_key, out);
    out.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 0)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 1)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 0)), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 1)), U64_DEGREE);
}

void KeyPackData::saveEvalKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getEvalKeyBuffer(out);
    out.close();
}

void KeyPackData::saveRelinKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getRelinKeyBuffer(out);
    out.close();
}

void KeyPackData::saveModPackKeyFile(const std::string &path) const {
    std::ofstream out(path, std::ios_base::binary);
    if (!out.is_open() || !eval_loaded_) {
        throw evi::FileNotFoundError("Failed to save evaluation key");
    }
    getModPackKeyBuffer(out);
    out.close();
}

void KeyPackData::serialize(std::ostream &os) const {
    if (os.fail()) {
        throw evi::EviError("Failed to open stream");
    }

    // TODO: replace below with the following deb serialize function
    // deb::serializeToStream(deb_enc_key, os);
    // deb::serializeToStream(deb_relin_key, os);
    // deb::serializeToStream(deb_mod_pack_key, os);
    os.write(reinterpret_cast<const char *>(&enc_loaded_), sizeof(bool));
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(&eval_loaded_), sizeof(bool));
    os.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(relin_key->getPolyData(1, 1)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 0)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(relin_key->getPolyData(0, 1)), U64_DEGREE);
    os.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    os.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    os.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    os.write(reinterpret_cast<const char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
}

void KeyPackData::deserialize(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_enc_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_enc_key, enckey);
    // enc_loaded_ = true;
    is.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);

    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    is.read(reinterpret_cast<char *>(relin_key->getPolyData(1, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(relin_key->getPolyData(1, 1)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(relin_key->getPolyData(0, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(relin_key->getPolyData(0, 1)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
    utils::syncFixedKeyToDebSwkKey(context_, relin_key, deb_relin_key);
    utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
}

void KeyPackData::loadEncKeyFile(const std::string &path) {
    fs::path input(path);
    fs::path target = input;
    if (fs::is_directory(input) || (!fs::is_regular_file(input) && input.extension() != ".bin")) {
        target = input / "EncKey.bin";
    }
    std::ifstream in(target, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load encryption key");
    }
    loadEncKeyBuffer(in);
    in.close();
}

void KeyPackData::loadEncKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_enc_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_enc_key, enckey);
    // enc_loaded_ = true;
    is.read(reinterpret_cast<char *>(&enc_loaded_), sizeof(bool));
    is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(1, 1)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 0)), U64_DEGREE);
    is.read(reinterpret_cast<char *>(enckey->getPolyData(0, 1)), U64_DEGREE);
    utils::syncFixedKeyToDebSwkKey(context_, enckey, deb_enc_key);
    enc_loaded_ = true;
}

void KeyPackData::loadEvalKeyFile(const std::string &path) {
    fs::path input(path);

    auto handle_eval_bundle = [&](const fs::path &bundle_path) {
        fs::path base_dir = bundle_path.parent_path().empty() ? fs::path(".") : bundle_path.parent_path();
        fs::path dump_dir = base_dir / "dump";
        utils::deserializeEvalKey(bundle_path.string(), dump_dir.string(), false);
        loadEvalKeyFile((dump_dir / ("EVIKeys" + std::to_string(context_->getPadRank()) + ".bin")).string());
        fs::remove_all(dump_dir);
    };

    auto load_raw_file = [&](const fs::path &file_path) {
        std::ifstream in(file_path, std::ios::in | std::ios_base::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("Failed to load evaluation key");
        }

        int header = in.peek();
        if (header == 'D' || header == 'F') {
            in.close();
            handle_eval_bundle(file_path);
            return;
        }

        loadEvalKeyBuffer(in);
        in.close();
    };

    if (fs::is_directory(input) || (!fs::exists(input) && !input.has_extension())) {
        fs::path &base_dir = input;
        fs::path bundle = base_dir / "EvalKey.bin";
        if (fs::exists(bundle)) {
            handle_eval_bundle(bundle);
            return;
        }
        load_raw_file(base_dir / ("EVIKeys" + std::to_string(context_->getPadRank()) + ".bin"));
        return;
    }

    if (fs::is_regular_file(input)) {
        load_raw_file(input);
        return;
    }

    load_raw_file(input / ("EVIKeys" + std::to_string(context_->getPadRank()) + ".bin"));
}

void KeyPackData::loadEvalKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    is.read((char *)relin_key->getPolyData(1, 0), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(1, 1), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(0, 0), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(0, 1), U64_DEGREE);
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
    utils::syncFixedKeyToDebSwkKey(context_, relin_key, deb_relin_key);
    utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
    eval_loaded_ = true;
}

void KeyPackData::loadRelinKeyFile(const std::string &path) {
    std::ifstream in(path, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load evaluation key");
    }
    loadRelinKeyBuffer(in);
    in.close();
}

void KeyPackData::loadRelinKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_relin_key);
    // utils::syncDebSwkKeyToFixedKey(context_, deb_relin_key, relin_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    is.read((char *)relin_key->getPolyData(1, 0), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(1, 1), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(0, 0), U64_DEGREE);
    is.read((char *)relin_key->getPolyData(0, 1), U64_DEGREE);
    utils::syncFixedKeyToDebSwkKey(context_, relin_key, deb_relin_key);
    eval_loaded_ = true;
}

void KeyPackData::loadModPackKeyFile(const std::string &path) {
    std::ifstream in(path, std::ios::in | std::ios_base::binary);
    if (!in.is_open()) {
        throw evi::FileNotFoundError("Failed to load evaluation key");
    }
    loadModPackKeyBuffer(in);
    in.close();
}

void KeyPackData::loadModPackKeyBuffer(std::istream &is) {
    // TODO: replace below with the following deb deserialize function
    // deb::deserializeFromStream(is, deb_mod_pack_key);
    // utils::syncDebSwkKeyToVarKey(context_, deb_mod_pack_key, mod_pack_key);
    // eval_loaded_ = true;
    is.read(reinterpret_cast<char *>(&eval_loaded_), sizeof(bool));
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(1, 1)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 0)), U64_DEGREE * context_->getPadRank());
    is.read(reinterpret_cast<char *>(mod_pack_key->getPolyData(0, 1)), U64_DEGREE * context_->getPadRank());
    utils::syncVarKeyToDebSwkKey(context_, mod_pack_key, deb_mod_pack_key);
    eval_loaded_ = true;
}

void KeyPackData::save(const std::string &path) {
    saveEncKeyFile(path + "/EncKey.bin");
    saveEvalKeyFile(path + "/EVIKeys.bin");
}

KeyPack makeKeyPack(const Context &context) {
    return std::make_shared<KeyPackData>(context);
}

KeyPack makeKeyPack(const Context &context, std::istream &in) {
    return std::make_shared<KeyPackData>(context, in);
}

KeyPack makeKeyPack(const Context &context, const std::string &dir_path) {
    return std::make_shared<KeyPackData>(context, dir_path);
}

} // namespace detail
} // namespace evi
