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

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "EVI/Const.hpp"
#include "EVI/Utils.hpp"
#include "utils/Utils.hpp"

#include "EVI/Enums.hpp"
#include "utils/Exceptions.hpp"
#include <filesystem>

namespace evi {
namespace detail {
namespace fs = std::filesystem;

void utils::serializeQueryTo(const Query &query, std::ostream &os) {
    QueryType query_type = QueryType::SINGLE;
    uint8_t query_type_raw = static_cast<uint8_t>(query_type);
    os.write(reinterpret_cast<const char *>(&query_type_raw), sizeof(query_type_raw));
    if (query_type_raw != static_cast<uint8_t>(QueryType::SINGLE)) {
        throw NotSupportedError("Matrix-based Query serialization requires BUILD_WITH_HEM");
    }

    if (query.empty()) {
        throw InvalidInputError("Cannot serialize empty single-query container");
    }
    auto t = query[0]->getDataType(); // check plain or cipher
    os.write(reinterpret_cast<char *>(&t), 1);
    u32 size = query.size();
    os.write(reinterpret_cast<char *>(&size), sizeof(u32));
    for (u32 i = 0; i < size; i++) {
        query[i]->serializeTo(os);
    }
}

Query utils::deserializeQueryFrom(std::istream &is) {
    uint8_t query_type_raw = 0;
    is.read(reinterpret_cast<char *>(&query_type_raw), sizeof(query_type_raw));

    if (query_type_raw != static_cast<uint8_t>(QueryType::SINGLE)) {
        throw NotSupportedError("Matrix-based Query deserialization is not supported current mode");
    }

    DataType t;
    is.read(reinterpret_cast<char *>(&t), 1);
    u32 size;
    is.read(reinterpret_cast<char *>(&size), sizeof(u32));
    Query res;
    switch (t) {
    case DataType::CIPHER:
        for (u32 i = 0; i < size; i++) {
            res.emplace_back(std::make_shared<SingleBlock<DataType::CIPHER>>(is));
        }
        break;
    case DataType::PLAIN:
        for (u32 i = 0; i < size; i++) {
            res.emplace_back(std::make_shared<SingleBlock<DataType::PLAIN>>(is));
        }
        break;
    case DataType::SERIALIZED_PLAIN:
        throw NotSupportedError("To be updated after shared-a feature done");
    default:
        throw NotSupportedError("Invalid type for query deserialization");
    }
    return res;
}

void utils::serializeResultTo(const SearchResult &res, std::ostream &os) {
    uint8_t tag = 0;
    os.write(reinterpret_cast<const char *>(&tag), sizeof(tag));

    u32 total_count = res.getTotalItemCount();
    if (!total_count && res->ip_data != nullptr && res->ip_data->n != 0) {
        total_count = static_cast<u32>(res->ip_data->n);
    }
    os.write(reinterpret_cast<const char *>(&total_count), sizeof(total_count));

    if (res->ip_data != nullptr) {
        res->ip_data->serializeTo(os);
    } else {
        throw NotSupportedError("Invalid type for result serialization");
    }
}

SearchResult utils::deserializeResultFrom(std::istream &is) {
    uint8_t tag = 0;
    is.read(reinterpret_cast<char *>(&tag), sizeof(tag));

    u32 total_count = 0;
    is.read(reinterpret_cast<char *>(&total_count), sizeof(total_count));

    SearchResult res;

    if (tag == 0) {
        res = SearchResult(std::make_shared<IPSearchResult>());
        res->ip_data = std::make_shared<Matrix<DataType::CIPHER>>(0);
        res->ip_data->deserializeFrom(is);
        if (!total_count && res->ip_data != nullptr) {
            total_count = static_cast<u32>(res->ip_data->n);
        }
    } else {
        throw std::runtime_error("Unknown result type tag");
    }
    res.total_item_count = total_count;
    return res;
}

SealMode utils::stringToSealMode(const std::string &str) {
    if (str == "NONE") {
        return SealMode::NONE;
    }
    if (str == "AES-KEK") {
        return SealMode::AES_KEK;
    }
    return SealMode::NONE;
}

ParameterPreset utils::stringToPreset(const std::string &str) {
    if (str == "IP0") {
        return ParameterPreset::IP0;
    } else if (str == "IP1") {
        return ParameterPreset::IP1;
    } else if (str == "QF0") {
        return ParameterPreset::QF0;
    } else if (str == "QF1") {
        return ParameterPreset::QF1;
    } else {
        throw InvalidInputError("Invalid preset name : " + str);
    }
}

std::string utils::assignParameterString(evi::ParameterPreset preset) {
    switch (preset) {
    case evi::ParameterPreset::IP0: {
        return "IP0";
    }
    case evi::ParameterPreset::IP1: {
        return "IP1";
    }
    case evi::ParameterPreset::QF1: {
        return "QF1";
    }
    case evi::ParameterPreset::QF0: {
        return "QF0";
    }
    default:
        return "NULL";
    }
}

std::string utils::assignSealModeString(evi::SealMode s_mode) {
    switch (s_mode) {
    case evi::SealMode::AES_KEK: {
        return "AES-KEK";
    }
    case evi::SealMode::NONE: {
        return "NONE";
    }
    default:
        return "NULL";
    }
}

// Serialize a string to the ostringstream
void utils::serializeString(const std::string &str, std::ostream &out) {
    uint64_t size = str.size();
    out.write(reinterpret_cast<const char *>(&size), sizeof(size)); // Write string size
    out.write(str.data(), size);                                    // Write string content
}

// Serialize the directory structure into an ostringstream
void utils::serializeEvalKey(const std::string &dir_path, const std::string &out_key_data) {
    std::ofstream out(out_key_data, std::ios::binary);
    for (const auto &entry : fs::recursive_directory_iterator(dir_path)) {
        std::string relative_path = fs::relative(entry.path(), dir_path).string();

        if (fs::is_directory(entry.status())) {
            // Serialize directory
            char type = 'D';
            out.write(&type, sizeof(type));      // Write type 'D'
            serializeString(relative_path, out); // Write relative path
        } else if (fs::is_regular_file(entry.status())) {

            if (entry.path().filename().string().find("EncKey") != std::string::npos ||
                entry.path().filename().string().find("EvalKey") != std::string::npos ||
                entry.path().filename().string().find("SecKey") != std::string::npos) {
                continue;
            }

            // Serialize file
            char type = 'F';
            out.write(&type, sizeof(type));      // Write type 'F'
            serializeString(relative_path, out); // Write relative path

            // Read and serialize file contents
            std::ifstream in_file(entry.path(), std::ios::binary | std::ios::ate);
            if (!in_file.is_open()) {
                throw FileNotFoundError("Failed to open file: " + entry.path().string());
            }

            std::streamsize file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            out.write(reinterpret_cast<const char *>(&file_size), sizeof(file_size)); // Write file size

            std::vector<char> content(file_size);
            in_file.read(content.data(), file_size);   // Read file contents
            out.write(content.data(), content.size()); // Write file contents

            in_file.close();
            fs::remove(entry.path());
        }
    }
    for (auto it = fs::recursive_directory_iterator(dir_path, fs::directory_options::skip_permission_denied),
              end = fs::recursive_directory_iterator();
         it != end;) {
        if (fs::is_directory(it->path()) && fs::is_empty(it->path())) {
            fs::remove(it->path());                          // Remove empty directory
            it = fs::recursive_directory_iterator(dir_path); // Restart iterator due to potential structure change
        } else {
            ++it;
        }
    }
    out.close();
}

// Deserialize a string from the istringstream
void utils::deserializeString(std::istream &in, std::string &str) {
    uint64_t size;
    in.read(reinterpret_cast<char *>(&size), sizeof(size)); // Read string size

    str.resize(size);
    in.read(&str[0], size); // Read string content
}

// Deserialize the directory structure from an istringstream
void utils::deserializeEvalKey(const std::string &key_path, const std::string &out_dir, bool delete_after) {
    const fs::path output_dir(out_dir);
    if (!fs::exists(output_dir)) {
        fs::create_directory(output_dir);
    }

    std::ifstream in(key_path, std::ios::binary);
    while (in.peek() != EOF) {
        char type;
        in.read(&type, sizeof(type)); // Read type ('D' or 'F')

        std::string relative_path;
        deserializeString(in, relative_path); // Read relative path

        fs::path full_path = output_dir / relative_path;

        if (type == 'D') {
            // Create directory
            fs::create_directories(full_path);
        } else if (type == 'F') {
            // Create file
            std::streamsize file_size;
            in.read(reinterpret_cast<char *>(&file_size), sizeof(file_size)); // Read file size

            std::vector<char> content(file_size);
            in.read(content.data(), file_size); // Read file contents

            std::ofstream out_file(full_path, std::ios::binary);
            if (!out_file.is_open()) {
                throw std::runtime_error("Failed to create file: " + full_path.string());
            }

            out_file.write(content.data(), content.size()); // Write file contents
        }
    }

    in.close();
    if (delete_after) {
        fs::remove(fs::path(key_path));
    }
}

void utils::serializeKeyFiles(const std::string &key_dir, std::ostream &out) {
    static constexpr std::array<const char *, 3> ORDER = {"SecKey.bin", "EncKey.bin", "EvalKey.bin"};
    fs::path dir(key_dir);
    for (const auto *name : ORDER) {
        fs::path file = dir / name;
        if (!fs::exists(file)) {
            throw FileNotFoundError("Key file not found: " + file.string());
        }
        std::ifstream in(file, std::ios::binary | std::ios::ate);
        if (!in.is_open()) {
            throw FileNotFoundError("Failed to open key file: " + file.string());
        }
        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        in.read(buffer.data(), size);

        uint32_t name_len = static_cast<uint32_t>(std::strlen(name));
        out.write(reinterpret_cast<const char *>(&name_len), sizeof(name_len));
        out.write(name, name_len);
        uint64_t blob_size = static_cast<uint64_t>(size);
        out.write(reinterpret_cast<const char *>(&blob_size), sizeof(blob_size));
        out.write(buffer.data(), blob_size);
    }
    uint32_t sentinel = 0;
    out.write(reinterpret_cast<const char *>(&sentinel), sizeof(sentinel));
}

void utils::deserializeKeyFiles(std::istream &in, SecretKey &sec_key, KeyPack &keypack) {
    while (true) {
        uint32_t name_len = 0;
        in.read(reinterpret_cast<char *>(&name_len), sizeof(name_len));
        if (!in) {
            throw InvalidInputError("Failed to read key file name length");
        }
        if (name_len == 0) {
            break;
        }
        std::string name(name_len, '\0');
        in.read(name.data(), name_len);
        uint64_t size = 0;
        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        std::string buffer(size, '\0');
        in.read(buffer.data(), size);
        std::istringstream data_stream(buffer, std::ios::binary);
        if (name == "SecKey.bin") {
            sec_key->loadSecKey(data_stream);
        } else if (name == "EncKey.bin") {
            keypack->loadEncKeyBuffer(data_stream);
        } else if (name == "EvalKey.bin") {
            keypack->loadEvalKeyBuffer(data_stream);
        }
    }
    if (!sec_key) {
        throw InvalidInputError("Secret key blob missing in key bundle");
    }
}

std::vector<std::pair<int, int>> utils::adjustRankList(std::vector<int> &rank_list) {
    std::map<int, int> inner_ranks;
    if (!rank_list.empty()) {
        std::sort(rank_list.begin(), rank_list.end());
        std::set<int> unique_ranks;
        for (int d : rank_list) {
            if (d < evi::MIN_CONTEXT_SIZE || d > evi::MAX_CONTEXT_SIZE) {
                throw InvalidInputError("Dimension must be over than " + (std::to_string(evi::MIN_CONTEXT_SIZE >> 1)) +
                                        " and less than or equal to " + std::to_string(evi::MAX_CONTEXT_SIZE) + ".");
            }
            int power = evi::MIN_CONTEXT_SIZE;
            while (power < d) {
                power *= 2;
            }
            unique_ranks.insert(power);
        }
        rank_list.assign(unique_ranks.begin(), unique_ranks.end());
    } else {
        for (int d = evi::MIN_CONTEXT_SIZE; d <= evi::MAX_CONTEXT_SIZE; d *= 2) {
            rank_list.push_back(d);
        }
    }
    for (int i = 0; i < rank_list.size(); i++) {
        int inner_rank = getInnerRank(rank_list[i]);
        if (inner_ranks.find(inner_rank) == inner_ranks.end()) {
            inner_ranks[inner_rank] = i;
        }
    }

    return std::vector<std::pair<int, int>>(inner_ranks.begin(), inner_ranks.end());
}

} // namespace detail

void Utils::serializeEvalKey(const std::string &dir_path, const std::string &out_key_path) {
    detail::utils::serializeEvalKey(dir_path, out_key_path);
}

void Utils::deserializeEvalKey(const std::string &key_path, const std::string &output_dir, bool delete_after) {
    detail::utils::deserializeEvalKey(key_path, output_dir, delete_after);
}

void Utils::serializeKeyFiles(const std::string &dir_path, std::ostream &out) {
    detail::utils::serializeKeyFiles(dir_path, out);
}

void Utils::deserializeKeyFiles(std::istream &in, SecretKey &seckey, KeyPack &keypack) {
    auto &sec_impl = getImpl(seckey);
    if (!sec_impl) {
        throw std::runtime_error("SecretKey implementation is null");
    }
    auto &kp_impl = getImpl(keypack);
    if (!kp_impl) {
        throw std::runtime_error("KeyPack implementation is null");
    }
    detail::utils::deserializeKeyFiles(in, *sec_impl, kp_impl);
}

SealMode Utils::stringToSealMode(const std::string &s) {
    return detail::utils::stringToSealMode(s);
}

ParameterPreset Utils::stringToPreset(const std::string &s) {
    return detail::utils::stringToPreset(s);
}
} // namespace evi
