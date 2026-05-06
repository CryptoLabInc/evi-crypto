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
#include "EVI/Context.hpp"
#include "EVI/Export.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/SecretKey.hpp"
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>

namespace evi {
namespace detail {
class KeyGenerator;
class MultiKeyGenerator;
} // namespace detail

/**
 * @class KeyGenerator
 * @brief Generates a Secret Key, Encryption Key, and Evaluation Key for homomorphic encryption.
 *
 * The `KeyGenerator` is responsible for creating a `SecretKey` and the corresponding public keys
 * such as the Encryption Key and Evaluation Key, based on the given encryption context.
 * The generated secret key is stored within a `SecretKey` instance,
 * while the public keys are typically stored in a `KeyPack` instance.
 */
class EVI_API KeyGenerator {
public:
    /// @brief Default constructor is deleted. Use `makeKeyGenerator()` factory functions instead.
    KeyGenerator() = delete;

    /**
     * @brief Constructs a `KeyGenerator` with a internal implementation.
     * @param impl Shared pointer to the internal `detail::KeyGenerator` object.
     */
    explicit KeyGenerator(std::shared_ptr<detail::KeyGenerator> impl) noexcept;

    /**
     * @brief Generates a new secret key.
     * @return The generated `SecretKey` object.
     */
    SecretKey genSecKey();

    /**
     * @brief Generates public keys and returns the associated KeyPack.
     * @param sec_key Secret key used to derive public keys.
     * @return The generated `KeyPack` object.
     */
    KeyPack genPubKeys(SecretKey &sec_key);

    /**
     * @brief Generates shared-A keys for RMS (shared-a) mode.
     *
     * Generates all four shared-A key types required for RMS evaluation:
     * SharedASwitchKey, AdditiveSharedASwitchKey, SharedAModPackKey, CCSharedAModPackKey.
     *
     * @param sec_from The main secret key.
     * @param sec_to Vector of additional secret keys (one per pad_rank dimension).
     */
    void genSharedAKeys(SecretKey &sec_from, const std::vector<SecretKey> &sec_to);

private:
    std::shared_ptr<detail::KeyGenerator> impl_;
};

/**
 * @brief Creates a KeyGenerator with a given context and key storage.
 *
 * @param context Context used for key initialization and device selection.
 * @param pack The key pack used to store generated public keys.
 * @param seed Optional seed for deterministic key generation.
 * @return A configured `KeyGenerator` instance.
 */
EVI_API KeyGenerator makeKeyGenerator(const Context &context, KeyPack &pack,
                                      const std::optional<std::vector<uint8_t>> &seed = std::nullopt);

/**
 * @brief Creates a KeyGenerator and automatically initializes an internal KeyPack.
 *
 * @param context Context used for key initialization and device selection.
 * @param seed Optional seed for deterministic key generation.
 * @return A configured `KeyGenerator` instance.
 */
EVI_API KeyGenerator makeKeyGenerator(const Context &context,
                                      const std::optional<std::vector<uint8_t>> &seed = std::nullopt);

/**
 * @class MultiKeyGenerator
 * @brief Generates and seals secret keys across multiple contexts and stores them securely.
 *
 * `MultiKeyGenerator` is typically used for generating sealed secret keys across multiple devices or ranks,
 * especially in distributed or multi-GPU setups.
 */
class EVI_API MultiKeyGenerator {
public:
    /// @brief Default constructor is deleted. Use `makeMultiKeyGenerator()` factory functions instead.
    MultiKeyGenerator() = delete;

    /**
     * @brief Constructs a MultiKeyGenerator from multiple contexts.
     * @param contexts List of contexts.
     * @param dir_path Path to the directory where all key files are stored.
     * @param s_info Sealing configuration (e.g., AES-KEK).
     * @param seed Optional seed for deterministic key generation.
     */
    MultiKeyGenerator(const std::vector<Context> &contexts, const std::string &dir_path, SealInfo &s_info,
                      const std::optional<std::vector<uint8_t>> &seed = std::nullopt);

    /**
     * @brief Constructs a MultiKeyGenerator with an internal implementation.
     * @param impl Shared pointer to the internal `detail::MultiKeyGenerator` object.
     */
    explicit MultiKeyGenerator(std::shared_ptr<detail::MultiKeyGenerator> impl) noexcept;

    /**
     * @brief Checks whether the key files already exist in the target directory.
     * @return `true` if key files are found; otherwise `false`.
     */
    bool checkFileExist() const;

    /**
     * @brief Generates a new SecretKey.
     * @return The generated `SecretKey` object.
     */
    SecretKey generateKeys();

    /**
     * @brief Generates keys and serializes the resulting key files into a stream.
     * @param os Output stream that receives the serialized key bundle.
     * @return The generated `SecretKey` object.
     */
    SecretKey generateKeys(std::ostream &os);

    /**
     * @brief Generates keys and writes secret/encryption/evaluation keys to separate output streams.
     * @param seckey Output stream receiving the secret key.
     * @param enckey Output stream receiving the encryption key.
     * @param evalkey Output stream receiving the evaluation key bundle.
     * @return The generated `SecretKey` object.
     */
    SecretKey generateKeys(std::ostream &seckey, std::ostream &enckey, std::ostream &evalkey);

    /**
     * @brief Generates encryption/evaluation keys from an existing secret key.
     * @param seckey Secret key used to derive the public key material.
     * @param enckey Output stream receiving the encryption key.
     * @param evalkey Output stream receiving the evaluation key bundle.
     * @return The provided `SecretKey` object.
     */
    SecretKey generateKeys(SecretKey &seckey, std::ostream &enckey, std::ostream &evalkey);

private:
    std::shared_ptr<detail::MultiKeyGenerator> impl_;
};

/**
 * @brief Creates a `MultiKeyGenerator` instance for distributed secret key generation and sealing.
 *
 * @param contexts List of contexts.
 * @param dir_path Path to the directory where all key files are stored.
 * @param s_info Sealing configuration used to protect the generated secret key.
 * @param seed Optional seed for deterministic key generation.
 * @return A configured `MultiKeyGenerator` instance.
 */
EVI_API MultiKeyGenerator makeMultiKeyGenerator(std::vector<Context> &contexts, const std::string &dir_path,
                                                SealInfo &s_info,
                                                std::optional<std::vector<uint8_t>> seed = std::nullopt);

} // namespace evi
