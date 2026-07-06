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
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Sampler.hpp"
#include "utils/span.hpp"

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Encryptor.hpp>

namespace evi {
namespace detail {
class EncryptorInterface {
public:
    virtual ~EncryptorInterface() = default;
    virtual void loadEncKey(const std::string &dir_path) = 0;
    virtual void loadEncKey(std::istream &in) = 0;
    virtual void loadEncKey(const KeyPack &keypack) = 0;

    virtual Query encrypt(const span<float> msg, const EncodeType type = EncodeType::ITEM,
                          const std::optional<uint32_t> level = std::nullopt,
                          std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type = EncodeType::ITEM,
                          const std::optional<uint32_t> level = std::nullopt,
                          std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const MultiSecretKey &seckey, const EncodeType type,
                          const std::optional<uint32_t> level, std::optional<float> scale) = 0;

    virtual Query encrypt(const span<float> msg, const std::string &enckey_path,
                          const EncodeType type = EncodeType::ITEM, const std::optional<uint32_t> level = std::nullopt,
                          std::optional<float> scale = std::nullopt) = 0;
    virtual Query encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type = EncodeType::ITEM,
                          const std::optional<uint32_t> level = std::nullopt,
                          std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type = EncodeType::ITEM,
                          const std::optional<uint32_t> level = std::nullopt,
                          std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg,
                                       const EncodeType type = EncodeType::ITEM,
                                       const std::optional<uint32_t> level = std::nullopt,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                                       const EncodeType type = EncodeType::ITEM,
                                       const std::optional<uint32_t> level = std::nullopt,
                                       std::optional<float> scale = std::nullopt) = 0;
    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                                       const EncodeType type = EncodeType::ITEM,
                                       const std::optional<uint32_t> level = std::nullopt,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const KeyPack &keypack,
                                       const EncodeType type = EncodeType::ITEM,
                                       const std::optional<uint32_t> level = std::nullopt,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<std::string> encryptRow(const std::vector<std::vector<float>> &msg,
                                                const EncodeType type = EncodeType::ITEM,
                                                const std::optional<uint32_t> level = std::nullopt,
                                                std::optional<float> scale = std::nullopt) = 0;

    virtual Query encode(const span<float> msg, const EncodeType type = EncodeType::ITEM,
                         const std::optional<uint32_t> level = std::nullopt,
                         std::optional<float> scale = std::nullopt) = 0;

    virtual Query encode(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::QUERY,
                         const std::optional<uint32_t> level = std::nullopt,
                         std::optional<float> scale = std::nullopt) = 0;

    virtual EvalMode getEvalMode() const = 0;
    virtual const Context &getContext() const = 0;
};

class RandomSampler;

template <EvalMode M>
class EncryptorImpl : public EncryptorInterface {
public:
    explicit EncryptorImpl(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, const KeyPack &keypack,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, const std::string &path,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, std::istream &in,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);

    void loadEncKey(const std::string &dir_path) override;
    void loadEncKey(std::istream &in) override;
    void loadEncKey(const KeyPack &keypack) override;

    Query encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type = EncodeType::ITEM,
                  const std::optional<uint32_t> level = std::nullopt,
                  std::optional<float> scale = std::nullopt) override;
    Query encrypt(const span<float> msg, const MultiSecretKey &seckey, const EncodeType type,
                  const std::optional<uint32_t> level, std::optional<float> scale) override;
    Query encrypt(const span<float> msg, const EncodeType type = EncodeType::ITEM,
                  const std::optional<uint32_t> level = std::nullopt,
                  std::optional<float> scale = std::nullopt) override;
    Query encrypt(const span<float> msg, const std::string &enckey_path, const EncodeType type,
                  const std::optional<uint32_t> level, std::optional<float> scale) override;
    Query encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type,
                  const std::optional<uint32_t> level, std::optional<float> scale) override;
    Query encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type,
                  const std::optional<uint32_t> level, std::optional<float> scale) override;

    // test feature batch encrypt
    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::ITEM,
                               const std::optional<uint32_t> level = std::nullopt,
                               std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                               const EncodeType type = EncodeType::ITEM,
                               const std::optional<uint32_t> level = std::nullopt,
                               std::optional<float> scale = std::nullopt) override;
    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                               const EncodeType type = EncodeType::ITEM,
                               const std::optional<uint32_t> level = std::nullopt,
                               std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const KeyPack &keypack,
                               const EncodeType type = EncodeType::ITEM,
                               const std::optional<uint32_t> level = std::nullopt,
                               std::optional<float> scale = std::nullopt) override;

    std::vector<std::string> encryptRow(const std::vector<std::vector<float>> &msg,
                                        const EncodeType type = EncodeType::ITEM,
                                        const std::optional<uint32_t> level = std::nullopt,
                                        std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encryptMM(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::ITEM,
                                 const std::optional<uint32_t> level = std::nullopt,
                                 std::optional<float> scale = std::nullopt);

    Query encode(const span<float> msg, const EncodeType type, const std::optional<uint32_t> level = std::nullopt,
                 std::optional<float> scale = std::nullopt) override;

    Query encode(const std::vector<std::vector<float>> &msg, const EncodeType type, const std::optional<uint32_t> level,
                 std::optional<float> scale) override;

    EvalMode getEvalMode() const override {
        return context_->getEvalMode();
    }
    const Context &getContext() const override {
        return context_;
    }

    // std::vector<polyvec128> plainQueryForLv0HERS(const span<float> msg, std::optional<float> scale =
    // std::nullopt);

    // std::vector<u64> packingWithModPackKey(KeyPack keys,
    //                                        std::vector<std::shared_ptr<evi::SingleCiphertext>> ciphers);
private:
    Query::SingleQuery innerEncrypt(const span<float> &msg, const uint32_t level, const double scale,
                                    std::optional<const SecretKey> seckey = std::nullopt,
                                    std::optional<bool> ntt = true);
    // Width-generic encrypt core: encrypt the coeff message with deb's u64 or
    // u32 encryptor (U), then return the (always u64) SingleBlock carrier
    // (widening the limbs when U=u32). innerEncrypt picks U via
    // utils::isU32NativePreset.
    template <typename U>
    Query::SingleQuery innerEncryptT(const deb::CoeffMessage &deb_msg, const uint32_t level, const double scale,
                                     const bool ntt_val, const std::optional<const SecretKey> &seckey);
    // Encrypt-into-buffers core: writes the ciphertext limbs (width U) directly
    // into caller-owned a_q/b_q[/a_p/b_p]. No SingleBlock, no widen — callers
    // that want u32-native storage (encryptMM typed Matrix, encryptRow packed
    // row) use this to avoid the u32->u64->u32 round-trip. a_p/b_p ignored when
    // level==0. innerEncryptT wraps this and builds the u64 SingleBlock carrier.
    template <typename U>
    void innerEncryptInto(const deb::CoeffMessage &deb_msg, const uint32_t level, const double scale,
                          const bool ntt_val, const std::optional<const SecretKey> &seckey, U *a_q, U *b_q, U *a_p,
                          U *b_p);
    Query::SingleQuery innerEncode(const span<float> &msg, const uint32_t level, const double scale,
                                   std::optional<const u64> msg_size = std::nullopt, std::optional<bool> ntt = true);

    const Context context_;
    RandomSampler sampler_;
    // u64 encrypt engine, constructed only for non-u32-native presets. IP3
    // (u32-native) always encrypts via deb_encryptor32_, so the u64 engine's
    // NTT precompute is never built there.
    std::optional<deb::Encryptor> deb_encryptor_;
    FixedKeyType encKey_;
    deb::SwitchKey deb_enc_key_;

    // u32-native encrypt path for IP3 (preset primes < 2^32). Lazily built so
    // non-IP3 presets (IP0/IP1 primes > 2^32) never construct a u32 modulus.
    // deb_enc_key32_ is the u32 enc key narrowed from the loaded u64 enc key
    // (lossless for IP3); see ensureU32Enc().
    std::optional<deb::Encryptor32> deb_encryptor32_;
    std::optional<deb::SwitchKey32> deb_enc_key32_;
    // Lazily construct the u32-native encryptor and narrow the u32 enc key from
    // the loaded u64 enc key (idempotent). Only the IP3 u32 path calls this.
    void ensureU32EncResources();
    // Construct the u64 encrypt engine unless the preset is u32-native (IP3),
    // which never uses it. Called from every constructor.
    void buildU64EncryptorIfNeeded(const std::optional<std::vector<u8>> &seed);

    VariadicKeyType switch_key_;
    bool enc_loaded_ = false;
};

class Encryptor : public std::shared_ptr<EncryptorInterface> {
public:
    Encryptor(std::shared_ptr<EncryptorInterface> impl) : std::shared_ptr<EncryptorInterface>(std::move(impl)) {}
};

Encryptor makeEncryptor(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, const KeyPack &keypack,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, const std::string &path,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, std::istream &in,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
} // namespace detail
} // namespace evi
