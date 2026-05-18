#pragma once

#include "km/KeyEnvelope.hpp"

#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace evi::detail::provider_common {

std::vector<uint8_t> readBinaryStream(std::istream &stream);
std::vector<uint8_t> computeSha256(const std::vector<uint8_t> &data);
ProviderEntry makeProviderEntryFromPayload(const std::string &name, const std::string &role,
                                           const std::vector<uint8_t> &payload);
nlohmann::ordered_json makeSealedEnvelopeJson(const ProviderEnvelope &encap, const std::string &key_id,
                                              const std::string &usage, const std::string &integrity_context,
                                              bool is_secret, const std::string &key_version = "1");
void writeEncKeyEnvelopeJsonFromStream(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                       const std::string &key_version = "1");
void writeEvalKeyEnvelopeJsonFromStream(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                        const std::string &key_version = "1");
void writeBinaryStream(std::ostream &stream, const std::vector<uint8_t> &data);
// Use for small sensitive payloads such as SecKey and MetadataKey that need in-memory handling.
std::vector<uint8_t> decodeEnvelopeKeyDataToVector(std::istream &stream,
                                                   const std::optional<std::string> &expected_usage = std::nullopt);
// Use for large payloads such as EncKey and EvalKey to avoid materializing key data in memory.
void decodeEnvelopeKeyDataToStream(std::istream &stream, std::ostream &out_stream,
                                   const std::optional<std::string> &expected_usage = std::nullopt,
                                   std::string *key_id = nullptr);

} // namespace evi::detail::provider_common
