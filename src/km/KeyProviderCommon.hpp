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
ProviderEntry makeEncapEntry(const std::string &name, const std::string &role, const std::vector<uint8_t> &payload);
nlohmann::ordered_json makeSealedEnvelopeJson(const ProviderEnvelope &encap, const std::string &key_id,
                                              const std::string &usage, const std::string &integrity_context,
                                              bool is_secret, const std::string &key_version = "1");
void writeBinaryStream(std::ostream &stream, const std::vector<uint8_t> &data);
std::vector<uint8_t> decodeEnvelopeKeyData(std::istream &stream,
                                           const std::optional<std::string> &expected_usage = std::nullopt);

} // namespace evi::detail::provider_common
