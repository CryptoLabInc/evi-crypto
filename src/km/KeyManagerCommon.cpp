#include "km/impl/KeyManagerCommon.hpp"

#include "utils/Exceptions.hpp"

#include <sstream>

namespace evi::detail::common {

constexpr char K_VERSION_RECORD_SUFFIX[] = "/metadata/SecKey.json";

// Version record paths are already metadata-only JSON blobs, not key envelopes.
// This suffix mirrors envector-kms metadata storage layout, so any convention
// change must update this check as well.
bool isVersionRecordPath(const std::string &storage_key_path) {
    const std::size_t suffix_len = sizeof(K_VERSION_RECORD_SUFFIX) - 1;
    if (storage_key_path.size() < suffix_len) {
        return false;
    }
    return storage_key_path.compare(storage_key_path.size() - suffix_len, suffix_len, K_VERSION_RECORD_SUFFIX) == 0;
}

std::string readStreamToString(std::istream &stream, const std::string &content) {
    std::ostringstream buffer(std::ios::binary);
    buffer << stream.rdbuf();
    if (stream.bad()) {
        throw evi::InvalidInputError("Failed to read " + content + " from stream");
    }
    return buffer.str();
}

} // namespace evi::detail::common
