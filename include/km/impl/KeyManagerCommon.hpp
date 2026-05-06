#pragma once

#include <istream>
#include <string>

namespace evi::detail::common {

bool isVersionRecordPath(const std::string &storage_key_path);
std::string readStreamToString(std::istream &stream, const std::string &content);

} // namespace evi::detail::common
