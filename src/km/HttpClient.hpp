#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace evi::detail::http {

struct ParsedUrl {
    bool https{false};
    std::string host;
    std::string port;
    std::string target;
};

struct Response {
    long status_code{0};
    std::string body;
};

ParsedUrl parseUrl(const std::string &url);

Response call(const std::string &method, const std::string &url,
              const std::vector<std::pair<std::string, std::string>> &headers, const std::optional<std::string> &body,
              bool tls_skip_verify);

} // namespace evi::detail::http
