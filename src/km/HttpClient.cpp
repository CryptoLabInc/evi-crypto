#include "HttpClient.hpp"

#include "utils/Exceptions.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <openssl/ssl.h>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace evi::detail::http {
namespace {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t K_INVALID_SOCKET = INVALID_SOCKET;
inline void closeSocket(socket_t s) {
    ::closesocket(s);
}

struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        (void)WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() {
        WSACleanup();
    }
};
static WinsockInit winsockInit;
#else
using socket_t = int;
constexpr socket_t K_INVALID_SOCKET = -1;
inline void closeSocket(socket_t s) {
    ::close(s);
}
#endif

std::string decodeChunkedBody(const std::string &chunked) {
    std::size_t cursor = 0;
    std::string decoded;
    while (cursor < chunked.size()) {
        const auto line_end = chunked.find("\r\n", cursor);
        if (line_end == std::string::npos) {
            throw evi::InvalidInputError("Invalid chunked HTTP response");
        }
        const std::string size_hex = chunked.substr(cursor, line_end - cursor);
        const std::size_t chunk_size = std::stoul(size_hex, nullptr, 16);
        cursor = line_end + 2;
        if (chunk_size == 0) {
            break;
        }
        if (cursor + chunk_size > chunked.size()) {
            throw evi::InvalidInputError("Truncated chunked HTTP response");
        }
        decoded.append(chunked, cursor, chunk_size);
        cursor += chunk_size + 2;
    }
    return decoded;
}

void sendAllPlain(socket_t sock_fd, const std::string &data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        const auto n = ::send(sock_fd, data.data() + sent, static_cast<int>(data.size() - sent), 0);
        if (n <= 0) {
            throw evi::EncryptionError("Failed to send HTTP request");
        }
        sent += static_cast<std::size_t>(n);
    }
}

std::string recvAllPlain(socket_t sock_fd) {
    std::string out;
    std::array<char, 8192> buffer{};
    while (true) {
        const auto n = ::recv(sock_fd, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            throw evi::EncryptionError("Failed to read HTTP response");
        }
        out.append(buffer.data(), static_cast<std::size_t>(n));
    }
    return out;
}

void sendAllTls(SSL *ssl, const std::string &data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        const int n = SSL_write(ssl, data.data() + sent, static_cast<int>(data.size() - sent));
        if (n <= 0) {
            throw evi::EncryptionError("Failed to send HTTPS request");
        }
        sent += static_cast<std::size_t>(n);
    }
}

std::string recvAllTls(SSL *ssl) {
    std::string out;
    std::array<char, 8192> buffer{};
    while (true) {
        const int n = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        if (n == 0) {
            break;
        }
        if (n < 0) {
            throw evi::EncryptionError("Failed to read HTTPS response");
        }
        out.append(buffer.data(), static_cast<std::size_t>(n));
    }
    return out;
}

} // namespace

ParsedUrl parseUrl(const std::string &url) {
    constexpr const char *K_HTTP = "http://";
    constexpr const char *K_HTTPS = "https://";
    ParsedUrl out;
    std::string rest;
    if (url.rfind(K_HTTPS, 0) == 0) {
        out.https = true;
        rest = url.substr(std::strlen(K_HTTPS));
        out.port = "443";
    } else if (url.rfind(K_HTTP, 0) == 0) {
        out.https = false;
        rest = url.substr(std::strlen(K_HTTP));
        out.port = "80";
    } else {
        throw evi::InvalidInputError("URL must start with http:// or https://: " + url);
    }

    std::string host_port = rest;
    out.target = "/";
    const auto slash_pos = rest.find('/');
    if (slash_pos != std::string::npos) {
        host_port = rest.substr(0, slash_pos);
        out.target = rest.substr(slash_pos);
    }

    out.host = host_port;
    const auto colon_pos = host_port.rfind(':');
    if (colon_pos != std::string::npos) {
        out.host = host_port.substr(0, colon_pos);
        out.port = host_port.substr(colon_pos + 1);
    }

    if (out.host.empty() || out.port.empty()) {
        throw evi::InvalidInputError("Invalid URL: " + url);
    }
    return out;
}

Response call(const std::string &method, const std::string &url,
              const std::vector<std::pair<std::string, std::string>> &headers, const std::optional<std::string> &body,
              bool tls_skip_verify) {
    ParsedUrl parsed = parseUrl(url);

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *results = nullptr;
    if (::getaddrinfo(parsed.host.c_str(), parsed.port.c_str(), &hints, &results) != 0) {
        throw evi::EncryptionError("Failed to resolve host: " + parsed.host);
    }

    socket_t sock_fd = K_INVALID_SOCKET;
    for (auto *ai = results; ai != nullptr; ai = ai->ai_next) {
        sock_fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock_fd == K_INVALID_SOCKET) {
            continue;
        }
        if (::connect(sock_fd, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
            break;
        }
        closeSocket(sock_fd);
        sock_fd = K_INVALID_SOCKET;
    }
    ::freeaddrinfo(results);

    if (sock_fd == K_INVALID_SOCKET) {
        throw evi::EncryptionError("Failed to connect to host " + parsed.host + ":" + parsed.port);
    }

    const std::string request_body = body.value_or("");
    std::ostringstream req;
    req << method << " " << parsed.target << " HTTP/1.1\r\n";
    const bool default_port = (!parsed.https && parsed.port == "80") || (parsed.https && parsed.port == "443");
    req << "Host: " << parsed.host << (default_port ? "" : (":" + parsed.port)) << "\r\n";
    req << "Accept-Encoding: identity\r\n";
    req << "Connection: close\r\n";
    for (const auto &kv : headers) {
        req << kv.first << ": " << kv.second << "\r\n";
    }
    if (!request_body.empty() || method == "PUT" || method == "POST") {
        req << "Content-Length: " << request_body.size() << "\r\n";
    }
    req << "\r\n";
    req << request_body;

    std::string raw_response;
    if (!parsed.https) {
        sendAllPlain(sock_fd, req.str());
        raw_response = recvAllPlain(sock_fd);
        closeSocket(sock_fd);
    } else {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            closeSocket(sock_fd);
            throw evi::EncryptionError("Failed to create TLS context");
        }
        if (tls_skip_verify) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
            (void)SSL_CTX_set_default_verify_paths(ctx);
        }
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            closeSocket(sock_fd);
            throw evi::EncryptionError("Failed to create TLS session");
        }
        (void)SSL_set_tlsext_host_name(ssl, parsed.host.c_str());
        SSL_set_fd(ssl, static_cast<int>(sock_fd));
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            closeSocket(sock_fd);
            throw evi::EncryptionError("TLS connect failed");
        }

        sendAllTls(ssl, req.str());
        raw_response = recvAllTls(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closeSocket(sock_fd);
    }

    const auto header_end = raw_response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        throw evi::InvalidInputError("Invalid HTTP response");
    }
    const std::string header_block = raw_response.substr(0, header_end);
    std::string body_block = raw_response.substr(header_end + 4);

    std::istringstream header_stream(header_block);
    std::string status_line;
    std::getline(header_stream, status_line);
    if (!status_line.empty() && status_line.back() == '\r') {
        status_line.pop_back();
    }

    std::istringstream status_parser(status_line);
    std::string http_version;
    long status_code = 0;
    status_parser >> http_version >> status_code;
    if (status_code <= 0) {
        throw evi::InvalidInputError("Failed to parse HTTP status line: " + status_line);
    }

    std::string lower_headers = header_block;
    std::transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (lower_headers.find("transfer-encoding: chunked") != std::string::npos) {
        body_block = decodeChunkedBody(body_block);
    }

    return Response{status_code, body_block};
}

} // namespace evi::detail::http
