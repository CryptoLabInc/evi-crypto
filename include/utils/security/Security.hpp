#pragma once

#include "EVI/Export.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace evi {
namespace security {

EVI_API void wipeBuffer(std::string &buffer);
EVI_API void wipeBuffer(std::vector<uint8_t> &buffer);

/// Disable core dumps for the current process.
/// Thread-safe (std::call_once internally). Idempotent after first call.
/// On Linux/macOS: sets RLIMIT_CORE to 0, prctl(PR_SET_DUMPABLE, 0) on Linux.
void ensureCoreDumpGuard();
std::size_t pageSize();
void setMemoryProtection(void *ptr, std::size_t len, int prot);
void secureZeroMemory(void *ptr, std::size_t size) noexcept;

class EVI_API SensitiveDataGuard {
public:
    explicit SensitiveDataGuard(std::string &buffer);
    explicit SensitiveDataGuard(std::vector<uint8_t> &buffer);
    ~SensitiveDataGuard();

    SensitiveDataGuard(const SensitiveDataGuard &) = delete;
    SensitiveDataGuard &operator=(const SensitiveDataGuard &) = delete;

private:
    std::string *string_buffer_;
    std::vector<uint8_t> *bytes_buffer_;
};

} // namespace security
} // namespace evi
