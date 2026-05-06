// Security.cpp -- Process hardening and secure buffer wiping.

#include "utils/security/Security.hpp"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string.h> // memset_s, explicit_bzero on BSD
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#define EVI_HAVE_EXPLICIT_BZERO __GLIBC_PREREQ(2, 25)
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define EVI_HAVE_EXPLICIT_BZERO 1
#else
#define EVI_HAVE_EXPLICIT_BZERO 0
#endif

namespace evi::security {

std::size_t pageSize() {
#if defined(__linux__) || defined(__APPLE__)
    static const long K_PAGE_SIZE = ::sysconf(_SC_PAGESIZE);
    return K_PAGE_SIZE > 0 ? static_cast<std::size_t>(K_PAGE_SIZE) : 4096U;
#else
    return 4096U;
#endif
}

void setMemoryProtection(void *ptr, std::size_t len, int prot) {
    if (ptr == nullptr || len == 0) {
        return;
    }

#if defined(__linux__) || defined(__APPLE__)
    const std::size_t page_size = pageSize();
    const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
    if ((addr % page_size) != 0U) {
        throw std::runtime_error("mprotect target pointer is not page-aligned");
    }

    if (::mprotect(ptr, len, prot) != 0) {
        throw std::runtime_error("mprotect failed while updating SecretKey memory protection");
    }
#else
    (void)prot;
    throw std::runtime_error("mprotect is not supported on this platform");
#endif
}

void secureZeroMemory(void *ptr, std::size_t size) noexcept {
    if (!ptr || size == 0) {
        return;
    }

#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, size, 0, size);
#elif EVI_HAVE_EXPLICIT_BZERO
    explicit_bzero(ptr, size);
#else
    volatile std::uint8_t *p = static_cast<volatile std::uint8_t *>(ptr);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
#endif
}

void wipeBuffer(std::string &buffer) {
    if (!buffer.empty()) {
        secureZeroMemory(buffer.data(), buffer.size());
        buffer.clear();
    }
}

void wipeBuffer(std::vector<uint8_t> &buffer) {
    if (!buffer.empty()) {
        secureZeroMemory(buffer.data(), buffer.size() * sizeof(uint8_t));
        buffer.clear();
    }
}

SensitiveDataGuard::SensitiveDataGuard(std::string &buffer) : string_buffer_(&buffer), bytes_buffer_(nullptr) {}

SensitiveDataGuard::SensitiveDataGuard(std::vector<uint8_t> &buffer)
    : string_buffer_(nullptr), bytes_buffer_(&buffer) {}

SensitiveDataGuard::~SensitiveDataGuard() {
    if (string_buffer_ != nullptr) {
        wipeBuffer(*string_buffer_);
        return;
    }
    if (bytes_buffer_ != nullptr) {
        wipeBuffer(*bytes_buffer_);
    }
}

#if defined(__linux__) || defined(__APPLE__)
namespace {

void disableCoreDumps() {
    struct rlimit rlim = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rlim) != 0) {
        throw std::runtime_error("setrlimit(RLIMIT_CORE,0) failed");
    }
#ifdef __linux__
    // Best-effort: seccomp/container policy may block prctl.
    (void)prctl(PR_SET_DUMPABLE, 0);
#endif
}

std::once_flag g_core_dump_guard_flag;

} // namespace

__attribute__((constructor)) static void coreDumpGuardCtor() {
    try {
        disableCoreDumps();
    } catch (...) {
    }
}

void ensureCoreDumpGuard() {
    std::call_once(g_core_dump_guard_flag, disableCoreDumps);
}
#else
void ensureCoreDumpGuard() {}
#endif

} // namespace evi::security
