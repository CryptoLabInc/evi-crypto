#include "km/audit/AuditStore.hpp"
#include "utils/Utils.hpp"

#include <cerrno>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace evi::detail {

namespace {

std::string generateEventId() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t hi = dist(rng);
    uint64_t lo = dist(rng);
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << (hi >> 32) << '-';
    oss << std::setw(4) << ((hi >> 16) & 0xFFFF) << '-';
    oss << std::setw(4) << (hi & 0xFFFF) << '-';
    oss << std::setw(4) << (lo >> 48) << '-';
    oss << std::setw(12) << (lo & 0x0000FFFFFFFFFFFFULL);
    return oss.str();
}

constexpr std::size_t K_MAX_MESSAGE_LEN = 256;
constexpr const char *K_DEFAULT_ACTOR = "system";

std::string summarizeErrorMessage(const std::string &error_code, const std::string &error_message) {
    if (error_code == "AAD_VERIFICATION_FAILED") {
        return "AAD verification failed";
    }
    if (error_code == "INTEGRITY_CHECK_FAILED") {
        return "Envelope integrity check failed";
    }
    if (error_code == "KEY_EXPIRED") {
        return "Key is expired";
    }
    if (error_code == "USAGE_MISMATCH") {
        return "Key usage does not match the requested operation";
    }
    if (error_code == "KEY_NOT_ACTIVE") {
        return "Key is not active";
    }
    if (error_code == "WRAP_FAILED") {
        return "Key wrap failed";
    }
    if (error_code == "UNWRAP_FAILED") {
        return "Key unwrap failed";
    }

    if (error_message.empty()) {
        return "Operation failed";
    }

    return error_message.size() <= K_MAX_MESSAGE_LEN ? error_message : "Operation failed";
}

} // namespace

AuditStore::AuditStore(const std::string &file_path) {
#ifdef _WIN32
    fd_ = _sopen(file_path.c_str(), _O_WRONLY | _O_CREAT | _O_APPEND | _O_TEXT, _SH_DENYNO, _S_IREAD | _S_IWRITE);
#else
    // O_APPEND: kernel moves the write position to EOF atomically on every
    fd_ = ::open(file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0640);
#endif
    if (fd_ < 0) {
        throw std::runtime_error("AuditStore: cannot open '" + file_path + "'");
    }
}

AuditStore::~AuditStore() {
    if (fd_ >= 0) {
#ifdef _WIN32
        _close(fd_);
#else
        ::close(fd_);
#endif
    }
}

AuditStore &AuditStore::noop() {
    static AuditStore instance; // fd_ == -1
    return instance;
}

AuditEvent AuditStore::makeBaseEvent(const std::string &event_type, const std::string &operation,
                                     const std::string &key_id, const std::string &key_type,
                                     const std::string &outcome) const {
    AuditEvent ev;
    ev.timestamp = evi::detail::utils::timePointToIso8601UtcString(std::chrono::system_clock::now());
    ev.event_type = event_type;
    ev.operation = operation;
    ev.key_id = key_id;
    ev.actor = K_DEFAULT_ACTOR;
    ev.outcome = outcome;
    ev.event_id = generateEventId();
    ev.component = "KeyManager";
    if (!key_type.empty()) {
        ev.key_type = key_type;
    }
    return ev;
}

void AuditStore::emitSuccess(const std::string &event_type, const std::string &operation, const std::string &key_id,
                             const std::string &key_type) const {
    append(makeBaseEvent(event_type, operation, key_id, key_type, "success"));
}

void AuditStore::emitFailure(const std::string &event_type, const std::string &operation, const std::string &key_id,
                             const std::string &key_type, const std::string &error_code,
                             const std::string &error_message) const {
    AuditEvent ev = makeBaseEvent(event_type, operation, key_id, key_type, "failure");
    if (!error_code.empty()) {
        ev.error_code = error_code;
    }
    const std::string sanitized_message = summarizeErrorMessage(error_code, error_message);
    if (!sanitized_message.empty()) {
        ev.error_message = sanitized_message;
    }
    append(ev);
}

// Thread-safe: mutex serialises concurrent appends so lines are never
// interleaved across threads. fd_ == -1 (noop) returns immediately.
void AuditStore::append(const AuditEvent &event) const {
    if (fd_ < 0) {
        return;
    }
    const std::string line = event.toJson() + "\n";
    std::lock_guard<std::mutex> lock(mutex_);
#ifdef _WIN32
    const int written = _write(fd_, line.data(), static_cast<unsigned int>(line.size()));
    if (written < 0 || static_cast<std::size_t>(written) != line.size()) {
        throw std::runtime_error("AuditStore: failed to append event");
    }
#else
    const char *buf = line.data();
    std::size_t remaining = line.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd_, buf, remaining);
        if (written <= 0) {
            throw std::runtime_error("AuditStore: failed to append event");
        }
        buf += written;
        remaining -= static_cast<std::size_t>(written);
    }
#endif
}

std::shared_ptr<AuditStore> makeAuditStore(const std::string &file_path) {
    return std::make_shared<AuditStore>(file_path);
}

} // namespace evi::detail
