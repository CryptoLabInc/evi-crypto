#pragma once

#include "AuditEvent.hpp"

#include <memory>
#include <mutex>
#include <string>

namespace evi::detail {

// Append-only JSONL file sink that also owns the event-building logic.
//
// Opened with O_WRONLY | O_CREAT | O_APPEND — never truncated.
// Throws std::runtime_error from the constructor if the file cannot be opened.
//
// append() is virtual so tests can subclass without a real file.
// Use AuditStore::noop() when no file path is needed (e.g. auditing disabled).
class AuditStore {
public:
    explicit AuditStore(const std::string &file_path);
    virtual ~AuditStore();

    AuditStore(const AuditStore &) = delete;
    AuditStore &operator=(const AuditStore &) = delete;

    static AuditStore &noop();

    void emitSuccess(const std::string &event_type, const std::string &operation, const std::string &key_id,
                     const std::string &key_type) const;

    void emitFailure(const std::string &event_type, const std::string &operation, const std::string &key_id,
                     const std::string &key_type, const std::string &error_code,
                     const std::string &error_message) const;

    virtual void append(const AuditEvent &event) const;

protected:
    AuditStore() = default;

private:
    AuditEvent makeBaseEvent(const std::string &event_type, const std::string &operation, const std::string &key_id,
                             const std::string &key_type, const std::string &outcome) const;

    int fd_{-1};
    mutable std::mutex mutex_;
};

std::shared_ptr<AuditStore> makeAuditStore(const std::string &file_path);

} // namespace evi::detail
