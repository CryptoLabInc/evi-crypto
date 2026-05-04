#pragma once

#include "nlohmann/json.hpp"

#include <optional>
#include <string>

namespace evi::detail {

// One audit record. All fields that could carry key material are intentionally
// absent — sanitization happens in AuditEmitter before the event is created.
struct AuditEvent {
    // --- Required fields ---
    std::string timestamp;  // ISO 8601 UTC, e.g. "2026-03-16T10:00:00Z"
    std::string event_type; // e.g. "key.wrap", "key.unwrap.fail", "key.aad.fail"
    std::string operation;  // e.g. "wrap", "unwrap", "list", "read", "create", "delete"
    std::string key_id;     // envelope kid; may be empty for stream-based unwrap
    std::string actor;      // requester identity
    std::string outcome;    // "success" | "failure"

    // --- Error info (failure only) ---
    // error_code: stable machine-readable token, e.g. "AAD_VERIFICATION_FAILED"
    // error_message: short human-readable text; must never contain key material
    std::optional<std::string> error_code;
    std::optional<std::string> error_message;

    // --- Context fields ---
    std::optional<std::string> event_id;  // UUID v4 per event
    std::optional<std::string> key_type;  // e.g. "seckey"|"enckey"|"evalkey"|"metadatakey"
    std::optional<std::string> component; // "KeyManager"

    // Serialise to a single-line JSON string (no trailing newline).
    std::string toJson() const {
        nlohmann::json j;
        j["timestamp"] = timestamp;
        j["event_type"] = event_type;
        j["operation"] = operation;
        j["key_id"] = key_id;
        j["actor"] = actor;
        j["outcome"] = outcome;
        if (event_id)
            j["event_id"] = *event_id;
        if (key_type)
            j["key_type"] = *key_type;
        if (component)
            j["component"] = *component;
        if (error_code || error_message) {
            nlohmann::json err;
            if (error_code)
                err["code"] = *error_code;
            if (error_message)
                err["message"] = *error_message;
            j["error"] = std::move(err);
        }
        return j.dump();
    }
};

} // namespace evi::detail
