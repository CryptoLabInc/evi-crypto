#include "km/KeyEnvelope.hpp"

#include <cctype>

namespace evi {

namespace {

std::optional<std::string> sanitizeOptionalField(const nlohmann::ordered_json &node, const char *field_name,
                                                 const std::string &owner_name) {
    const auto it = node.find(field_name);
    if (it == node.end() || it->is_null()) {
        return std::nullopt;
    }
    if (!it->is_string()) {
        throw InvalidInputError(owner_name + " state has non-string '" + field_name + "'");
    }
    const std::string value = KeyState::sanitizeReason(it->get<std::string>());
    if (value.empty()) {
        throw InvalidInputError(owner_name + " state has empty '" + field_name + "'");
    }
    return value;
}

} // namespace

std::string toString(KeyLifecycleState state) {
    switch (state) {
    case KeyLifecycleState::Preparing:
        return "preparing";
    case KeyLifecycleState::Active:
        return "active";
    case KeyLifecycleState::Deactivated:
        return "deactivated";
    case KeyLifecycleState::Destroyed:
        return "destroyed";
    }
    throw InvalidInputError("Unknown key lifecycle state");
}

KeyLifecycleState parseKeyLifecycleState(std::string_view value) {
    if (value == "preparing") {
        return KeyLifecycleState::Preparing;
    }
    if (value == "active") {
        return KeyLifecycleState::Active;
    }
    if (value == "deactivated") {
        return KeyLifecycleState::Deactivated;
    }
    if (value == "destroyed") {
        return KeyLifecycleState::Destroyed;
    }
    throw InvalidInputError("Invalid key state '" + std::string(value) +
                            "'; allowed states are: preparing, active, deactivated, destroyed");
}

std::string KeyState::sanitizeReason(const std::string &reason) {
    std::size_t start = 0;
    while (start < reason.size() && std::isspace(static_cast<unsigned char>(reason[start])) != 0) {
        ++start;
    }
    std::size_t end = reason.size();
    while (end > start && std::isspace(static_cast<unsigned char>(reason[end - 1])) != 0) {
        --end;
    }
    return reason.substr(start, end - start);
}

nlohmann::ordered_json KeyState::toJson() const {
    nlohmann::ordered_json node = {
        {"value", evi::toString(value)},
        {"updated_at", updated_at},
    };
    if (reason.has_value()) {
        node["reason"] = *reason;
    } else {
        node["reason"] = nullptr;
    }
    return node;
}

KeyState KeyState::fromJson(const nlohmann::ordered_json &node, const std::string &owner_name) {
    if (!node.is_object()) {
        throw InvalidInputError(owner_name + " is missing 'state' object");
    }

    const auto value_it = node.find("value");
    if (value_it == node.end() || !value_it->is_string()) {
        throw InvalidInputError(owner_name + " state is missing 'value'");
    }
    const std::string value_string = value_it->get<std::string>();
    if (value_string.empty()) {
        throw InvalidInputError(owner_name + " state has empty 'value'");
    }

    KeyState state;
    state.value = evi::parseKeyLifecycleState(value_string);
    state.reason = sanitizeOptionalField(node, "reason", owner_name);

    const auto updated_at_it = node.find("updated_at");
    if (updated_at_it == node.end() || !updated_at_it->is_string()) {
        throw InvalidInputError(owner_name + " state is missing 'updated_at'");
    }
    state.updated_at = updated_at_it->get<std::string>();
    if (state.updated_at.empty()) {
        throw InvalidInputError(owner_name + " state has empty 'updated_at'");
    }

    return state;
}

} // namespace evi
