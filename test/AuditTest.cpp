#include "km/KeyManager.hpp"
#include "km/KeyStorageConfig.hpp"
#include "km/audit/AuditEvent.hpp"
#include "km/audit/AuditStore.hpp"
#include "nlohmann/json.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

// In-memory store that records every appended event.
class CapturingAuditStore : public evi::detail::AuditStore {
public:
    void append(const evi::detail::AuditEvent &event) const override {
        events.push_back(event);
    }
    mutable std::vector<evi::detail::AuditEvent> events;
};

// Read all JSONL lines from a file into a vector of json objects.
std::vector<nlohmann::json> readJsonlFile(const fs::path &path) {
    std::ifstream in(path);
    std::vector<nlohmann::json> result;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            result.push_back(nlohmann::json::parse(line));
        }
    }
    return result;
}

// Tiny stub key material (not cryptographically meaningful).
std::string makeStubKeyData() {
    return std::string(32, '\x42'); // 32 bytes = 0x42
}

} // namespace

// ---------------------------------------------------------------------------
// Unit: AuditStore emit methods
// ---------------------------------------------------------------------------

class AuditStoreEmitTest : public ::testing::Test {
protected:
    std::shared_ptr<CapturingAuditStore> store_ = std::make_shared<CapturingAuditStore>();
};

TEST_F(AuditStoreEmitTest, EmitSuccessFillsRequiredFields) {
    store_->emitSuccess("key.wrap", "wrap", "kid-1", "seckey");

    ASSERT_EQ(store_->events.size(), 1u);
    const auto &ev = store_->events[0];
    EXPECT_EQ(ev.event_type, "key.wrap");
    EXPECT_EQ(ev.operation, "wrap");
    EXPECT_EQ(ev.key_id, "kid-1");
    EXPECT_EQ(ev.outcome, "success");
    EXPECT_EQ(ev.key_type, "seckey");
    EXPECT_EQ(ev.component, "KeyManager");
    EXPECT_FALSE(ev.timestamp.empty());
    EXPECT_TRUE(ev.event_id.has_value());
    EXPECT_FALSE(ev.error_code.has_value());
    EXPECT_FALSE(ev.error_message.has_value());
}

TEST_F(AuditStoreEmitTest, EmitFailureFillsErrorFields) {
    store_->emitFailure("key.unwrap.fail", "unwrap", "kid-2", "enc_key", "UNWRAP_FAILED", "some error message");

    ASSERT_EQ(store_->events.size(), 1u);
    const auto &ev = store_->events[0];
    EXPECT_EQ(ev.event_type, "key.unwrap.fail");
    EXPECT_EQ(ev.outcome, "failure");
    EXPECT_EQ(ev.error_code, "UNWRAP_FAILED");
    EXPECT_EQ(ev.error_message, "Key unwrap failed");
}

TEST_F(AuditStoreEmitTest, LongErrorMessageIsTruncated) {
    const std::string long_msg(512, 'X');
    store_->emitFailure("key.wrap.fail", "wrap", "k", "secret_key", "WRAP_FAILED", long_msg);

    ASSERT_EQ(store_->events.size(), 1u);
    const auto &ev = store_->events[0];
    ASSERT_TRUE(ev.error_message.has_value());
    EXPECT_EQ(ev.error_message, "Key wrap failed");
}

TEST_F(AuditStoreEmitTest, NoopStoreDoesNotCrash) {
    auto &noop = evi::detail::AuditStore::noop();
    EXPECT_NO_THROW(noop.emitSuccess("key.wrap", "wrap", "k", "secret_key"));
    EXPECT_NO_THROW(noop.emitFailure("key.wrap.fail", "wrap", "k", "secret_key", "E", "m"));
}

TEST_F(AuditStoreEmitTest, EventIdIsUniquePerEmit) {
    store_->emitSuccess("key.wrap", "wrap", "k1", "secret_key");
    store_->emitSuccess("key.wrap", "wrap", "k2", "secret_key");
    ASSERT_EQ(store_->events.size(), 2u);
    EXPECT_NE(store_->events[0].event_id, store_->events[1].event_id);
}

// ---------------------------------------------------------------------------
// Unit: AuditStore — append-only invariant
// ---------------------------------------------------------------------------

class AuditStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        tmp_dir_ = fs::temp_directory_path() /
                   ("audit_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        fs::create_directories(tmp_dir_);
        audit_path_ = tmp_dir_ / "audit.jsonl";
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }

    fs::path tmp_dir_;
    fs::path audit_path_;
};

TEST_F(AuditStoreTest, AppendIncreasesLineCount) {
    auto store = evi::detail::makeAuditStore(audit_path_.string());
    store->emitSuccess("key.wrap", "wrap", "kid-1", "secret_key");
    store->emitSuccess("key.unwrap", "unwrap", "kid-1", "secret_key");

    const auto lines = readJsonlFile(audit_path_);
    EXPECT_EQ(lines.size(), 2u);
}

TEST_F(AuditStoreTest, ExistingLinesNotModifiedAfterAppend) {
    auto store = evi::detail::makeAuditStore(audit_path_.string());
    store->emitSuccess("key.wrap", "wrap", "kid-1", "secret_key");
    const auto before = readJsonlFile(audit_path_);
    ASSERT_EQ(before.size(), 1u);
    const std::string first_event_id = before[0].value("event_id", std::string{});

    store->emitSuccess("key.unwrap", "unwrap", "kid-1", "secret_key");
    const auto after = readJsonlFile(audit_path_);
    ASSERT_EQ(after.size(), 2u);

    // First line must be byte-for-byte unchanged.
    EXPECT_EQ(after[0].value("event_id", std::string{}), first_event_id);
    EXPECT_EQ(after[0].value("event_type", std::string{}), "key.wrap");
}

TEST_F(AuditStoreTest, EachLineIsValidJson) {
    auto store = evi::detail::makeAuditStore(audit_path_.string());
    store->emitSuccess("key.wrap", "wrap", "kid-1", "secret_key");
    store->emitFailure("key.unwrap.fail", "unwrap", "kid-1", "secret_key", "UNWRAP_FAILED", "parse error");

    const auto lines = readJsonlFile(audit_path_);
    ASSERT_EQ(lines.size(), 2u);
    // If readJsonlFile didn't throw, all lines are valid JSON.
    EXPECT_EQ(lines[0]["outcome"], "success");
    EXPECT_EQ(lines[1]["outcome"], "failure");
    EXPECT_EQ(lines[1]["error"]["code"], "UNWRAP_FAILED");
}

TEST_F(AuditStoreTest, SecondStoreInstanceAppendsNotTruncates) {
    // Open, write one record, close.
    {
        auto store = evi::detail::makeAuditStore(audit_path_.string());
        store->emitSuccess("key.wrap", "wrap", "kid-1", "secret_key");
    }
    // Open same file again, write another record.
    {
        auto store = evi::detail::makeAuditStore(audit_path_.string());
        store->emitSuccess("key.unwrap", "unwrap", "kid-1", "secret_key");
    }

    const auto lines = readJsonlFile(audit_path_);
    // Both records must be present — the second open must NOT have truncated the file.
    EXPECT_EQ(lines.size(), 2u);
}

// ---------------------------------------------------------------------------
// Integration: KeyManager wrap/unwrap emits correct events
// ---------------------------------------------------------------------------

class KeyManagerAuditTest : public ::testing::Test {
protected:
    void SetUp() override {
        tmp_dir_ = fs::temp_directory_path() /
                   ("km_audit_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        fs::create_directories(tmp_dir_);
        audit_path_ = tmp_dir_ / "audit.jsonl";
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }

    fs::path tmp_dir_;
    fs::path audit_path_;
};

TEST_F(KeyManagerAuditTest, WrapEncKeyEmitsSuccessEvent) {
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));
    km.setAuditStore(audit_path_.string());

    const std::string blob(128, '\x01');
    std::istringstream key_in(blob);
    std::ostringstream out;
    km.wrapEncKey("test-key-id", key_in, out);

    const auto lines = readJsonlFile(audit_path_);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines[0]["event_type"], "key.wrap");
    EXPECT_EQ(lines[0]["operation"], "wrap");
    EXPECT_EQ(lines[0]["key_id"], "test-key-id");
    EXPECT_EQ(lines[0]["key_type"], "enckey");
    EXPECT_EQ(lines[0]["outcome"], "success");
}

TEST_F(KeyManagerAuditTest, UnwrapEncKeyEmitsSuccessEvent) {
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));
    km.setAuditStore(audit_path_.string());

    const std::string blob(128, '\x02');
    std::istringstream key_in(blob);
    std::ostringstream wrapped_out;
    km.wrapEncKey("my-enc-key", key_in, wrapped_out);

    const std::string envelope = wrapped_out.str();
    std::istringstream env_in(envelope);
    std::ostringstream key_out;
    km.unwrapEncKey(env_in, key_out);

    const auto lines = readJsonlFile(audit_path_);
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_EQ(lines[1]["event_type"], "key.unwrap");
    EXPECT_EQ(lines[1]["operation"], "unwrap");
    EXPECT_EQ(lines[1]["key_id"], "my-enc-key");
    EXPECT_EQ(lines[1]["key_type"], "enckey");
    EXPECT_EQ(lines[1]["outcome"], "success");
}

TEST_F(KeyManagerAuditTest, UnwrapWithCorruptEnvelopeDoesNotEmitAuditEvent) {
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));
    km.setAuditStore(audit_path_.string());

    std::istringstream bad_in("{\"not\":\"valid-envelope\"}");
    std::ostringstream out;
    EXPECT_THROW(km.unwrapEncKey(bad_in, out), std::exception);

    const auto lines = readJsonlFile(audit_path_);
    EXPECT_TRUE(lines.empty());
}

TEST_F(KeyManagerAuditTest, AadMismatchEmitsAadFailEvent) {
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));
    km.setAuditStore(audit_path_.string());

    const std::string blob(64, '\xAB');
    std::istringstream key_in(blob);
    std::ostringstream wrapped_out;
    km.wrapEncKey("aad-test-key", key_in, wrapped_out);

    nlohmann::json env = nlohmann::json::parse(wrapped_out.str());
    env["aad"]["value"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    std::istringstream tampered_in(env.dump());
    std::ostringstream key_out;
    EXPECT_THROW(km.unwrapEncKey(tampered_in, key_out), std::exception);

    const auto lines = readJsonlFile(audit_path_);
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_EQ(lines[1]["event_type"], "key.aad.fail");
    EXPECT_EQ(lines[1]["error"]["code"], "AAD_VERIFICATION_FAILED");
}

TEST_F(KeyManagerAuditTest, NoAuditStoreDoesNotThrow) {
    // Default KeyManager has no audit store (null → no-op).
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));

    const std::string blob(64, '\x03');
    std::istringstream key_in(blob);
    std::ostringstream out;
    EXPECT_NO_THROW(km.wrapEncKey("no-audit-key", key_in, out));
}

TEST_F(KeyManagerAuditTest, WrapEmptyKeyIdEmitsFailEvent) {
    auto km = evi::makeKeyManager(evi::KeyStorageConfig::makeLocal(evi::LocalConfig{}));
    km.setAuditStore(audit_path_.string());

    const std::string blob(64, '\x04');
    std::istringstream key_in(blob);
    std::ostringstream out;
    EXPECT_THROW(km.wrapEncKey("", key_in, out), std::exception);

    const auto lines = readJsonlFile(audit_path_);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_EQ(lines[0]["event_type"], "key.wrap.fail");
    EXPECT_EQ(lines[0]["outcome"], "failure");
}
