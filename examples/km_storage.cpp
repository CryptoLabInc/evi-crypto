#include "CLI/CLI.hpp"
#include "EVI/EVI.hpp"
#include "km/KeyManager.hpp"
#include "km/KeyStorageConfig.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

static void printBanner(const std::string &title) {
    std::cout << "==============================\n";
    std::cout << " " << title << "\n";
    std::cout << "==============================\n";
}

static std::vector<uint8_t> readKekFile(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::invalid_argument("Failed to open KEK file: " + path);
    }
    std::vector<uint8_t> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (key.size() != evi::AES256_KEY_SIZE) {
        throw std::invalid_argument("KEK file must contain exactly 32 bytes: " + path);
    }
    return key;
}

struct ProviderOpts {
    std::string provider = "local";

    // hash corp vault
    std::string vault_addr = "http://127.0.0.1:8200";
    std::string vault_kv_mount = "secret";
    std::string vault_namespace;
    bool vault_tls_skip_verify = false;

    // aws
    std::string aws_region;
    std::string aws_bucket;
    std::string aws_endpoint;
    bool aws_force_path_style = false;
    bool aws_tls_skip_verify = false;
    std::string aws_access_key_env = "AWS_ACCESS_KEY_ID";
    std::string aws_secret_key_env = "AWS_SECRET_ACCESS_KEY";
    std::string aws_session_token_env = "AWS_SESSION_TOKEN";

    // gcp
    std::string gcp_bucket;
    std::string gcp_endpoint = "https://storage.googleapis.com";
    bool gcp_tls_skip_verify = false;
    std::string gcp_oauth_token_env = "GCP_OAUTH_TOKEN";
};

static evi::KeyStorageConfig makeStorageConfig(const ProviderOpts &o) {
    if (o.provider == "local") {
        return evi::KeyStorageConfig::makeLocal(evi::LocalConfig{});
    }
    if (o.provider == "vault") {
        return evi::KeyStorageConfig::fromConfig("vault", {
                                                              {"address", o.vault_addr},
                                                              {"kv_mount", o.vault_kv_mount},
                                                              {"namespace", o.vault_namespace},
                                                              {"tls_skip_verify", o.vault_tls_skip_verify ? "1" : "0"},
                                                          });
    }
    if (o.provider == "aws") {
        return evi::KeyStorageConfig::fromConfig("aws", {
                                                            {"region", o.aws_region},
                                                            {"bucket_name", o.aws_bucket},
                                                            {"endpoint", o.aws_endpoint},
                                                            {"force_path_style", o.aws_force_path_style ? "1" : "0"},
                                                            {"tls_skip_verify", o.aws_tls_skip_verify ? "1" : "0"},
                                                            {"access_key_env", o.aws_access_key_env},
                                                            {"secret_key_env", o.aws_secret_key_env},
                                                            {"session_token_env", o.aws_session_token_env},
                                                        });
    }
    if (o.provider == "gcp") {
        return evi::KeyStorageConfig::fromConfig("gcp", {
                                                            {"bucket_name", o.gcp_bucket},
                                                            {"oauth_token_env", o.gcp_oauth_token_env},
                                                            {"endpoint", o.gcp_endpoint},
                                                            {"tls_skip_verify", o.gcp_tls_skip_verify ? "1" : "0"},
                                                        });
    }
    throw std::invalid_argument("Unknown provider: " + o.provider + " (expected: local|vault|aws|gcp)");
}

static void ensureParentDir(const fs::path &p) {
    if (p.has_parent_path()) {
        fs::create_directories(p.parent_path());
    }
}

static const char *k_quick_examples = R"(Quick examples

  HashCorp Vault (KV v2)
    export VAULT_TOKEN=...; export VAULT_ADDR=http://127.0.0.1:8200
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo put --dir keys
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo list
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo get --out-dir /tmp/demo_keys
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo rotate --old-kek-file old.kek --new-kek-file new.kek
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo deactivate --reason "rotation complete"
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo destroy --reason "retention expired"
    ./build/examples/km_storage --provider vault --vault-addr "$VAULT_ADDR" --key-id demo delete

  AWS S3 (requires AWS SDK enabled at build time)
    export AWS_ACCESS_KEY_ID=...; export AWS_SECRET_ACCESS_KEY=...; export AWS_REGION=ap-northeast-2
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo put --dir keys
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo list
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo get --out-dir /tmp/demo_keys
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo rotate --old-kek-file old.kek --new-kek-file new.kek
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo deactivate --reason "rotation complete"
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo destroy --reason "retention expired"
    ./build/examples/km_storage --provider aws --aws-region "$AWS_REGION" --aws-bucket YOUR_BUCKET --key-id demo delete

  GCP GCS (requires google-cloud-cpp enabled at build time)
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo put --dir keys
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo list
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo get --out-dir /tmp/demo_keys
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo rotate --old-kek-file old.kek --new-kek-file new.kek
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo deactivate --reason "rotation complete"
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo destroy --reason "retention expired"
    ./build/examples/km_storage --provider gcp --gcp-bucket YOUR_BUCKET --key-id demo delete
)";

} // namespace

int main(int argc, char **argv) {
    CLI::App app{"KeyStorageConfig example (Vault/AWS/GCP) - wrap + CRUD"};
    app.footer(k_quick_examples);

    ProviderOpts opts;
    app.add_option("--provider", opts.provider, "Storage provider: local|vault|aws|gcp")->default_val("local");

    // Vault options
    app.add_option("--vault-addr", opts.vault_addr, "Vault address (http://...)")->default_val(opts.vault_addr);
    app.add_option("--vault-kv-mount", opts.vault_kv_mount, "Vault KV v2 mount")->default_val(opts.vault_kv_mount);
    app.add_option("--vault-namespace", opts.vault_namespace, "Vault namespace header value")->default_val("");
    app.add_flag("--vault-tls-skip-verify", opts.vault_tls_skip_verify, "Skip TLS verify (Vault)");

    // AWS options
    app.add_option("--aws-region", opts.aws_region, "AWS region (e.g., ap-northeast-2)");
    app.add_option("--aws-bucket", opts.aws_bucket, "S3 bucket name");
    app.add_option("--aws-endpoint", opts.aws_endpoint, "Optional S3 endpoint override (for minio/localstack)");
    app.add_flag("--aws-force-path-style", opts.aws_force_path_style, "Use path-style addressing");
    app.add_flag("--aws-tls-skip-verify", opts.aws_tls_skip_verify, "Skip TLS verify (S3)");
    app.add_option("--aws-access-key-env", opts.aws_access_key_env, "Access key env var name")
        ->default_val(opts.aws_access_key_env);
    app.add_option("--aws-secret-key-env", opts.aws_secret_key_env, "Secret key env var name")
        ->default_val(opts.aws_secret_key_env);
    app.add_option("--aws-session-token-env", opts.aws_session_token_env, "Session token env var name")
        ->default_val(opts.aws_session_token_env);

    // GCP options
    app.add_option("--gcp-bucket", opts.gcp_bucket, "GCS bucket name");
    app.add_option("--gcp-endpoint", opts.gcp_endpoint, "GCS API endpoint")->default_val(opts.gcp_endpoint);
    app.add_flag("--gcp-tls-skip-verify", opts.gcp_tls_skip_verify, "Skip TLS verify (GCS)");
    app.add_option("--gcp-oauth-token-env", opts.gcp_oauth_token_env, "OAuth token env var name (HTTP impl only)")
        ->default_val(opts.gcp_oauth_token_env);

    // Common options
    std::string key_id;
    app.add_option("--key-id", key_id, "Key ID (used for wrap-all and default storage_key_path)");

    auto cmd_wrap_all = app.add_subcommand("wrap-all", "Wrap Sec/Enc/Eval keys (expects *Key.bin under --dir)");
    std::string dir = "keys";
    cmd_wrap_all->add_option("--dir", dir, "Directory containing SecKey.bin/EncKey.bin/EvalKey.bin")
        ->default_val("keys");
    bool cleanup = false;
    cmd_wrap_all->add_flag("--cleanup", cleanup, "Remove existing *.json before writing");

    auto cmd_list = app.add_subcommand("list", "List stored key paths (Vault/S3/GCS only)");
    std::string list_prefix;
    cmd_list->add_option("--prefix", list_prefix, "Optional prefix filter")->default_val("");
    auto cmd_list_versions =
        app.add_subcommand("list-versions", "List version records for the stored secret-key envelope");

    auto cmd_get = app.add_subcommand("get", "Download Sec/Enc/Eval envelope JSON files as a set");
    std::string out_dir = "keys";
    cmd_get->add_option("--out-dir", out_dir, "Output directory for SecKey.json/EncKey.json/EvalKey.json")
        ->default_val("keys");

    auto cmd_rotate = app.add_subcommand("rotate", "Rotate the stored secret-key envelope from old KEK to new KEK");
    std::string old_kek_file;
    std::string new_kek_file;
    cmd_rotate->add_option("--old-kek-file", old_kek_file, "Path to current AES-256 KEK file (32 bytes)")->required();
    cmd_rotate->add_option("--new-kek-file", new_kek_file, "Path to new AES-256 KEK file (32 bytes)")->required();

    auto cmd_put = app.add_subcommand("put", "Upload Sec/Enc/Eval envelopes as a set");
    std::string put_dir = "keys";
    cmd_put->add_option("--dir", put_dir, "Directory containing SecKey.json/EncKey.json/EvalKey.json")
        ->default_val("keys");

    auto cmd_deactivate =
        app.add_subcommand("deactivate", "Transition stored envelopes to the deactivated lifecycle state");
    std::string deactivate_reason = "manual deactivate";
    cmd_deactivate->add_option("--reason", deactivate_reason, "Reason recorded in the key lifecycle state")
        ->default_val(deactivate_reason);

    auto cmd_destroy = app.add_subcommand("destroy", "Transition stored envelopes to the destroyed lifecycle state");
    std::string destroy_reason = "manual destroy";
    cmd_destroy->add_option("--reason", destroy_reason, "Reason recorded in the key lifecycle state")
        ->default_val(destroy_reason);

    auto cmd_del = app.add_subcommand("delete", "Permanently delete Sec/Enc/Eval envelopes as a set");

    CLI11_PARSE(app, argc, argv);

    try {
        const evi::KeyStorageConfig storage_config = makeStorageConfig(opts);
        evi::KeyManager km = evi::makeKeyManager(storage_config);

        if (*cmd_wrap_all) {
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for wrap-all");
            }
            const fs::path base = dir;
            const fs::path sec_bin_path = base / "SecKey.bin";
            const fs::path enc_bin_path = base / "EncKey.bin";
            const fs::path eval_bin_path = base / "EvalKey.bin";
            const fs::path sec_json_path = base / "SecKey.json";
            const fs::path enc_json_path = base / "EncKey.json";
            const fs::path eval_json_path = base / "EvalKey.json";

            if (!fs::exists(sec_bin_path) || !fs::exists(enc_bin_path) || !fs::exists(eval_bin_path)) {
                throw std::runtime_error("Missing SecKey.bin/EncKey.bin/EvalKey.bin in: " + base.string());
            }

            if (cleanup) {
                fs::remove(sec_json_path);
                fs::remove(enc_json_path);
                fs::remove(eval_json_path);
            }

            printBanner("WRAP-ALL");
            km.wrapSecKey(key_id, sec_bin_path.string(), sec_json_path.string());
            km.wrapEncKey(key_id, enc_bin_path.string(), enc_json_path.string());
            km.wrapEvalKey(key_id, eval_bin_path.string(), eval_json_path.string());
            std::cout << "Wrote envelopes under: " << base.string() << "\n";
            return 0;
        }

        if (*cmd_list) {
            printBanner("LIST");
            const std::vector<std::string> keys = km.listKeys(list_prefix);
            for (const auto &k : keys) {
                std::cout << k << "\n";
            }
            return 0;
        }

        if (*cmd_list_versions) {
            printBanner("LIST-VERSIONS");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for list-versions");
            }
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            std::string sec_key = sec_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
            }
            const std::vector<std::string> versions = km.listVersions(sec_key);
            for (const auto &row : versions) {
                std::cout << row << "\n";
            }
            return 0;
        }

        if (*cmd_get) {
            printBanner("GET");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for get");
            }
            const fs::path base = out_dir;
            fs::create_directories(base);
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            const std::string enc_storage_key_path = key_id + "/EncKey.json";
            const std::string eval_storage_key_path = key_id + "/EvalKey.json";
            std::string sec_key = sec_storage_key_path;
            std::string enc_key = enc_storage_key_path;
            std::string eval_key = eval_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
                std::replace(enc_key.begin(), enc_key.end(), '/', '-');
                std::replace(eval_key.begin(), eval_key.end(), '/', '-');
            }
            const fs::path sec_out_path = base / "SecKey.json";
            const fs::path enc_out_path = base / "EncKey.json";
            const fs::path eval_out_path = base / "EvalKey.json";

            std::ofstream sec_out(sec_out_path, std::ios::binary);
            km.getSecKey(sec_key, sec_out);
            std::cout << "Wrote envelope: " << sec_out_path.string() << "\n";
            if (opts.provider != "vault") {
                std::ofstream enc_out(enc_out_path, std::ios::binary);
                km.getPubKey(enc_key, enc_out);
                std::cout << "Wrote envelope: " << enc_out_path.string() << "\n";

                std::ofstream eval_out(eval_out_path, std::ios::binary);
                km.getPubKey(eval_key, eval_out);
                std::cout << "Wrote envelope: " << eval_out_path.string() << "\n";
            } else {
                std::cout << "Skipped EncKey/EvalKey remote GET for Vault provider\n";
            }
            return 0;
        }

        if (*cmd_rotate) {
            printBanner("ROTATE");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for rotate");
            }
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            std::string sec_key = sec_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
            }

            const evi::SealInfo old_seal_info(evi::SealMode::AES_KEK, readKekFile(old_kek_file));
            const evi::SealInfo new_seal_info(evi::SealMode::AES_KEK, readKekFile(new_kek_file));
            km.rotateSecKey(sec_key, old_seal_info, new_seal_info);
            std::cout << "Rotated: " << sec_key << "\n";
            return 0;
        }

        if (*cmd_put) {
            printBanner("PUT");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for put");
            }
            const fs::path base = put_dir;
            const fs::path sec_path = base / "SecKey.json";
            const fs::path enc_path = base / "EncKey.json";
            const fs::path eval_path = base / "EvalKey.json";
            if (!fs::exists(sec_path)) {
                throw std::runtime_error("Missing envelope file: " + sec_path.string());
            }
            if (!fs::exists(enc_path)) {
                throw std::runtime_error("Missing envelope file: " + enc_path.string());
            }
            if (!fs::exists(eval_path)) {
                throw std::runtime_error("Missing envelope file: " + eval_path.string());
            }

            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            const std::string enc_storage_key_path = key_id + "/EncKey.json";
            const std::string eval_storage_key_path = key_id + "/EvalKey.json";
            std::string sec_key = sec_storage_key_path;
            std::string enc_key = enc_storage_key_path;
            std::string eval_key = eval_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
                std::replace(enc_key.begin(), enc_key.end(), '/', '-');
                std::replace(eval_key.begin(), eval_key.end(), '/', '-');
            }

            std::ifstream sec_in(sec_path, std::ios::binary);
            km.putSecKey(sec_key, sec_in);
            std::cout << "Uploaded: " << sec_key << "\n";
            if (opts.provider != "vault") {
                std::ifstream enc_in(enc_path, std::ios::binary);
                km.putPubKey(enc_key, enc_in);
                std::cout << "Uploaded: " << enc_key << "\n";
                std::ifstream eval_in(eval_path, std::ios::binary);
                km.putPubKey(eval_key, eval_in);
                std::cout << "Uploaded: " << eval_key << "\n";
            } else {
                std::cout << "Skipped EncKey/EvalKey remote PUT for Vault provider\n";
            }
            return 0;
        }

        if (*cmd_deactivate) {
            printBanner("DEACTIVATE");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for deactivate");
            }
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            const std::string enc_storage_key_path = key_id + "/EncKey.json";
            const std::string eval_storage_key_path = key_id + "/EvalKey.json";
            std::string sec_key = sec_storage_key_path;
            std::string enc_key = enc_storage_key_path;
            std::string eval_key = eval_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
                std::replace(enc_key.begin(), enc_key.end(), '/', '-');
                std::replace(eval_key.begin(), eval_key.end(), '/', '-');
            }

            km.deactivateSecKey(sec_key, deactivate_reason);
            std::cout << "Deactivated: " << sec_key << "\n";
            if (opts.provider != "vault") {
                km.deactivatePubKey(enc_key, deactivate_reason);
                std::cout << "Deactivated: " << enc_key << "\n";
                km.deactivatePubKey(eval_key, deactivate_reason);
                std::cout << "Deactivated: " << eval_key << "\n";
            } else {
                std::cout << "Skipped EncKey/EvalKey remote DEACTIVATE for Vault provider\n";
            }
            return 0;
        }

        if (*cmd_destroy) {
            printBanner("DESTROY");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for destroy");
            }
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            const std::string enc_storage_key_path = key_id + "/EncKey.json";
            const std::string eval_storage_key_path = key_id + "/EvalKey.json";
            std::string sec_key = sec_storage_key_path;
            std::string enc_key = enc_storage_key_path;
            std::string eval_key = eval_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
                std::replace(enc_key.begin(), enc_key.end(), '/', '-');
                std::replace(eval_key.begin(), eval_key.end(), '/', '-');
            }

            km.destroySecKey(sec_key, destroy_reason);
            std::cout << "Destroyed: " << sec_key << "\n";
            if (opts.provider != "vault") {
                km.destroyPubKey(enc_key, destroy_reason);
                std::cout << "Destroyed: " << enc_key << "\n";
                km.destroyPubKey(eval_key, destroy_reason);
                std::cout << "Destroyed: " << eval_key << "\n";
            } else {
                std::cout << "Skipped EncKey/EvalKey remote DESTROY for Vault provider\n";
            }
            return 0;
        }

        if (*cmd_del) {
            printBanner("DELETE");
            if (key_id.empty()) {
                throw std::invalid_argument("--key-id is required for delete");
            }
            const std::string sec_storage_key_path = key_id + "/SecKey.json";
            const std::string enc_storage_key_path = key_id + "/EncKey.json";
            const std::string eval_storage_key_path = key_id + "/EvalKey.json";
            std::string sec_key = sec_storage_key_path;
            std::string enc_key = enc_storage_key_path;
            std::string eval_key = eval_storage_key_path;
            if (opts.provider == "gcp") {
                std::replace(sec_key.begin(), sec_key.end(), '/', '-');
                std::replace(enc_key.begin(), enc_key.end(), '/', '-');
                std::replace(eval_key.begin(), eval_key.end(), '/', '-');
            }

            km.deleteSecKey(sec_key);
            std::cout << "Deleted: " << sec_key << "\n";
            if (opts.provider != "vault") {
                km.deletePubKey(enc_key);
                std::cout << "Deleted: " << enc_key << "\n";
                km.deletePubKey(eval_key);
                std::cout << "Deleted: " << eval_key << "\n";
            } else {
                std::cout << "Skipped EncKey/EvalKey remote DELETE for Vault provider\n";
            }
            return 0;
        }

        std::cerr << "No command specified. Use --help.\n";
        return 2;
    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
