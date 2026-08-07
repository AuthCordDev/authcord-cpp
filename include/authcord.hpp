#pragma once

/**
 * AuthCord C++ SDK - Single-header library
 *
 * Requirements:
 *   - C++17 compiler
 *   - libcurl (https://curl.se/libcurl/)
 *   - nlohmann/json (https://github.com/nlohmann/json)
 *
 * Usage:
 *   #include "authcord.hpp"
 *
 *   authcord::AuthCordClient client("dax_your_api_key");
 *   auto result = client.validate("your_app_id", "123456789");
 */

#include <string>
#include <vector>
#include <optional>
#include <map>
#include <stdexcept>
#include <sstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <functional>
#include <memory>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <sddl.h>     // ConvertSidToStringSidA
  #include <intrin.h>   // __cpuid
  // Link Advapi32.lib for SID and registry APIs. Most build systems
  // pick this up automatically with MSVC's pragma; MinGW/Clang users
  // may need -lAdvapi32 on the link line.
  #ifdef _MSC_VER
    #pragma comment(lib, "Advapi32.lib")
  #endif
#endif

namespace authcord {

// ─── Exceptions ─────────────────────────────────────────────────────────────

/**
 * Base exception for all AuthCord SDK errors.
 */
class AuthCordError : public std::runtime_error {
public:
    int status_code;

    explicit AuthCordError(const std::string& message, int status_code = 0)
        : std::runtime_error(message), status_code(status_code) {}
};

/**
 * Raised when API key authentication fails (HTTP 401).
 */
class AuthenticationError : public AuthCordError {
public:
    explicit AuthenticationError(const std::string& message = "Invalid API key")
        : AuthCordError(message, 401) {}
};

/**
 * Raised when the API rate limit is exceeded (HTTP 429).
 */
class RateLimitError : public AuthCordError {
public:
    int retry_after;

    explicit RateLimitError(const std::string& message = "Rate limit exceeded", int retry_after = 60)
        : AuthCordError(message, 429), retry_after(retry_after) {}
};

/**
 * Raised when the API returns a non-success status code.
 */
class ApiError : public AuthCordError {
public:
    explicit ApiError(const std::string& message, int status_code)
        : AuthCordError(message, status_code) {}
};

// ─── Models ─────────────────────────────────────────────────────────────────

struct UserInfo {
    std::string discord_id;
    std::string username;
};

struct ProductInfo {
    std::string id;
    std::string name;
    std::string expires_at;
    bool is_lifetime = false;
    std::string hwid_status;
};

struct HwidResult {
    std::string product_id;
    std::string product_name;
    std::string hwid_status;
};

struct FileInfo {
    std::string id;
    std::string name;
    std::string filename;
    long size = 0;
    std::string description;
    std::string version;
    std::string checksum;
    bool stream_only = false;
};

struct SessionInfo {
    std::string device_name;
    std::string first_seen;
    std::string last_seen;
    std::string ip;
    std::string user_agent;
};

struct ValidationResult {
    bool valid = false;
    std::string mode;
    std::optional<UserInfo> user;
    std::vector<ProductInfo> products;
    std::vector<HwidResult> hwid_results;
    nlohmann::json metadata;
    nlohmann::json config;
    nlohmann::json entitlements;
    std::vector<FileInfo> files;
    std::optional<SessionInfo> session_info;
    std::string reason;
    bool banned = false;
    bool hwid_mismatch = false;
};

struct SessionCreateResult {
    bool success = false;
    std::string session_token;
    std::string expires_at;
    std::string device_name;
};

struct Session {
    std::string id;
    std::string hwid;
    std::string device_name;
    std::string ip;
    std::string last_used_at;
    std::string created_at;
    std::string expires_at;
    std::string revoked_at;
    bool is_active = false;
};

/**
 * Structured HWID components the SDK can send instead of (or alongside) a
 * single opaque `hwid` string. The server combines a configured subset of
 * these — controlled by the app's HWID Strategy in the dashboard — to
 * derive the canonical HWID used for slot matching.
 *
 * Typical "temp HWID spoofers" (used by cheaters to evade FiveM-style
 * bans) change SMBIOS UUID, disk serial, MAC, and MachineGuid — but
 * NOT the Windows User SID or CPUID. An app set to "STABLE" strategy
 * hashes only (sid + cpu_id), so users stay bound across spoofs and
 * don't get locked out of licenses they paid for.
 *
 * See collect_hwid_components() below for a Windows populating helper.
 * On non-Windows platforms, leave fields empty or fill them yourself.
 */
struct HwidComponents {
    std::string sid;           // Windows User SID (S-1-5-21-...) — survives temp spoofers
    std::string cpu_id;        // CPUID signature — silicon, hard to fake
    std::string machine_guid;  // Windows MachineGuid registry value
    std::string mac;           // primary NIC MAC
    std::string disk;          // boot disk serial
};

/**
 * Result of a heartbeat check.
 *
 * `valid` is false when an admin has terminated the device/session, the
 * user has been banned/paused, the product expired, or the HWID was
 * unbound. `reason` carries the machine-readable code so the client can
 * branch on it (e.g. "terminated", "banned", "expired", "hwid_unbound").
 * `next_heartbeat_in` is server-controlled; the auto-heartbeat loop
 * honours it unless the caller pinned an interval.
 */
struct HeartbeatResult {
    bool valid = false;
    std::string reason;
    int next_heartbeat_in = 10;
};

// ───────────────────────────────────────────────────────────────────────────
// Admin operation results (server-side, FULL API key only)
//
// `success` is false for the expected 404 cases (carrying a machine `error`
// code + human `reason`) and the 409 already-paused case. Check it before
// reading the data fields. `status` is the HTTP status code.
// ───────────────────────────────────────────────────────────────────────────

struct PausedProduct {
    std::string product_id;
    std::string paused_at;
    std::string pause_ends_at;
    std::string frozen_expires_at;
};

struct PauseResult {
    bool success = false;
    long status = 0;
    std::vector<PausedProduct> paused;
    std::string error;    // machine code: "user_not_found", "already_paused", ...
    std::string reason;   // human string (404 cases)
    std::string message;  // 409 already-paused message
};

struct UnpausedProduct {
    std::string product_id;
    std::string new_expires_at;
};

struct UnpauseResult {
    bool success = false;
    long status = 0;
    std::vector<UnpausedProduct> unpaused;
    std::string error;
    std::string reason;
};

struct HwidResetEntry {
    std::string product_id;
    int cleared_hwids = 0;      // idempotent: nothing bound reports 0
    bool on_cooldown = false;   // skipped: still inside its reset cooldown
    std::string cooldown_ends_at;  // set when on_cooldown is true (ISO 8601)
};

struct ResetHwidResult {
    bool success = false;
    long status = 0;
    std::vector<HwidResetEntry> reset;
    std::string cooldown_ends_at;  // soonest blocked cooldown end (409 cooldown_active only)
    std::string error;
    std::string reason;
};

/**
 * RAII handle for a running heartbeat loop. Stops the loop on destruction
 * or when stop() is called. Move-only — copying a running loop doesn't
 * make sense.
 */
class HeartbeatLoop {
public:
    struct SharedState {
        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<bool> stopped{false};
    };

    HeartbeatLoop() = default;
    HeartbeatLoop(std::shared_ptr<SharedState> state, std::thread t)
        : state_(std::move(state)), thread_(std::move(t)) {}

    ~HeartbeatLoop() { stop(); }

    HeartbeatLoop(const HeartbeatLoop&) = delete;
    HeartbeatLoop& operator=(const HeartbeatLoop&) = delete;
    HeartbeatLoop(HeartbeatLoop&& other) noexcept = default;
    HeartbeatLoop& operator=(HeartbeatLoop&& other) noexcept {
        if (this != &other) {
            stop();
            state_ = std::move(other.state_);
            thread_ = std::move(other.thread_);
        }
        return *this;
    }

    void stop() {
        if (!state_) return;
        state_->stopped.store(true);
        state_->cv.notify_all();
        if (thread_.joinable()) thread_.join();
        state_.reset();
    }

    bool is_running() const noexcept {
        return state_ && !state_->stopped.load();
    }

private:
    std::shared_ptr<SharedState> state_;
    std::thread thread_;
};

// ─── HWID component collection (Windows) ────────────────────────────────────

/**
 * Best-effort Windows HWID component collector. Populates `sid`, `cpu_id`,
 * and `machine_guid` from the running process's identity, the CPU silicon,
 * and the registry. Leaves fields blank on failure rather than throwing
 * — callers can still pass a partial result.
 *
 * `mac` and `disk` aren't populated here because they typically require
 * WMI (heavy) or admin-privileged APIs; if your app already collects
 * them for other reasons, fill those fields yourself before calling
 * validate(). The default Stable strategy on the server hashes only
 * `sid` + `cpu_id`, so those two are sufficient for the spoofer-
 * resistance use case.
 *
 * Returns an empty struct on non-Windows platforms. Cross-platform
 * callers should fill the struct themselves with whatever stable
 * identifiers they can collect.
 */
inline HwidComponents collect_hwid_components() {
    HwidComponents out;
#ifdef _WIN32
    // ── Windows User SID ──
    // S-1-5-21-X-Y-Z-RID — generated at Windows install, stored in the
    // SAM. Temp HWID spoofers don't touch this because changing it
    // breaks the user profile.
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed > 0) {
            std::vector<BYTE> buffer(needed);
            if (GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
                PSID sid = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
                LPSTR sid_str = nullptr;
                if (ConvertSidToStringSidA(sid, &sid_str)) {
                    out.sid = sid_str;
                    LocalFree(sid_str);
                }
            }
        }
        CloseHandle(token);
    }

    // ── CPUID signature ──
    // Leaf 1 EAX = family/model/stepping; EBX = brand index + APIC; ECX/EDX
    // = feature flags. Not per-chip-unique (Intel deprecated PSN in P3 era)
    // but stable across spoofers and identical across reboots.
    {
        int cpu_info[4] = {0, 0, 0, 0};
        __cpuid(cpu_info, 1);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%08X%08X%08X%08X",
            static_cast<unsigned>(cpu_info[0]),
            static_cast<unsigned>(cpu_info[1]),
            static_cast<unsigned>(cpu_info[2]),
            static_cast<unsigned>(cpu_info[3]));
        out.cpu_id = buf;
    }

    // ── Windows MachineGuid ──
    // Easier to spoof than the SID (it's just a registry value) but free
    // to collect and useful for STRICT strategy.
    {
        HKEY key = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS) {
            char value[128] = {0};
            DWORD size = sizeof(value);
            DWORD type = 0;
            if (RegQueryValueExA(key, "MachineGuid", nullptr, &type,
                                 reinterpret_cast<BYTE*>(value), &size) == ERROR_SUCCESS) {
                // Strip the trailing NUL if registry reported it as part of size
                if (size > 0 && value[size - 1] == '\0') size--;
                out.machine_guid.assign(value, size);
            }
            RegCloseKey(key);
        }
    }
#endif
    return out;
}

// ─── Client ─────────────────────────────────────────────────────────────────

/**
 * Official AuthCord C++ SDK client.
 *
 * Uses libcurl for HTTP and nlohmann/json for JSON parsing.
 */
class AuthCordClient {
public:
    /**
     * Create a new AuthCord client.
     *
     * @param api_key      Your API key (starts with dax_).
     * @param base_url     Base URL for the AuthCord API.
     * @param timeout_secs Request timeout in seconds.
     */
    AuthCordClient(
        const std::string& api_key,
        const std::string& base_url = "https://authcord.dev",
        long timeout_secs = 30)
        : api_key_(api_key)
        , base_url_(base_url)
        , timeout_secs_(timeout_secs)
        , curl_(nullptr)
    {
        // Remove trailing slash from base URL
        while (!base_url_.empty() && base_url_.back() == '/') {
            base_url_.pop_back();
        }

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_ = curl_easy_init();
        if (!curl_) {
            throw AuthCordError("Failed to initialize libcurl");
        }
    }

    ~AuthCordClient() {
        if (curl_) {
            curl_easy_cleanup(curl_);
            curl_ = nullptr;
        }
        curl_global_cleanup();
    }

    // Non-copyable
    AuthCordClient(const AuthCordClient&) = delete;
    AuthCordClient& operator=(const AuthCordClient&) = delete;

    // Movable
    AuthCordClient(AuthCordClient&& other) noexcept
        : api_key_(std::move(other.api_key_))
        , base_url_(std::move(other.base_url_))
        , timeout_secs_(other.timeout_secs_)
        , curl_(other.curl_)
    {
        other.curl_ = nullptr;
    }

    AuthCordClient& operator=(AuthCordClient&& other) noexcept {
        if (this != &other) {
            if (curl_) curl_easy_cleanup(curl_);
            api_key_ = std::move(other.api_key_);
            base_url_ = std::move(other.base_url_);
            timeout_secs_ = other.timeout_secs_;
            curl_ = other.curl_;
            other.curl_ = nullptr;
        }
        return *this;
    }

    /**
     * Validate a user's access to your application.
     *
     * At least one of discord_id, user_id, or email must be non-empty.
     */
    ValidationResult validate(
        const std::string& app_id,
        const std::string& discord_id = "",
        const std::string& user_id = "",
        const std::string& email = "",
        const std::string& product_id = "",
        const std::string& hwid = "")
    {
        if (discord_id.empty() && user_id.empty() && email.empty()) {
            throw AuthCordError("At least one of discord_id, user_id, or email is required.");
        }
        nlohmann::json body = {
            {"app_id", app_id}
        };
        if (!discord_id.empty()) body["discord_id"] = discord_id;
        if (!user_id.empty()) body["user_id"] = user_id;
        if (!email.empty()) body["email"] = email;
        if (!product_id.empty()) body["product_id"] = product_id;
        if (!hwid.empty()) body["hwid"] = hwid;

        auto resp = request("POST", "/api/v1/auth/validate", body);
        return parse_validation_result(resp);
    }

    /**
     * Validate using structured HWID components.
     *
     * The server derives the canonical HWID from a subset of the
     * components based on the app's HWID Strategy setting:
     *   - LEGACY (default): components ignored, opaque `hwid` string used.
     *   - STABLE: server hashes (sid + cpu_id) — spoofer-resistant.
     *   - STRICT: server hashes (sid + cpu + machine_guid + mac + disk).
     *
     * The `hwid` argument is still useful as a back-compat fallback:
     * the server uses it when components are missing or empty, so apps
     * that flip their strategy before all clients have updated continue
     * to work.
     */
    ValidationResult validate(
        const std::string& app_id,
        const std::string& discord_id,
        const HwidComponents& components,
        const std::string& hwid = "",
        const std::string& user_id = "",
        const std::string& email = "",
        const std::string& product_id = "")
    {
        if (discord_id.empty() && user_id.empty() && email.empty()) {
            throw AuthCordError("At least one of discord_id, user_id, or email is required.");
        }
        nlohmann::json body = {
            {"app_id", app_id}
        };
        if (!discord_id.empty()) body["discord_id"] = discord_id;
        if (!user_id.empty()) body["user_id"] = user_id;
        if (!email.empty()) body["email"] = email;
        if (!product_id.empty()) body["product_id"] = product_id;
        if (!hwid.empty()) body["hwid"] = hwid;

        nlohmann::json comp = nlohmann::json::object();
        if (!components.sid.empty())          comp["sid"]          = components.sid;
        if (!components.cpu_id.empty())       comp["cpu_id"]       = components.cpu_id;
        if (!components.machine_guid.empty()) comp["machine_guid"] = components.machine_guid;
        if (!components.mac.empty())          comp["mac"]          = components.mac;
        if (!components.disk.empty())         comp["disk"]         = components.disk;
        if (!comp.empty()) body["hwid_components"] = comp;

        auto resp = request("POST", "/api/v1/auth/validate", body);
        return parse_validation_result(resp);
    }

    /**
     * Create a persistent device session.
     *
     * At least one of discord_id, user_id, or email must be non-empty.
     */
    SessionCreateResult create_session(
        const std::string& app_id,
        const std::string& hwid,
        const std::string& discord_id = "",
        const std::string& user_id = "",
        const std::string& email = "",
        const std::string& device_name = "")
    {
        if (discord_id.empty() && user_id.empty() && email.empty()) {
            throw AuthCordError("At least one of discord_id, user_id, or email is required.");
        }
        nlohmann::json body = {
            {"app_id", app_id},
            {"hwid", hwid}
        };
        if (!discord_id.empty()) body["discord_id"] = discord_id;
        if (!user_id.empty()) body["user_id"] = user_id;
        if (!email.empty()) body["email"] = email;
        if (!device_name.empty()) body["device_name"] = device_name;

        auto resp = request("POST", "/api/v1/auth/sessions/create", body);
        return parse_session_create_result(resp);
    }

    /**
     * Validate using a session token.
     */
    ValidationResult validate_session(
        const std::string& session_token,
        const std::string& hwid,
        const std::string& product_id = "")
    {
        nlohmann::json body = {
            {"session_token", session_token},
            {"hwid", hwid}
        };
        if (!product_id.empty()) body["product_id"] = product_id;

        auto resp = request("POST", "/api/v1/auth/sessions/validate", body);
        return parse_validation_result(resp);
    }

    /**
     * Revoke a specific session by token.
     */
    bool revoke_session(const std::string& session_token) {
        nlohmann::json body = {{"session_token", session_token}};
        auto resp = request("POST", "/api/v1/auth/sessions/revoke", body);
        return resp.value("success", false);
    }

    /**
     * Single heartbeat check — returns whether the user's session is
     * still live. Pass `session_token` (DeviceSession flow) OR both
     * `discord_id` and `hwid` (validate-only flow). The endpoint is
     * cheap and rate-limited to ~2/sec/IP on the server side; intended
     * to be called every few seconds from your app's main loop.
     */
    HeartbeatResult heartbeat(
        const std::string& app_id,
        const std::string& discord_id = "",
        const std::string& hwid = "",
        const std::string& session_token = "")
    {
        if (session_token.empty() && (discord_id.empty() || hwid.empty())) {
            throw std::invalid_argument(
                "heartbeat: provide session_token, or both discord_id and hwid");
        }
        nlohmann::json body = {{"app_id", app_id}};
        if (!session_token.empty()) body["session_token"] = session_token;
        if (!discord_id.empty())    body["discord_id"]    = discord_id;
        if (!hwid.empty())          body["hwid"]          = hwid;

        auto resp = request("POST", "/api/v1/auth/heartbeat", body);
        HeartbeatResult result;
        result.valid             = resp.value("valid", false);
        result.reason            = resp.value("reason", std::string{});
        result.next_heartbeat_in = resp.value("next_heartbeat_in", 10);
        return result;
    }

    /**
     * Heartbeat overload that sends structured HWID components.
     *
     * Use this when your app has been updated to send components on
     * validate — the heartbeat must use the same derivation so the slot
     * lookup hits the right row on STABLE/STRICT-strategy apps.
     * Pass `hwid` too as a back-compat fallback when the app's
     * strategy is still LEGACY.
     */
    HeartbeatResult heartbeat(
        const std::string& app_id,
        const std::string& discord_id,
        const HwidComponents& components,
        const std::string& hwid = "")
    {
        if (discord_id.empty()) {
            throw std::invalid_argument("heartbeat: discord_id is required");
        }
        nlohmann::json body = {
            {"app_id", app_id},
            {"discord_id", discord_id},
        };
        if (!hwid.empty()) body["hwid"] = hwid;

        nlohmann::json comp = nlohmann::json::object();
        if (!components.sid.empty())          comp["sid"]          = components.sid;
        if (!components.cpu_id.empty())       comp["cpu_id"]       = components.cpu_id;
        if (!components.machine_guid.empty()) comp["machine_guid"] = components.machine_guid;
        if (!components.mac.empty())          comp["mac"]          = components.mac;
        if (!components.disk.empty())         comp["disk"]         = components.disk;
        if (!comp.empty()) body["hwid_components"] = comp;

        auto resp = request("POST", "/api/v1/auth/heartbeat", body);
        HeartbeatResult result;
        result.valid             = resp.value("valid", false);
        result.reason            = resp.value("reason", std::string{});
        result.next_heartbeat_in = resp.value("next_heartbeat_in", 10);
        return result;
    }

    /**
     * Start a background heartbeat loop. Invokes `on_terminated` exactly
     * once when the server returns `valid=false` (admin clicked
     * Terminate, user banned, product expired, ...) and then the loop
     * stops on its own. Returns a RAII handle — destroying it (or
     * calling .stop()) cancels the loop and joins the thread.
     *
     * Network errors are passed to `on_error` (if set) and the loop
     * keeps polling. When `interval_seconds` is 0 the loop honours the
     * server-suggested `next_heartbeat_in` between calls.
     */
    HeartbeatLoop start_heartbeat(
        const std::string& app_id,
        std::function<void(const HeartbeatResult&)> on_terminated,
        const std::string& discord_id = "",
        const std::string& hwid = "",
        const std::string& session_token = "",
        int interval_seconds = 0,
        std::function<void(const std::exception&)> on_error = nullptr)
    {
        if (session_token.empty() && (discord_id.empty() || hwid.empty())) {
            throw std::invalid_argument(
                "start_heartbeat: provide session_token, or both discord_id and hwid");
        }

        auto state = std::make_shared<HeartbeatLoop::SharedState>();
        // Capture `this` — the SDK is a single-header lib; lifetime of
        // the client must outlive the loop, same contract as the other
        // SDKs. Document this on the caller side.
        std::thread t([this, state, app_id, discord_id, hwid, session_token,
                       interval_seconds, on_terminated, on_error]() {
            int wait_seconds = interval_seconds > 0 ? interval_seconds : 10;
            while (!state->stopped.load()) {
                {
                    std::unique_lock<std::mutex> lock(state->mtx);
                    state->cv.wait_for(lock, std::chrono::seconds(wait_seconds),
                        [&] { return state->stopped.load(); });
                }
                if (state->stopped.load()) return;

                HeartbeatResult result;
                try {
                    result = this->heartbeat(app_id, discord_id, hwid, session_token);
                } catch (const std::exception& ex) {
                    if (on_error) {
                        try { on_error(ex); } catch (...) { /* swallow */ }
                    }
                    continue;
                }
                if (!result.valid) {
                    try { on_terminated(result); } catch (...) { /* swallow */ }
                    return;
                }
                if (interval_seconds == 0) {
                    wait_seconds = std::max(1, result.next_heartbeat_in);
                }
            }
        });
        return HeartbeatLoop(state, std::move(t));
    }

    /**
     * Revoke all sessions for a user in an app. Returns count revoked.
     */
    int revoke_all_sessions(const std::string& discord_id, const std::string& app_id) {
        nlohmann::json body = {
            {"discord_id", discord_id},
            {"app_id", app_id}
        };
        auto resp = request("POST", "/api/v1/auth/sessions/revoke", body);
        return resp.value("count", 0);
    }

    /**
     * List all sessions for a user in an app.
     */
    std::vector<Session> list_sessions(
        const std::string& discord_id,
        const std::string& app_id)
    {
        std::string path = "/api/v1/auth/sessions/list?discord_id="
            + url_encode(discord_id) + "&app_id=" + url_encode(app_id);
        auto resp = request("GET", path);

        std::vector<Session> sessions;
        if (resp.contains("sessions") && resp["sessions"].is_array()) {
            for (const auto& s : resp["sessions"]) {
                sessions.push_back(parse_session(s));
            }
        }
        return sessions;
    }

    /**
     * Generate a signed offline token.
     *
     * At least one of discord_id, user_id, or email must be non-empty.
     */
    nlohmann::json get_offline_token(
        const std::string& app_id,
        const std::string& discord_id = "",
        const std::string& user_id = "",
        const std::string& email = "",
        const std::string& product_id = "",
        const std::string& hwid = "",
        int ttl = 0)
    {
        if (discord_id.empty() && user_id.empty() && email.empty()) {
            throw AuthCordError("At least one of discord_id, user_id, or email is required.");
        }
        nlohmann::json body = {
            {"app_id", app_id}
        };
        if (!discord_id.empty()) body["discord_id"] = discord_id;
        if (!user_id.empty()) body["user_id"] = user_id;
        if (!email.empty()) body["email"] = email;
        if (!product_id.empty()) body["product_id"] = product_id;
        if (!hwid.empty()) body["hwid"] = hwid;
        if (ttl > 0) body["ttl"] = ttl;

        return request("POST", "/api/v1/auth/offline-token", body);
    }

    /**
     * Get the public key for offline token verification.
     */
    nlohmann::json get_public_key(const std::string& app_id) {
        std::string path = "/api/v1/auth/offline-token/public-key?app_id=" + url_encode(app_id);
        return request("GET", path);
    }

    // ─── Admin operations — server-side only, require a FULL API key ─────────

    /**
     * Pause (freeze the expiry clock) one product — or every product the user
     * owns on the app when product_id is empty — for `days` days.
     *
     * Server-side only. Requires a FULL API key (a CLIENT key gets 403).
     *
     * Does not throw on the expected 404 cases (app/user/product not found,
     * user owns nothing) or the 409 already-paused case — inspect
     * result.success, result.error and result.reason. Auth (401), rate-limit
     * (429), network and server (5xx) errors still throw.
     */
    PauseResult pause_product(
        const std::string& app_id,
        const std::string& discord_id,
        int days,
        const std::string& product_id = "",
        const std::string& reason = "",
        const std::string& paused_by = "")
    {
        nlohmann::json body = {
            {"app_id", app_id},
            {"discord_id", discord_id},
            {"days", days}
        };
        if (!product_id.empty()) body["product_id"] = product_id;
        if (!reason.empty()) body["reason"] = reason;
        if (!paused_by.empty()) body["paused_by"] = paused_by;

        auto rr = request_raw("POST", "/api/v1/products/pause", body);
        const nlohmann::json& resp = rr.second;
        PauseResult r;
        r.status = rr.first;
        r.success = resp.value("success", rr.first >= 200 && rr.first < 300);
        r.error = resp.value("error", "");
        r.reason = resp.value("reason", "");
        r.message = resp.value("message", "");
        if (resp.contains("paused") && resp["paused"].is_array()) {
            for (const auto& p : resp["paused"]) {
                PausedProduct pp;
                pp.product_id = p.value("product_id", "");
                pp.paused_at = p.value("paused_at", "");
                pp.pause_ends_at = (p.contains("pause_ends_at") && !p["pause_ends_at"].is_null())
                    ? p["pause_ends_at"].get<std::string>() : "";
                pp.frozen_expires_at = (p.contains("frozen_expires_at") && !p["frozen_expires_at"].is_null())
                    ? p["frozen_expires_at"].get<std::string>() : "";
                r.paused.push_back(pp);
            }
        }
        return r;
    }

    /**
     * Unpause one product — or every paused product on the app when product_id
     * is empty. Idempotent. Requires a FULL API key. Same error semantics as
     * pause_product().
     */
    UnpauseResult unpause_product(
        const std::string& app_id,
        const std::string& discord_id,
        const std::string& product_id = "")
    {
        nlohmann::json body = {
            {"app_id", app_id},
            {"discord_id", discord_id}
        };
        if (!product_id.empty()) body["product_id"] = product_id;

        auto rr = request_raw("POST", "/api/v1/products/unpause", body);
        const nlohmann::json& resp = rr.second;
        UnpauseResult r;
        r.status = rr.first;
        r.success = resp.value("success", rr.first >= 200 && rr.first < 300);
        r.error = resp.value("error", "");
        r.reason = resp.value("reason", "");
        if (resp.contains("unpaused") && resp["unpaused"].is_array()) {
            for (const auto& u : resp["unpaused"]) {
                UnpausedProduct up;
                up.product_id = u.value("product_id", "");
                up.new_expires_at = (u.contains("new_expires_at") && !u["new_expires_at"].is_null())
                    ? u["new_expires_at"].get<std::string>() : "";
                r.unpaused.push_back(up);
            }
        }
        return r;
    }

    /**
     * Clear the HWID binding(s) for a user on one product — or every product
     * the user owns on the app when product_id is empty — so they can re-bind
     * on a new machine. Idempotent for unbound products.
     *
     * The app's HWID reset cooldown applies (same rule as dashboard and
     * self-service resets): blocked products are skipped with
     * on_cooldown = true, and the call returns 409 cooldown_active when every
     * target was blocked. Pass bypass_cooldown = true for an explicit admin
     * override. Pass hwid (with product_id) to clear a single device slot.
     *
     * Requires a FULL API key; scoped keys need the devices:reset scope.
     * Resets are attributed to the calling key in the reset and audit logs.
     * Same error semantics as pause_product().
     */
    ResetHwidResult reset_hwid(
        const std::string& app_id,
        const std::string& discord_id,
        const std::string& product_id = "",
        const std::string& hwid = "",
        bool bypass_cooldown = false,
        const std::string& reason = "")
    {
        nlohmann::json body = {
            {"app_id", app_id},
            {"discord_id", discord_id}
        };
        if (!product_id.empty()) body["product_id"] = product_id;
        if (!hwid.empty()) body["hwid"] = hwid;
        if (bypass_cooldown) body["bypass_cooldown"] = true;
        if (!reason.empty()) body["reason"] = reason;

        auto rr = request_raw("POST", "/api/v1/products/reset-hwid", body);
        const nlohmann::json& resp = rr.second;
        ResetHwidResult r;
        r.status = rr.first;
        r.success = resp.value("success", rr.first >= 200 && rr.first < 300);
        r.error = resp.value("error", "");
        r.reason = resp.value("reason", "");
        r.cooldown_ends_at = resp.value("cooldown_ends_at", "");
        if (resp.contains("reset") && resp["reset"].is_array()) {
            for (const auto& e : resp["reset"]) {
                HwidResetEntry entry;
                entry.product_id = e.value("product_id", "");
                entry.cleared_hwids = e.value("cleared_hwids", 0);
                entry.on_cooldown = e.value("on_cooldown", false);
                entry.cooldown_ends_at = e.value("cooldown_ends_at", "");
                r.reset.push_back(entry);
            }
        }
        return r;
    }

private:
    std::string api_key_;
    std::string base_url_;
    long timeout_secs_;
    CURL* curl_;

    /**
     * libcurl write callback: appends received data to a std::string.
     */
    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* response = static_cast<std::string*>(userdata);
        size_t total = size * nmemb;
        response->append(ptr, total);
        return total;
    }

    /**
     * URL-encode a string using libcurl.
     */
    std::string url_encode(const std::string& value) {
        char* encoded = curl_easy_escape(curl_, value.c_str(), static_cast<int>(value.length()));
        if (!encoded) return value;
        std::string result(encoded);
        curl_free(encoded);
        return result;
    }

    /**
     * Extract a human-readable error message from a parsed error body.
     */
    static std::string error_message(long http_code, const nlohmann::json& j) {
        std::string msg = "HTTP " + std::to_string(http_code);
        if (j.contains("message") && j["message"].is_string()) {
            msg = j["message"].get<std::string>();
        } else if (j.contains("error") && j["error"].is_string()) {
            msg = j["error"].get<std::string>();
        }
        return msg;
    }

    /**
     * Perform the HTTP call and parse the JSON body. Returns {status, json}.
     * Throws only on network failure or an unparseable body — status-based
     * error handling is left to the caller (request / request_raw).
     */
    std::pair<long, nlohmann::json> perform(
        const std::string& method,
        const std::string& path,
        const nlohmann::json& body)
    {
        std::string url = base_url_ + path;
        std::string response_body;

        curl_easy_reset(curl_);

        // URL
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());

        // Timeout
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, timeout_secs_);

        // Headers
        struct curl_slist* headers = nullptr;
        std::string api_key_header = "X-API-Key: " + api_key_;
        headers = curl_slist_append(headers, api_key_header.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "User-Agent: AuthCord-Cpp-SDK/1.3.0");
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);

        // Write callback
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response_body);

        // Method & body
        std::string body_str;
        if (method == "POST") {
            body_str = body.is_null() ? "{}" : body.dump();
            curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, body_str.c_str());
            curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, static_cast<long>(body_str.size()));
        } else {
            curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
        }

        // Perform request
        CURLcode res = curl_easy_perform(curl_);
        curl_slist_free_all(headers);

        if (res != CURLE_OK) {
            throw AuthCordError(
                std::string("Network error: ") + curl_easy_strerror(res));
        }

        // Get HTTP status code
        long http_code = 0;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);

        // Parse response
        nlohmann::json json_response;
        try {
            json_response = nlohmann::json::parse(response_body);
        } catch (const nlohmann::json::parse_error& e) {
            throw AuthCordError(
                std::string("Failed to parse response: ") + e.what());
        }

        return { http_code, json_response };
    }

    /**
     * Send an HTTP request and return the parsed JSON response. Throws on any
     * HTTP error status (>= 400), mapping 401/429 to typed exceptions.
     */
    nlohmann::json request(
        const std::string& method,
        const std::string& path,
        const nlohmann::json& body = nlohmann::json())
    {
        auto rr = perform(method, path, body);
        long http_code = rr.first;

        if (http_code >= 400) {
            std::string error_msg = error_message(http_code, rr.second);
            if (http_code == 401) {
                throw AuthenticationError(error_msg);
            } else if (http_code == 429) {
                int retry_after = 60;
                if (rr.second.contains("retry_after") && rr.second["retry_after"].is_number()) {
                    retry_after = rr.second["retry_after"].get<int>();
                }
                throw RateLimitError(error_msg, retry_after);
            } else {
                throw ApiError(error_msg, static_cast<int>(http_code));
            }
        }

        return rr.second;
    }

    /**
     * Like request(), but for admin endpoints whose 404/409 responses carry a
     * meaningful JSON body ({success, error, reason}). Returns {status, body}
     * instead of throwing on those. Still throws on auth (401), rate-limit
     * (429) and server (5xx) errors (network/parse throw inside perform()).
     */
    std::pair<long, nlohmann::json> request_raw(
        const std::string& method,
        const std::string& path,
        const nlohmann::json& body = nlohmann::json())
    {
        auto rr = perform(method, path, body);
        long http_code = rr.first;

        if (http_code == 401) {
            throw AuthenticationError(error_message(http_code, rr.second));
        } else if (http_code == 429) {
            int retry_after = 60;
            if (rr.second.contains("retry_after") && rr.second["retry_after"].is_number()) {
                retry_after = rr.second["retry_after"].get<int>();
            }
            throw RateLimitError(error_message(http_code, rr.second), retry_after);
        } else if (http_code >= 500) {
            throw ApiError(error_message(http_code, rr.second), static_cast<int>(http_code));
        }

        return rr;
    }

    // ─── Parsing helpers ────────────────────────────────────────────────────

    static UserInfo parse_user(const nlohmann::json& j) {
        UserInfo u;
        u.discord_id = j.value("discord_id", "");
        u.username = j.value("username", "");
        return u;
    }

    static ProductInfo parse_product(const nlohmann::json& j) {
        ProductInfo p;
        p.id = j.value("id", "");
        p.name = j.value("name", "");
        p.expires_at = j.contains("expires_at") && !j["expires_at"].is_null()
            ? j["expires_at"].get<std::string>() : "";
        p.is_lifetime = j.value("is_lifetime", false);
        p.hwid_status = j.value("hwid_status", "");
        return p;
    }

    static HwidResult parse_hwid_result(const nlohmann::json& j) {
        HwidResult h;
        h.product_id = j.value("productId", "");
        h.product_name = j.value("productName", "");
        h.hwid_status = j.value("hwidStatus", "");
        return h;
    }

    static FileInfo parse_file(const nlohmann::json& j) {
        FileInfo f;
        f.id = j.value("id", "");
        f.name = j.value("name", "");
        f.filename = j.value("filename", "");
        f.size = j.value("size", 0L);
        f.description = j.value("description", "");
        f.version = j.value("version", "");
        f.checksum = j.value("checksum", "");
        f.stream_only = j.value("stream_only", false);
        return f;
    }

    static SessionInfo parse_session_info(const nlohmann::json& j) {
        SessionInfo s;
        s.device_name = j.value("device_name", "");
        s.first_seen = j.value("first_seen", "");
        s.last_seen = j.value("last_seen", "");
        s.ip = j.value("ip", "");
        s.user_agent = j.value("user_agent", "");
        return s;
    }

    static Session parse_session(const nlohmann::json& j) {
        Session s;
        s.id = j.value("id", "");
        s.hwid = j.value("hwid", "");
        s.device_name = j.value("device_name", "");
        s.ip = j.value("ip", "");
        s.last_used_at = j.value("last_used_at", "");
        s.created_at = j.value("created_at", "");
        s.expires_at = j.value("expires_at", "");
        s.revoked_at = j.contains("revoked_at") && !j["revoked_at"].is_null()
            ? j["revoked_at"].get<std::string>() : "";
        s.is_active = j.value("is_active", false);
        return s;
    }

    static ValidationResult parse_validation_result(const nlohmann::json& j) {
        ValidationResult r;
        r.valid = j.value("valid", false);
        r.reason = j.value("reason", "");
        r.banned = j.value("banned", false);
        r.hwid_mismatch = j.value("hwid_mismatch", false);

        if (!r.valid) {
            return r;
        }

        r.mode = j.value("mode", "");

        if (j.contains("user") && j["user"].is_object()) {
            r.user = parse_user(j["user"]);
        }

        if (j.contains("products") && j["products"].is_array()) {
            for (const auto& p : j["products"]) {
                r.products.push_back(parse_product(p));
            }
        }

        if (j.contains("hwid_results") && j["hwid_results"].is_array()) {
            for (const auto& h : j["hwid_results"]) {
                r.hwid_results.push_back(parse_hwid_result(h));
            }
        }

        if (j.contains("files") && j["files"].is_array()) {
            for (const auto& f : j["files"]) {
                r.files.push_back(parse_file(f));
            }
        }

        if (j.contains("session") && j["session"].is_object()) {
            r.session_info = parse_session_info(j["session"]);
        }

        if (j.contains("metadata") && !j["metadata"].is_null()) {
            r.metadata = j["metadata"];
        }

        if (j.contains("config") && !j["config"].is_null()) {
            r.config = j["config"];
        }

        if (j.contains("entitlements") && !j["entitlements"].is_null()) {
            r.entitlements = j["entitlements"];
        }

        return r;
    }

    static SessionCreateResult parse_session_create_result(const nlohmann::json& j) {
        SessionCreateResult r;
        r.success = j.value("success", false);
        r.session_token = j.value("session_token", "");
        r.expires_at = j.value("expires_at", "");
        r.device_name = j.value("device_name", "");
        return r;
    }
};

} // namespace authcord
