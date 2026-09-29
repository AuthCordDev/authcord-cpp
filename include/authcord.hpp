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
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>  // hosted_login() loopback listener (must precede windows.h)
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <shellapi.h>  // ShellExecuteA: hosted_login() opens the browser
  #include <bcrypt.h>    // BCryptGenRandom: PKCE verifier and state
  #include <sddl.h>     // ConvertSidToStringSidA
  #include <intrin.h>   // __cpuid
  // Link Advapi32.lib for SID and registry APIs, plus Ws2_32, Shell32 and
  // Bcrypt for hosted_login(). Most build systems pick these up
  // automatically with MSVC's pragma; MinGW/Clang users may need
  // -lAdvapi32 -lws2_32 -lshell32 -lbcrypt on the link line.
  #ifdef _MSC_VER
    #pragma comment(lib, "Advapi32.lib")
    #pragma comment(lib, "Ws2_32.lib")
    #pragma comment(lib, "Shell32.lib")
    #pragma comment(lib, "Bcrypt.lib")
  #endif
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <spawn.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <sys/wait.h>
  #include <unistd.h>
  #ifdef __APPLE__
    #include <crt_externs.h>  // _NSGetEnviron
  #else
    extern char** environ;
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
 *
 * `code` is the machine-readable code the server sent with the error, if
 * any (e.g. "invalid_grant", "HOSTED_LOGIN_DISABLED", "MISSING_SCOPE").
 */
class ApiError : public AuthCordError {
public:
    std::string code;

    explicit ApiError(const std::string& message, int status_code, const std::string& code = "")
        : AuthCordError(message, status_code), code(code) {}
};

/**
 * Raised when the browser part of hosted_login() ends without a code.
 *
 * `code` is the OAuth error AuthCord redirected back with ("access_denied",
 * "unauthorized_client" when hosted login is off for the app,
 * "invalid_request", "server_error") or one of the SDK's own: "timeout",
 * "state_mismatch", "invalid_callback", "browser_unavailable".
 * `description` is the human-readable detail.
 */
class HostedLoginError : public AuthCordError {
public:
    std::string code;
    std::string description;

    explicit HostedLoginError(const std::string& code, const std::string& description = "")
        : AuthCordError(description.empty() ? code : code + ": " + description),
          code(code), description(description) {}
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

/**
 * Result of hosted_login(): a device session for the Discord account
 * AuthCord verified in the browser.
 */
struct HostedLoginResult {
    bool success = false;
    std::string session_token;
    std::string expires_at;
    std::string device_name;
    UserInfo user;
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

// ─── Hosted login building blocks ───────────────────────────────────────────
//
// PKCE (RFC 7636) and the one-shot loopback listener (RFC 8252 §7.3) behind
// AuthCordClient::hosted_login(). Self-contained: no OpenSSL dependency.

namespace detail {

/** SHA-256 of `data` (FIPS 180-4). */
inline std::array<unsigned char, 32> sha256(const std::string& data) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    std::string msg = data;
    const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;
    msg.push_back(static_cast<char>(0x80));
    while (msg.size() % 64 != 56) msg.push_back('\0');
    for (int i = 7; i >= 0; --i) msg.push_back(static_cast<char>((bit_len >> (i * 8)) & 0xff));

    auto rotr = [](uint32_t x, int n) { return (x >> n) | (x << (32 - n)); };
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            const auto* p = reinterpret_cast<const unsigned char*>(msg.data() + off + i * 4);
            w[i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    std::array<unsigned char, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<unsigned char>(h[i] >> 24);
        out[i * 4 + 1] = static_cast<unsigned char>(h[i] >> 16);
        out[i * 4 + 2] = static_cast<unsigned char>(h[i] >> 8);
        out[i * 4 + 3] = static_cast<unsigned char>(h[i]);
    }
    return out;
}

/** Unpadded base64url (RFC 4648 §5). */
inline std::string base64url(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63]; out += tbl[(n >> 6) & 63]; out += tbl[n & 63];
    }
    if (len - i == 1) {
        const uint32_t n = uint32_t(data[i]) << 16;
        out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63];
    } else if (len - i == 2) {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63]; out += tbl[(n >> 6) & 63];
    }
    return out;
}

/** `n` bytes from the operating system's CSPRNG. */
inline std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> out(n);
#ifdef _WIN32
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(n),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        throw AuthCordError("hosted login: the system random number generator failed");
    }
#else
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw AuthCordError("hosted login: cannot open /dev/urandom");
    size_t got = 0;
    while (got < n) {
        const ssize_t r = ::read(fd, out.data() + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { ::close(fd); throw AuthCordError("hosted login: cannot read /dev/urandom"); }
        got += static_cast<size_t>(r);
    }
    ::close(fd);
#endif
    return out;
}

inline std::string random_token(size_t bytes) {
    const auto b = random_bytes(bytes);
    return base64url(b.data(), b.size());
}

inline std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

inline int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Decode one application/x-www-form-urlencoded component ('+' is a space). */
inline std::string form_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') {
            out += ' ';
        } else if (s[i] == '%' && i + 2 < s.size() && hex_digit(s[i + 1]) >= 0 && hex_digit(s[i + 2]) >= 0) {
            out += static_cast<char>(hex_digit(s[i + 1]) * 16 + hex_digit(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

/** Parse a query string; the first occurrence of a key wins. */
inline std::map<std::string, std::string> parse_query(const std::string& query) {
    std::map<std::string, std::string> out;
    size_t pos = 0;
    while (pos <= query.size()) {
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        const std::string pair = query.substr(pos, amp - pos);
        if (!pair.empty()) {
            const size_t eq = pair.find('=');
            out.emplace(form_decode(pair.substr(0, eq)),
                        eq == std::string::npos ? std::string() : form_decode(pair.substr(eq + 1)));
        }
        pos = amp + 1;
    }
    return out;
}

inline std::string callback_page(const std::string& title, const std::string& detail) {
    const std::string t = html_escape(title);
    return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
           "<title>" + t + "</title>\n"
           "<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,-apple-system,\"Segoe UI\",sans-serif;background:#f6f7f9;color:#1b1d22}@media (prefers-color-scheme:dark){body{background:#111317;color:#e8eaee}}main{max-width:30rem;padding:24px;text-align:center}h1{font-size:1.4rem;margin:0 0 .5rem}p{margin:.25rem 0;opacity:.8}</style>\n"
           "</head><body><main><h1>" + t + "</h1><p>" + html_escape(detail) +
           "</p><p>You can close this tab and return to the app.</p></main></body></html>";
}

#ifdef _WIN32
using socket_t = SOCKET;
const socket_t kInvalidSocket = INVALID_SOCKET;
inline void close_socket(socket_t s) { ::closesocket(s); }

/** Winsock reference for the listener's lifetime (WSAStartup is ref-counted). */
class WinsockSession {
public:
    WinsockSession() {
        WSADATA data;
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw AuthCordError("hosted login: could not initialise Winsock");
        }
    }
    ~WinsockSession() { ::WSACleanup(); }
    WinsockSession(const WinsockSession&) = delete;
    WinsockSession& operator=(const WinsockSession&) = delete;
};
#else
using socket_t = int;
const socket_t kInvalidSocket = -1;
inline void close_socket(socket_t s) { ::close(s); }
#endif

/** Owning socket handle. */
class Socket {
public:
    explicit Socket(socket_t s = kInvalidSocket) : s_(s) {}
    ~Socket() { reset(); }
    Socket(Socket&& other) noexcept : s_(other.s_) { other.s_ = kInvalidSocket; }
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) { reset(); s_ = other.s_; other.s_ = kInvalidSocket; }
        return *this;
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    socket_t get() const { return s_; }
    bool valid() const { return s_ != kInvalidSocket; }
    void reset() {
        if (s_ != kInvalidSocket) { close_socket(s_); s_ = kInvalidSocket; }
    }

private:
    socket_t s_;
};

/** Milliseconds left until `deadline` (0 once it has passed), capped at one minute per wait. */
inline int ms_until(std::chrono::steady_clock::time_point deadline) {
    using rep = std::chrono::milliseconds::rep;
    const rep ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    return ms <= 0 ? 0 : static_cast<int>((std::min)(ms, rep{60000}));
}

/**
 * Which of `socks` are readable (data, a pending connection, or a hang-up)
 * within `timeout_ms`. All false on timeout.
 */
inline std::vector<bool> poll_readable(const std::vector<socket_t>& socks, int timeout_ms) {
    std::vector<bool> ready(socks.size(), false);
#ifdef _WIN32
    fd_set fds;
    FD_ZERO(&fds);
    for (socket_t s : socks) FD_SET(s, &fds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (::select(0, &fds, nullptr, nullptr, &tv) > 0) {
        for (size_t i = 0; i < socks.size(); ++i) ready[i] = FD_ISSET(socks[i], &fds) != 0;
    }
#else
    std::vector<pollfd> fds;
    for (socket_t s : socks) fds.push_back(pollfd{s, POLLIN, 0});
    int n;
    do { n = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), timeout_ms); } while (n < 0 && errno == EINTR);
    if (n > 0) {
        for (size_t i = 0; i < socks.size(); ++i) ready[i] = (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
    }
#endif
    return ready;
}

/** Wait until `s` is readable (or has a pending connection). False on timeout. */
inline bool wait_readable(socket_t s, int timeout_ms) {
    return poll_readable({s}, timeout_ms)[0];
}

inline void set_blocking(socket_t s, bool blocking) {
#ifdef _WIN32
    u_long nonblocking = blocking ? 0 : 1;
    ::ioctlsocket(s, FIONBIO, &nonblocking);
#else
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags >= 0) ::fcntl(s, F_SETFL, blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
#endif
}

inline void send_all(socket_t s, const std::string& data) {
#if defined(MSG_NOSIGNAL)
    const int flags = MSG_NOSIGNAL;  // a closed tab must not SIGPIPE the app
#else
    const int flags = 0;
#endif
    size_t sent = 0;
    while (sent < data.size()) {
        const auto n = ::send(s, data.data() + sent, static_cast<int>(data.size() - sent), flags);
        if (n <= 0) return;  // the browser went away; nothing more to do
        sent += static_cast<size_t>(n);
    }
}

inline void send_page(socket_t s, int status, const std::string& title, const std::string& detail) {
    const std::string body = callback_page(title, detail);
    const char* reason = status == 200 ? "OK" : status == 400 ? "Bad Request" : "Not Found";
    send_all(s, "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n"
                "Cache-Control: no-store\r\n"
                "Connection: close\r\n\r\n" + body);
#ifdef _WIN32
    ::shutdown(s, SD_SEND);
#else
    ::shutdown(s, SHUT_WR);
#endif
}

/** What the redirect to the loopback listener carried. */
struct CallbackOutcome {
    std::string code;         // set on success
    std::string error;        // OAuth error or SDK error code otherwise
    std::string description;
};

/**
 * Listens on http://127.0.0.1:<ephemeral port>/callback for the one redirect
 * AuthCord sends back after sign-in.
 *
 * Requests for any other path (a browser's /favicon.ico, say) get a 404 and
 * don't count. The first request to the callback path is answered with a
 * small "you can close this tab" page and ends the wait, whatever it carries.
 * Connections are serviced together, so one that never sends a request (a
 * browser preconnect) can't hold up the redirect.
 */
class LoopbackReceiver {
public:
    LoopbackReceiver() {
#if defined(SOCK_CLOEXEC)
        listener_ = Socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP));
#else
        listener_ = Socket(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
#endif
        if (!listener_.valid()) throw AuthCordError("hosted login: could not create a socket");
#ifdef _WIN32
        // Don't let the browser (or anything else we launch) inherit the listener.
        ::SetHandleInformation(reinterpret_cast<HANDLE>(listener_.get()), HANDLE_FLAG_INHERIT, 0);
#elif !defined(SOCK_CLOEXEC)
        ::fcntl(listener_.get(), F_SETFD, FD_CLOEXEC);
#endif
        // Non-blocking, so accept() can't hang when a connection is reset
        // between poll() reporting it and accept() taking it.
        set_blocking(listener_.get(), false);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // ephemeral
        if (::bind(listener_.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::listen(listener_.get(), 16) != 0) {
            throw AuthCordError("hosted login: could not listen on 127.0.0.1");
        }
        socklen_t len = sizeof(addr);
        if (::getsockname(listener_.get(), reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            throw AuthCordError("hosted login: could not read the listener's port");
        }
        redirect_uri_ = "http://127.0.0.1:" + std::to_string(ntohs(addr.sin_port)) + "/callback";
    }

    const std::string& redirect_uri() const { return redirect_uri_; }

    /** Wait for the callback; std::nullopt when `deadline` passes first. */
    std::optional<CallbackOutcome> wait(const std::string& state,
                                        std::chrono::steady_clock::time_point deadline) {
        using clock = std::chrono::steady_clock;
        struct Pending {
            Socket sock;
            std::string head;
            clock::time_point give_up;  // connections that stay silent are dropped
            bool done = false;
        };
        std::vector<Pending> pending;

        for (;;) {
            const int remaining = ms_until(deadline);
            if (remaining == 0) return std::nullopt;

            const auto now = clock::now();
            pending.erase(std::remove_if(pending.begin(), pending.end(),
                                         [&](const Pending& p) { return p.done || p.give_up <= now; }),
                          pending.end());

            std::vector<socket_t> socks{listener_.get()};
            for (const auto& p : pending) socks.push_back(p.sock.get());
            const auto ready = poll_readable(socks, (std::min)(remaining, 250));

            for (size_t i = 0; i < pending.size(); ++i) {
                if (!ready[i + 1]) continue;
                Pending& p = pending[i];
                char buf[1024];
                const auto n = ::recv(p.sock.get(), buf, static_cast<int>(sizeof(buf)), 0);
                if (n <= 0) { p.done = true; continue; }
                p.head.append(buf, static_cast<size_t>(n));
                if (p.head.find("\r\n\r\n") == std::string::npos) {
                    if (p.head.size() > 8192) p.done = true;
                    continue;
                }
                p.done = true;
                auto outcome = handle_request(p.sock.get(), p.head, state);
                if (outcome) return outcome;
            }

            if (ready[0]) {
                Socket conn(::accept(listener_.get(), nullptr, nullptr));
                if (conn.valid()) {
                    set_blocking(conn.get(), true);  // accepted sockets inherit non-blocking on BSD and Windows
#if defined(SO_NOSIGPIPE)
                    int one = 1;  // macOS has no MSG_NOSIGNAL
                    ::setsockopt(conn.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
                    if (pending.size() >= kMaxPending) pending.erase(pending.begin());
                    pending.push_back(Pending{std::move(conn), std::string(), clock::now() + std::chrono::seconds(10)});
                }
            }
        }
    }

private:
    static constexpr size_t kMaxPending = 16;

#ifdef _WIN32
    WinsockSession winsock_;  // declared first: outlives the listener socket
#endif
    Socket listener_;
    std::string redirect_uri_;

    /**
     * Answer one complete request head. Returns the outcome when it was the
     * callback, std::nullopt for anything else (which gets a 400 or 404).
     */
    static std::optional<CallbackOutcome> handle_request(socket_t s, const std::string& head,
                                                         const std::string& state) {
        const std::string line = head.substr(0, head.find("\r\n"));
        const size_t sp1 = line.find(' ');
        const size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) {
            send_page(s, 400, "Bad request", "This address only accepts the AuthCord sign-in redirect.");
            return std::nullopt;
        }
        const std::string method = line.substr(0, sp1);
        const std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        const size_t q = target.find('?');
        if (method != "GET" || target.substr(0, q) != "/callback") {
            send_page(s, 404, "Not found", "This address only accepts the AuthCord sign-in redirect.");
            return std::nullopt;
        }

        const auto params = parse_query(q == std::string::npos ? std::string() : target.substr(q + 1));
        const auto get = [&](const char* key) {
            const auto it = params.find(key);
            return it == params.end() ? std::string() : it->second;
        };
        CallbackOutcome out;
        if (params.find("state") == params.end() || get("state") != state) {
            out.error = "state_mismatch";
            out.description = "The sign-in response does not belong to this sign-in attempt.";
        } else if (params.find("error") != params.end()) {
            out.error = get("error").empty() ? "invalid_callback" : get("error");
            out.description = get("error_description");
        } else if (!get("code").empty()) {
            out.code = get("code");
        } else {
            out.error = "invalid_callback";
            out.description = "The sign-in response carried neither a code nor an error.";
        }

        if (out.error.empty()) {
            send_page(s, 200, "Signed in", "Your Discord account is verified.");
        } else {
            send_page(s, 400, "Sign-in failed", out.description.empty() ? out.error : out.description);
        }
        return out;
    }
};

/** Open `url` in the user's default browser without going through a shell. */
inline void open_system_browser(const std::string& url) {
#ifdef _WIN32
    const auto rc = reinterpret_cast<INT_PTR>(
        ::ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    if (rc <= 32) {
        throw HostedLoginError("browser_unavailable",
            "Could not open a web browser. Pass an open_browser callback to show the sign-in URL yourself.");
    }
#else
  #ifdef __APPLE__
    const char* tool = "open";
    char** env = *_NSGetEnviron();
  #else
    const char* tool = "xdg-open";
    char** env = environ;
  #endif
    std::string url_arg = url;
    char* argv[] = {const_cast<char*>(tool), &url_arg[0], nullptr};

    // Detach the launcher from the app: its own process group (so Ctrl+C in
    // the app's terminal doesn't take the browser down) and no stdio.
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    ::posix_spawn_file_actions_init(&actions);
    ::posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    ::posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    ::posix_spawnattr_init(&attr);
    short flags = POSIX_SPAWN_SETPGROUP;
  #ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;  // macOS: pass on only the fds opened above
  #endif
    ::posix_spawnattr_setflags(&attr, flags);
    ::posix_spawnattr_setpgroup(&attr, 0);

    pid_t pid = 0;
    const int rc = ::posix_spawnp(&pid, tool, &actions, &attr, argv, env);
    ::posix_spawnattr_destroy(&attr);
    ::posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        throw HostedLoginError("browser_unavailable",
            std::string("Could not run ") + tool + ". Pass an open_browser callback to show the sign-in URL yourself.");
    }
    // xdg-open can stay alive as long as the browser it started; reap it off-thread.
    std::thread([pid] { int status = 0; ::waitpid(pid, &status, 0); }).detach();
#endif
}

} // namespace detail

/** A fresh PKCE code_verifier: 32 random bytes as base64url (43 chars). */
inline std::string generate_code_verifier() {
    return detail::random_token(32);
}

/** The S256 code_challenge for a verifier: base64url(SHA-256(verifier)). */
inline std::string code_challenge_s256(const std::string& code_verifier) {
    const auto digest = detail::sha256(code_verifier);
    return detail::base64url(digest.data(), digest.size());
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
     * Sign the user in with Discord through AuthCord and create a device
     * session — for desktop apps without their own server. A CLIENT key is
     * enough: AuthCord, not the app, vouches for who the user is.
     *
     * Opens AuthCord's sign-in page in the browser, waits up to
     * `timeout_seconds` (AuthCord allows up to 600) for the redirect back to
     * a one-shot listener on http://127.0.0.1:<random port>/callback, then
     * redeems the one-time code (PKCE S256) for a session bound to `hwid`.
     * Blocks the calling thread; run it off your UI thread. Hosted login must
     * be enabled for the app in the dashboard (Settings → Hosted Login).
     *
     * `open_browser` receives the sign-in URL when set (open it yourself or
     * show it in your UI); otherwise the default browser is opened.
     *
     * Keep `session_token` and use it with validate_session(), heartbeat() /
     * start_heartbeat() (session_token argument),
     * get_offline_token_for_session() and revoke_session() (sign-out).
     *
     * Throws HostedLoginError when the browser part fails (`code`:
     * "access_denied" if the user cancelled, "unauthorized_client" if hosted
     * login is off for the app, "timeout", "state_mismatch", ...), and
     * ApiError when AuthCord refuses the code (`code == "invalid_grant"`) or
     * the user is banned or has no active product (403), and RateLimitError
     * (429) when the user already has 10 active sessions.
     */
    HostedLoginResult hosted_login(
        const std::string& app_id,
        const std::string& hwid,
        const std::string& device_name = "",
        int timeout_seconds = 120,
        const std::function<void(const std::string&)>& open_browser = nullptr)
    {
        // Checked up front: the server would only reject these after the user signed in.
        if (app_id.empty() || hwid.empty()) {
            throw AuthCordError("hosted_login: app_id and hwid are required.");
        }
        const std::string verifier = generate_code_verifier();
        const std::string state = detail::random_token(16);
        std::string redirect_uri;
        detail::CallbackOutcome outcome;
        {
            detail::LoopbackReceiver receiver;
            redirect_uri = receiver.redirect_uri();
            const std::string url = base_url_ + "/api/v1/hosted-login/authorize"
                "?response_type=code"
                "&app_id=" + url_encode(app_id) +
                "&redirect_uri=" + url_encode(redirect_uri) +
                "&code_challenge=" + code_challenge_s256(verifier) +
                "&code_challenge_method=S256"
                "&state=" + state;
            if (open_browser) {
                open_browser(url);
            } else {
                detail::open_system_browser(url);
            }
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
            auto received = receiver.wait(state, deadline);
            if (!received) {
                throw HostedLoginError("timeout",
                    "No sign-in completed within " + std::to_string(timeout_seconds) + " seconds.");
            }
            outcome = *received;
        }
        if (!outcome.error.empty()) {
            throw HostedLoginError(outcome.error, outcome.description);
        }

        nlohmann::json body = {
            {"app_id", app_id},
            {"code", outcome.code},
            {"code_verifier", verifier},
            {"redirect_uri", redirect_uri},
            {"hwid", hwid},
        };
        if (!device_name.empty()) body["device_name"] = device_name;

        auto resp = request("POST", "/api/v1/hosted-login/token", body);
        HostedLoginResult r;
        r.success = resp.value("success", false);
        r.session_token = resp.value("session_token", "");
        r.expires_at = resp.value("expires_at", "");
        r.device_name = (resp.contains("device_name") && resp["device_name"].is_string())
            ? resp["device_name"].get<std::string>() : "";
        if (resp.contains("user") && resp["user"].is_object()) {
            r.user = parse_user(resp["user"]);
        }
        return r;
    }

    /**
     * Revoke a specific session by token. With a CLIENT key this signs the
     * user out of a hosted-login session.
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
                    // Parenthesised: windows.h defines a max() macro.
                    wait_seconds = (std::max)(1, result.next_heartbeat_in);
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
     * Generate a signed offline token for a hosted-login session — the only
     * way with a CLIENT key. The token is bound to the session's device.
     */
    nlohmann::json get_offline_token_for_session(
        const std::string& app_id,
        const std::string& session_token,
        const std::string& product_id = "",
        int ttl = 0)
    {
        nlohmann::json body = {
            {"app_id", app_id},
            {"session_token", session_token}
        };
        if (!product_id.empty()) body["product_id"] = product_id;
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
    std::mutex curl_mutex_;  // curl_ is shared with the heartbeat thread

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
        std::lock_guard<std::mutex> lock(curl_mutex_);
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
     * The machine-readable `code` from a parsed error body, if any.
     */
    static std::string error_code(const nlohmann::json& j) {
        return (j.contains("code") && j["code"].is_string()) ? j["code"].get<std::string>() : "";
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

        std::lock_guard<std::mutex> lock(curl_mutex_);
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
        headers = curl_slist_append(headers, "User-Agent: AuthCord-Cpp-SDK/1.4.0");
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
                throw ApiError(error_msg, static_cast<int>(http_code), error_code(rr.second));
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
