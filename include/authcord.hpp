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
#include <curl/curl.h>
#include <nlohmann/json.hpp>

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
     * Send an HTTP request and return the parsed JSON response.
     */
    nlohmann::json request(
        const std::string& method,
        const std::string& path,
        const nlohmann::json& body = nlohmann::json())
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
        headers = curl_slist_append(headers, "User-Agent: AuthCord-Cpp-SDK/1.0.0");
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

        // Handle errors
        if (http_code >= 400) {
            std::string error_msg = "HTTP " + std::to_string(http_code);
            if (json_response.contains("message") && json_response["message"].is_string()) {
                error_msg = json_response["message"].get<std::string>();
            } else if (json_response.contains("error") && json_response["error"].is_string()) {
                error_msg = json_response["error"].get<std::string>();
            }

            if (http_code == 401) {
                throw AuthenticationError(error_msg);
            } else if (http_code == 429) {
                int retry_after = 60;
                // Note: Retry-After from headers is not easily accessible via libcurl
                // after the request; use the response body if available.
                if (json_response.contains("retry_after") && json_response["retry_after"].is_number()) {
                    retry_after = json_response["retry_after"].get<int>();
                }
                throw RateLimitError(error_msg, retry_after);
            } else {
                throw ApiError(error_msg, static_cast<int>(http_code));
            }
        }

        return json_response;
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
