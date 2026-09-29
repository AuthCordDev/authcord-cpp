// Hosted login: SHA-256/PKCE helpers, the loopback listener, and the code
// exchange against a local fake of AuthCord's token endpoint.
//
// The "browser" is an open_browser callback that requests the loopback
// redirect itself. No test framework: build with CMake and run `ctest`, or run
// the authcord_hosted_login_test binary directly (exit code 0 = all passed).

#include "authcord.hpp"

#include <cstdio>
#include <iostream>
#include <regex>

using authcord::detail::Socket;

static int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            ++g_failures;                                                        \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond \
                      << std::endl;                                              \
        }                                                                        \
    } while (0)

static std::string hex(const std::array<unsigned char, 32>& d) {
    std::string out;
    char buf[3];
    for (unsigned char c : d) {
        std::snprintf(buf, sizeof(buf), "%02x", c);
        out += buf;
    }
    return out;
}

static Socket listen_loopback(int& port) {
    Socket s(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(s.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::listen(s.get(), 4);
    socklen_t len = sizeof(addr);
    ::getsockname(s.get(), reinterpret_cast<sockaddr*>(&addr), &len);
    port = ntohs(addr.sin_port);
    return s;
}

static Socket connect_loopback(int port) {
    Socket s(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));
    if (::connect(s.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) s.reset();
    return s;
}

static std::string read_until_close(authcord::detail::socket_t s) {
    std::string out;
    char buf[4096];
    for (;;) {
        const auto n = ::recv(s, buf, static_cast<int>(sizeof(buf)), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

struct Page {
    int status = 0;  // 0 = could not connect
    std::string body;
};

/** GET http://127.0.0.1:<port><target> like a browser would. */
static Page browser_get(int port, const std::string& target) {
    Page page;
    Socket s = connect_loopback(port);
    if (!s.valid()) return page;
    authcord::detail::send_all(s.get(), "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1:" +
                                            std::to_string(port) + "\r\nConnection: close\r\n\r\n");
    const std::string resp = read_until_close(s.get());
    if (resp.size() > 12) page.status = std::stoi(resp.substr(9, 3));
    const size_t body_at = resp.find("\r\n\r\n");
    if (body_at != std::string::npos) page.body = resp.substr(body_at + 4);
    return page;
}

/** Plays the user's browser: optional extra requests, then the redirect back. */
struct FakeBrowser {
    std::function<std::string(const std::map<std::string, std::string>&)> redirect_query;
    std::vector<std::string> extra_paths;
    std::map<std::string, std::string> authorize;  // query of the URL it was sent to
    std::string authorize_url;
    std::vector<Page> pages;
    std::thread worker;

    ~FakeBrowser() { join(); }
    void join() { if (worker.joinable()) worker.join(); }

    std::function<void(const std::string&)> opener() {
        return [this](const std::string& url) {
            authorize_url = url;
            authorize = query_of(url);
            // Like a real browser, this runs while hosted_login() waits.
            worker = std::thread([this] {
                const std::string redirect = authorize["redirect_uri"];
                const std::smatch m = match_port(redirect);
                const int port = std::stoi(m[1].str());
                for (const auto& p : extra_paths) pages.push_back(browser_get(port, p));
                if (redirect_query) {
                    const std::string q = redirect_query(authorize);
                    if (!q.empty()) pages.push_back(browser_get(port, m[2].str() + "?" + q));
                }
            });
        };
    }

    static std::map<std::string, std::string> query_of(const std::string& url) {
        const size_t q = url.find('?');
        return authcord::detail::parse_query(q == std::string::npos ? "" : url.substr(q + 1));
    }

    static std::smatch match_port(const std::string& redirect) {
        static const std::regex re(R"(^http://127\.0\.0\.1:(\d+)(/callback)$)");
        std::smatch m;
        std::regex_match(redirect, m, re);
        return m;
    }
};

/** One-shot stand-in for AuthCord's POST /api/v1/hosted-login/token. */
struct FakeTokenServer {
    int port = 0;
    int status;
    std::string response_json;
    std::string request_head;
    nlohmann::json request_body;
    bool served = false;
    Socket listener;
    std::thread worker;

    FakeTokenServer(int http_status, std::string json) : status(http_status), response_json(std::move(json)) {
        listener = listen_loopback(port);
        worker = std::thread([this] {
            if (!authcord::detail::wait_readable(listener.get(), 10000)) return;
            Socket conn(::accept(listener.get(), nullptr, nullptr));
            std::string data;
            char buf[4096];
            size_t header_end = std::string::npos;
            size_t content_length = 0;
            for (;;) {
                if (header_end == std::string::npos) {
                    header_end = data.find("\r\n\r\n");
                    if (header_end != std::string::npos) {
                        std::smatch m;
                        const std::string head = data.substr(0, header_end);
                        if (std::regex_search(head, m, std::regex(R"(Content-Length:\s*(\d+))", std::regex::icase))) {
                            content_length = std::stoul(m[1].str());
                        }
                    }
                }
                if (header_end != std::string::npos && data.size() >= header_end + 4 + content_length) break;
                const auto n = ::recv(conn.get(), buf, static_cast<int>(sizeof(buf)), 0);
                if (n <= 0) return;
                data.append(buf, static_cast<size_t>(n));
            }
            request_head = data.substr(0, header_end);
            request_body = nlohmann::json::parse(data.substr(header_end + 4, content_length));
            authcord::detail::send_all(conn.get(),
                "HTTP/1.1 " + std::to_string(this->status) + " X\r\nContent-Type: application/json\r\n"
                "Content-Length: " + std::to_string(response_json.size()) + "\r\nConnection: close\r\n\r\n" +
                response_json);
            served = true;
        });
    }
    ~FakeTokenServer() { join(); }
    void join() { if (worker.joinable()) worker.join(); }
    std::string base_url() const { return "http://127.0.0.1:" + std::to_string(port); }
};

static const char* kTokenOk =
    R"({"success":true,"session_token":"ac_session_abc","expires_at":"2026-10-29T00:00:00.000Z",)"
    R"("device_name":"Work PC","user":{"discord_id":"123456789012345678","username":"user123"}})";

static std::string ok_redirect(const std::map<std::string, std::string>& q) {
    return "code=ac_hlc_test&state=" + q.at("state");
}

static void test_sha256_vectors() {
    using authcord::detail::sha256;
    CHECK(hex(sha256("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hex(sha256("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hex(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(hex(sha256(std::string(1000000, 'a'))) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_pkce() {
    // RFC 7636 Appendix B.
    CHECK(authcord::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") ==
          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    const std::regex verifier_re(R"(^[A-Za-z0-9\-._~]{43,128}$)");
    std::map<std::string, int> seen;
    for (int i = 0; i < 50; ++i) {
        const std::string v = authcord::generate_code_verifier();
        CHECK(std::regex_match(v, verifier_re));
        ++seen[v];
    }
    CHECK(seen.size() == 50);
}

static void test_query_decoding() {
    const auto q = authcord::detail::parse_query("error=access_denied&error_description=Discord+sign-in%20was%3F&x=1&x=2");
    CHECK(q.at("error") == "access_denied");
    CHECK(q.at("error_description") == "Discord sign-in was?");
    CHECK(q.at("x") == "1");
}

static void test_success() {
    FakeTokenServer server(200, kTokenOk);
    authcord::AuthCordClient client("dax_client_key", server.base_url());
    FakeBrowser browser;
    browser.extra_paths = {"/favicon.ico"};
    browser.redirect_query = ok_redirect;

    const auto result = client.hosted_login("app_123", "HWID-WORK-PC", "Work PC", 5, browser.opener());
    browser.join();
    server.join();

    CHECK(result.success);
    CHECK(result.session_token == "ac_session_abc");
    CHECK(result.user.username == "user123");
    CHECK(result.user.discord_id == "123456789012345678");
    CHECK(result.device_name == "Work PC");

    CHECK(browser.authorize_url.rfind(server.base_url() + "/api/v1/hosted-login/authorize?", 0) == 0);
    CHECK(browser.authorize["app_id"] == "app_123");
    CHECK(browser.authorize["response_type"] == "code");
    CHECK(browser.authorize["code_challenge_method"] == "S256");
    CHECK(std::regex_match(browser.authorize["code_challenge"], std::regex(R"(^[A-Za-z0-9_-]{43}$)")));
    CHECK(!FakeBrowser::match_port(browser.authorize["redirect_uri"]).empty());

    // favicon: 404 and the wait went on; callback: the success page.
    CHECK(browser.pages.size() == 2);
    if (browser.pages.size() == 2) {
        CHECK(browser.pages[0].status == 404);
        CHECK(browser.pages[1].status == 200);
        CHECK(browser.pages[1].body.find("Signed in") != std::string::npos);
    }

    CHECK(server.request_head.rfind("POST /api/v1/hosted-login/token ", 0) == 0);
    CHECK(server.request_head.find("X-API-Key: dax_client_key") != std::string::npos);
    CHECK(server.request_body.value("app_id", "") == "app_123");
    CHECK(server.request_body.value("code", "") == "ac_hlc_test");
    CHECK(server.request_body.value("redirect_uri", "") == browser.authorize["redirect_uri"]);
    CHECK(server.request_body.value("hwid", "") == "HWID-WORK-PC");
    CHECK(server.request_body.value("device_name", "") == "Work PC");
    CHECK(authcord::code_challenge_s256(server.request_body.value("code_verifier", "")) ==
          browser.authorize["code_challenge"]);

    // The listener is gone once the flow is over.
    const int port = std::stoi(FakeBrowser::match_port(browser.authorize["redirect_uri"])[1].str());
    CHECK(browser_get(port, "/callback").status == 0);
}

template <typename Fn>
static std::string hosted_login_error(Fn&& fn, std::string* description = nullptr) {
    try {
        fn();
    } catch (const authcord::HostedLoginError& e) {
        if (description) *description = e.description;
        return e.code;
    } catch (const std::exception& e) {
        return std::string("unexpected: ") + e.what();
    }
    return "no error";
}

static void test_state_mismatch() {
    // Nothing listens on the base URL: redeeming would fail with a network error instead.
    authcord::AuthCordClient client("dax_client_key", "http://127.0.0.1:9");
    FakeBrowser browser;
    browser.redirect_query = [](const std::map<std::string, std::string>&) { return std::string("code=ac_hlc_test&state=forged"); };
    CHECK(hosted_login_error([&] { client.hosted_login("app_123", "HWID", "", 5, browser.opener()); }) == "state_mismatch");
    browser.join();
    CHECK(browser.pages.size() == 1 && browser.pages[0].status == 400);
}

static void test_error_redirect() {
    authcord::AuthCordClient client("dax_client_key", "http://127.0.0.1:9");
    FakeBrowser browser;
    browser.redirect_query = [](const std::map<std::string, std::string>& q) {
        return "error=access_denied&error_description=%3Cb%3EDiscord+sign-in+was+not+completed.%3C%2Fb%3E&state=" + q.at("state");
    };
    std::string description;
    CHECK(hosted_login_error([&] { client.hosted_login("app_123", "HWID", "", 5, browser.opener()); }, &description) == "access_denied");
    browser.join();
    CHECK(description == "<b>Discord sign-in was not completed.</b>");
    CHECK(browser.pages.size() == 1);
    if (!browser.pages.empty()) {
        CHECK(browser.pages[0].body.find("<b>") == std::string::npos);
        CHECK(browser.pages[0].body.find("&lt;b&gt;Discord sign-in was not completed.") != std::string::npos);
    }
}

static void test_timeout() {
    authcord::AuthCordClient client("dax_client_key", "http://127.0.0.1:9");
    CHECK(hosted_login_error([&] { client.hosted_login("app_123", "HWID", "", 1, [](const std::string&) {}); }) == "timeout");
}

static void test_invalid_grant() {
    FakeTokenServer server(400, R"({"error":"Invalid or expired code","code":"invalid_grant"})");
    authcord::AuthCordClient client("dax_client_key", server.base_url());
    FakeBrowser browser;
    browser.redirect_query = ok_redirect;
    bool caught = false;
    try {
        client.hosted_login("app_123", "HWID", "", 5, browser.opener());
    } catch (const authcord::ApiError& e) {
        caught = true;
        CHECK(e.status_code == 400);
        CHECK(e.code == "invalid_grant");
    }
    browser.join();
    server.join();
    CHECK(caught);
}

static void test_idle_connection_does_not_hold_up_the_redirect() {
    FakeTokenServer server(200, kTokenOk);
    authcord::AuthCordClient client("dax_client_key", server.base_url());
    FakeBrowser browser;
    browser.redirect_query = ok_redirect;
    Socket idle;
    const auto opener = browser.opener();
    const auto started = std::chrono::steady_clock::now();
    client.hosted_login("app_123", "HWID", "", 5, [&](const std::string& url) {
        // A browser preconnect that never sends a request, ahead of the redirect.
        const auto q = FakeBrowser::query_of(url);
        idle = connect_loopback(std::stoi(FakeBrowser::match_port(q.at("redirect_uri"))[1].str()));
        opener(url);
    });
    browser.join();
    server.join();
    const auto took = std::chrono::steady_clock::now() - started;
    CHECK(idle.valid());
    CHECK(took < std::chrono::seconds(2));
}

static void test_malformed_request_line() {
    FakeTokenServer server(200, kTokenOk);
    authcord::AuthCordClient client("dax_client_key", server.base_url());
    FakeBrowser browser;
    browser.redirect_query = ok_redirect;
    const auto opener = browser.opener();
    std::string reply;
    std::thread garbage;
    struct Joiner {
        std::thread& t;
        ~Joiner() { if (t.joinable()) t.join(); }
    } joiner{garbage};
    const auto result = client.hosted_login("app_123", "HWID", "", 5, [&](const std::string& url) {
        // Runs alongside hosted_login()'s wait, like a browser would.
        garbage = std::thread([&, url] {
            const auto q = FakeBrowser::query_of(url);
            Socket s = connect_loopback(std::stoi(FakeBrowser::match_port(q.at("redirect_uri"))[1].str()));
            authcord::detail::send_all(s.get(), "GARBAGE\r\n\r\n");
            reply = read_until_close(s.get());
            opener(url);
        });
    });
    garbage.join();
    browser.join();
    server.join();
    CHECK(reply.rfind("HTTP/1.1 400", 0) == 0);
    CHECK(result.session_token == "ac_session_abc");
}

static void test_empty_error_parameter() {
    authcord::AuthCordClient client("dax_client_key", "http://127.0.0.1:9");
    FakeBrowser browser;
    browser.redirect_query = [](const std::map<std::string, std::string>& q) { return "error=&state=" + q.at("state"); };
    CHECK(hosted_login_error([&] { client.hosted_login("app_123", "HWID", "", 5, browser.opener()); }) == "invalid_callback");
    browser.join();
}

static void test_missing_hwid_is_rejected_first() {
    authcord::AuthCordClient client("dax_client_key", "http://127.0.0.1:9");
    bool opened = false;
    bool threw = false;
    try {
        client.hosted_login("app_123", "", "", 5, [&](const std::string&) { opened = true; });
    } catch (const authcord::AuthCordError&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(!opened);
}

static void run(const char* name, void (*test)()) {
    std::cout << "[ RUN      ] " << name << std::endl;
    const int before = g_failures;
    test();
    std::cout << (g_failures == before ? "[       OK ] " : "[  FAILED  ] ") << name << std::endl;
}

int main() {
#ifdef _WIN32
    authcord::detail::WinsockSession winsock;
#endif
    run("sha256_vectors", test_sha256_vectors);
    run("pkce", test_pkce);
    run("query_decoding", test_query_decoding);
    run("success", test_success);
    run("state_mismatch", test_state_mismatch);
    run("error_redirect", test_error_redirect);
    run("timeout", test_timeout);
    run("invalid_grant", test_invalid_grant);
    run("idle_connection_does_not_hold_up_the_redirect", test_idle_connection_does_not_hold_up_the_redirect);
    run("malformed_request_line", test_malformed_request_line);
    run("empty_error_parameter", test_empty_error_parameter);
    run("missing_hwid_is_rejected_first", test_missing_hwid_is_rejected_first);

    if (g_failures == 0) {
        std::cout << "hosted_login_test: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "hosted_login_test: " << g_failures << " check(s) failed" << std::endl;
    return 1;
}
