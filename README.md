# AuthCord C++ SDK

> [AuthCord](https://authcord.dev) - Sell, authenticate, and manage your software. All in one place. Replace your auth system, payment platform, and Discord bots with a single dashboard.

Official AuthCord SDK for C++17. Single-header library.

## Requirements

- C++17 compatible compiler
- [libcurl](https://curl.se/libcurl/) (HTTP client)
- [nlohmann/json](https://github.com/nlohmann/json) (JSON parsing)

## Installation

Copy `include/authcord.hpp` into your project's include path. No build step required for the SDK itself.

Install dependencies via your preferred package manager:

```bash
# Ubuntu/Debian
sudo apt install libcurl4-openssl-dev nlohmann-json3-dev

# macOS (Homebrew)
brew install curl nlohmann-json

# vcpkg
vcpkg install curl nlohmann-json
```

## Build Example

```bash
mkdir build && cd build
cmake ..
cmake --build .
./authcord_example
ctest --output-on-failure   # runs tests/hosted_login_test.cpp
```

## Usage

```cpp
#include "authcord.hpp"
#include <iostream>

int main() {
    try {
        authcord::AuthCordClient client("dax_your_api_key");

        // Validate by Discord ID
        auto result = client.validate("your_app_id", "123456789", "", "", "", "HWID-123");

        if (result.valid) {
            std::cout << "Welcome " << result.user.value().username << "!" << std::endl;
        } else {
            std::cout << "Denied: " << result.reason << std::endl;
        }
    } catch (const authcord::AuthCordError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## Hosted Login (desktop apps without a server)

If your app has no backend of its own, let AuthCord run the Discord sign-in. The user signs in in their browser, and your app gets a device session for the Discord account AuthCord verified. Your app ships only a **CLIENT** key and never has to say who the user is — a Discord ID sent by the app itself can be forged, because Discord IDs are public. (`create_session()` needs a FULL key and belongs on your own server.)

Turn it on per app in the dashboard: **Settings → Hosted Login**.

```cpp
#include "authcord.hpp"
#include <iostream>

authcord::AuthCordClient client("dax_your_client_key");

try {
    auto login = client.hosted_login("your_app_id", "HWID-ABC", /*device_name=*/"Work PC");
    std::cout << "Signed in as " << login.user.username << std::endl;
    // keep login.session_token (e.g. in the OS keychain) for later launches
} catch (const authcord::HostedLoginError& e) {
    std::cerr << "Sign-in did not complete: " << e.code << std::endl;  // access_denied, timeout, ...
}
```

`hosted_login()` opens the default browser at AuthCord's sign-in page and listens on `http://127.0.0.1:<random port>/callback` for the redirect back. It checks `state`, redeems the one-time code with PKCE, and returns the session. It blocks until the user finishes or `timeout_seconds` (default 120) passes, so call it off your UI thread.

- The last argument, `open_browser`, receives the sign-in URL instead of opening the default browser, so you can open it yourself or show it in your UI: `client.hosted_login(app_id, hwid, "Work PC", 120, [](const std::string& url) { ... })`.
- `HostedLoginError::code` is `access_denied` (the user cancelled), `unauthorized_client` (hosted login is off for this app), `timeout`, `state_mismatch`, `invalid_request` or `server_error`.
- `ApiError` is thrown when AuthCord refuses the code (`e.code == "invalid_grant"`, e.g. it expired after 60 seconds) or the user is banned or owns no active product (403). `RateLimitError` (429) means the user already has 10 active sessions; revoke one first.

Use the session token for everything afterwards. All of these work with a CLIENT key:

```cpp
const std::string& token = login.session_token;
client.validate_session(token, "HWID-ABC");                                  // on each launch
auto loop = client.start_heartbeat("your_app_id", on_terminated, "", "", token); // real-time kick
client.get_offline_token_for_session("your_app_id", token);                  // offline mode
client.revoke_session(token);                                                // sign out
```

Self-contained: PKCE's SHA-256 is built in, so there is no OpenSSL dependency. On Windows the header links `Ws2_32`, `Shell32` and `Bcrypt` through `#pragma comment(lib)` under MSVC; with MinGW, add `-lws2_32 -lshell32 -lbcrypt -ladvapi32`. Full example: `examples/hosted_login.cpp`.

## Spoofer-resistant HWID (v1.2+)

The default `validate(app_id, discord_id, ..., hwid)` sends one opaque HWID string. If your users legitimately temp-spoof their hardware (e.g. FiveM cheat customers evading server bans), the HWID your client built changes with the spoof and your user gets locked out of a license they paid for.

Use the **HwidComponents** overload + flip your app's **HWID Strategy** to `STABLE` on the dashboard. The server then derives the canonical HWID from `sid + cpu_id` only — temp HWID spoofers don't touch the Windows User SID or the CPUID, so the same user stays bound across spoofs.

```cpp
#include "authcord.hpp"

authcord::AuthCordClient client("dax_your_api_key");

// Windows: populates SID + CPUID + MachineGuid via Win32 APIs.
// Non-Windows: returns empty; fill the struct yourself.
auto components = authcord::collect_hwid_components();

auto result = client.validate(
    /*app_id*/      "your_app_id",
    /*discord_id*/  "123456789",
    /*components*/  components,
    /*hwid*/        "your_existing_hwid_string");  // back-compat fallback
```

**Backwards-compatible:** the legacy `hwid` arg is still honoured on `LEGACY`-strategy apps, and the server falls back to it whenever components are absent. You can ship a new SDK build to your users **before** flipping the dashboard setting — nobody gets locked out during the rollout. Use the matching `heartbeat()` overload so the heartbeat loop sends components too.

Windows builds: link `Advapi32` (the CMakeLists already does this for the bundled example). Full example: `examples/hwid_components.cpp`.

## Real-time Session Kick (Heartbeat)

After `validate()` succeeds, start a background heartbeat so an admin clicking **Terminate** in the dashboard takes effect within ~10 seconds instead of waiting for the user's next manual validate.

```cpp
#include "authcord.hpp"
#include <iostream>

authcord::AuthCordClient client("dax_your_api_key");

auto loop = client.start_heartbeat(
    /*app_id*/      "your_app_id",
    /*on_terminated*/ [](const authcord::HeartbeatResult& hb) {
        std::cerr << "Session ended: " << hb.reason << std::endl;
        // Tear down: close windows, clear in-memory secrets, exit, etc.
        std::exit(0);
    },
    /*discord_id*/  "123456789",
    /*hwid*/        "HWID-ABC",
    /*session_token*/ "",
    /*interval_seconds*/ 0,  // 0 = honour server-suggested cadence
    /*on_error*/    [](const std::exception& ex) {
        // Network errors are non-fatal — the loop keeps polling.
        std::cerr << "[heartbeat] " << ex.what() << std::endl;
    });

// ... your app does its thing ...
// loop.stop() is called automatically when `loop` goes out of scope.
```

The returned `HeartbeatLoop` is RAII — destroying it (or calling `loop.stop()`) cancels the loop and joins the thread. Reason codes on `valid=false`: `terminated`, `banned`, `paused`, `expired`, `product_expired`, `hwid_unbound`.

For a DeviceSession-based flow, pass `session_token` instead of `discord_id` + `hwid`. Full runnable example in `examples/heartbeat.cpp`.

## Email-Based Validation

AuthCord supports validating users by Discord ID, user ID, or email:

```cpp
// Validate by email
auto result = client.validate("your_app_id", "", "", "user@example.com");

// Validate by custom user ID
auto result2 = client.validate("your_app_id", "", "user123");

// Create a session with email
auto session = client.create_session("your_app_id", "HWID-ABC", "", "", "user@example.com");

// Get offline token with email
auto token = client.get_offline_token("your_app_id", "", "", "user@example.com");
```

## Error Handling

The SDK throws typed exceptions:

- `AuthCordError` -- base class for all errors
- `AuthenticationError` -- invalid API key (HTTP 401)
- `RateLimitError` -- rate limited (HTTP 429), includes `retry_after` field
- `ApiError` -- other HTTP errors, includes `status_code` and the server's machine-readable `code` (e.g. `invalid_grant`), when it sends one
- `HostedLoginError` -- `hosted_login()` ended without a code; includes `code` and `description`

## Admin operations (server-side, FULL key only)

`pause_product`, `unpause_product` and `reset_hwid` mutate user state and
require a **FULL** API key (a CLIENT key is rejected with 403). They do **not**
throw on the expected "not found" cases — inspect `.success`, `.error` (machine
code) and `.reason` (human string). Leave `product_id` empty to apply to every
product the user owns on the app.

`reset_hwid` respects the app's HWID reset cooldown (blocked products are
skipped with `on_cooldown = true`; 409 `cooldown_active` when every target was
blocked). Pass `bypass_cooldown = true` for an admin override, `hwid` to clear
one device slot, and `reason` for the reset log. Scoped API keys need the
`devices:reset` scope; resets are attributed to the calling key.

```cpp
auto res = client.pause_product("app_id", "discord_id", /*days=*/7,
                                /*product_id=*/"", "chargeback hold", "discord:999");
if (res.success) {
    // res.paused is a std::vector<PausedProduct>
} else if (res.error == "user_not_found") {
    // pre-cutover case: res.reason holds the human string
} else {
    // res.status, res.error, res.reason
}

client.unpause_product("app_id", "discord_id"); // all products
client.reset_hwid("app_id", "discord_id");       // cooldown-gated, idempotent
client.reset_hwid("app_id", "discord_id", "", "", /*bypass_cooldown=*/true, "ticket #123");
```
