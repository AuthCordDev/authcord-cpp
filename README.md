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
- `ApiError` -- other HTTP errors, includes `status_code` field
