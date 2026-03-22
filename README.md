# AuthCord C++ SDK

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
