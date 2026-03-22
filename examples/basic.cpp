#include "authcord.hpp"
#include <iostream>

int main() {
    try {
        authcord::AuthCordClient client("dax_your_api_key");

        // Validate a user
        auto result = client.validate("123456789", "your_app_id", "", "HWID-123");

        if (result.valid) {
            std::cout << "Welcome " << result.user.value().username << "!" << std::endl;

            for (const auto& product : result.products) {
                std::cout << "  Product: " << product.name
                          << " (lifetime: " << (product.is_lifetime ? "yes" : "no") << ")"
                          << std::endl;
            }
        } else {
            std::cout << "Denied: " << result.reason << std::endl;
        }

        // Create a session
        auto session = client.create_session("123456789", "your_app_id", "HWID-123", "Work PC");
        std::cout << "Session token: " << session.session_token << std::endl;

        // Validate with session
        auto session_result = client.validate_session(session.session_token, "HWID-123");
        if (session_result.valid) {
            std::cout << "Session valid!" << std::endl;
        }

    } catch (const authcord::AuthenticationError& e) {
        std::cerr << "Auth error: " << e.what() << std::endl;
        return 1;
    } catch (const authcord::RateLimitError& e) {
        std::cerr << "Rate limited. Retry after " << e.retry_after << "s" << std::endl;
        return 1;
    } catch (const authcord::AuthCordError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
