/**
 * Hosted login: sign the user in with Discord through AuthCord, without a
 * server of your own. Ships a CLIENT key only.
 *
 * Enable it for your app first: dashboard → Settings → Hosted Login.
 */

#include "authcord.hpp"
#include <cstdlib>
#include <iostream>

int main() {
    authcord::AuthCordClient client("dax_your_client_key");
    const std::string app_id = "your_app_id";
    const std::string hwid = "HWID-ABC";

    try {
        // Opens the browser, waits for the user to sign in, and returns a
        // device session for the Discord account AuthCord verified.
        auto login = client.hosted_login(app_id, hwid, /*device_name=*/"Work PC");
        std::cout << "Signed in as " << login.user.username << std::endl;

        // Store login.session_token (e.g. in the OS keychain). On later
        // launches validate it instead of signing in again.
        auto result = client.validate_session(login.session_token, hwid);
        if (result.valid) {
            for (const auto& product : result.products) {
                std::cout << "  " << product.name << (product.is_lifetime ? " (lifetime)" : "") << std::endl;
            }
        }

        // Real-time kick, keyed by the session token.
        auto loop = client.start_heartbeat(
            app_id,
            [](const authcord::HeartbeatResult& hb) {
                std::cerr << "Session ended: " << hb.reason << std::endl;
                std::exit(0);
            },
            /*discord_id=*/"", /*hwid=*/"", /*session_token=*/login.session_token);

        // ... your app does its thing ...

        // Sign out.
        loop.stop();
        client.revoke_session(login.session_token);
    } catch (const authcord::HostedLoginError& e) {
        // "access_denied" (user cancelled), "timeout", "unauthorized_client"
        // (hosted login is off for this app), ...
        std::cerr << "Sign-in did not complete: " << e.code << " " << e.description << std::endl;
        return 1;
    } catch (const authcord::AuthCordError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
