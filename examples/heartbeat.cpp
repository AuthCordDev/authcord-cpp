// Real-time session kick via the heartbeat loop.
//
// When an admin clicks Terminate in the AuthCord dashboard, the user's
// client app should disconnect within ~10 seconds. This is done by
// running a background heartbeat after the initial validate call.

#include "authcord.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

int main() {
    authcord::AuthCordClient client("dax_your_api_key_here");

    const std::string app_id     = "your_app_id";
    const std::string discord_id = "123456789012345678";
    const std::string hwid       = "PC-12345";

    // Step 1: standard validate at startup.
    auto result = client.validate(app_id, discord_id, /*email*/"", hwid);
    if (!result.valid) {
        std::cerr << "Access denied: " << result.reason << std::endl;
        return 1;
    }
    std::cout << "Access granted for "
              << (result.user ? result.user->username : std::string{"?"}) << std::endl;

    // Step 2: start the heartbeat loop. The returned HeartbeatLoop is
    // RAII — when it goes out of scope the loop stops and the thread is
    // joined. Call loop.stop() explicitly if you want to end early.
    std::atomic<bool> kicked{false};

    auto loop = client.start_heartbeat(
        app_id,
        /*on_terminated*/ [&kicked](const authcord::HeartbeatResult& hb) {
            std::cerr << "\nSession ended by AuthCord: " << hb.reason << std::endl;
            // Tear down whatever your app is doing — close windows,
            // clear secrets in memory, redirect to login, etc.
            kicked.store(true);
        },
        discord_id, hwid,
        /*session_token*/ "",
        /*interval_seconds*/ 0,  // 0 = honour server-suggested cadence
        /*on_error*/ [](const std::exception& ex) {
            // Network errors are non-fatal — the loop keeps polling.
            std::cerr << "[heartbeat] transient error: " << ex.what() << std::endl;
        });

    std::cout << "App running. The heartbeat will kick us off if an admin terminates the session."
              << std::endl;

    // ... your actual app does its thing here ...
    while (!kicked.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Destructor of `loop` would call .stop() and join automatically,
    // but calling stop() explicitly is fine too:
    loop.stop();
    return 0;
}
