// Spoofer-resistant HWID via structured components.
//
// Default `validate()` sends one opaque `hwid` string and the server
// matches on it exactly — fine for most apps. But if your users
// legitimately spoof their hardware (e.g. FiveM cheat customers
// evading server bans), the spoof changes the components your old
// HWID was built from and your user gets locked out of a license
// they paid for.
//
// Switch your app's HWID Strategy on the dashboard to "STABLE" and
// use this `validate()` overload. The server hashes (Windows SID +
// CPUID) only — temp HWID spoofers don't touch either, so the same
// user stays bound across spoofs.
//
// Backwards-compat: if you pass `hwid` alongside `components`, the
// server uses the legacy string when the strategy is LEGACY (old
// behaviour) and the derived hash when STABLE/STRICT. So you can
// roll this out before flipping your dashboard setting.

#include "authcord.hpp"
#include <iostream>

int main() {
    try {
        authcord::AuthCordClient client("dax_your_api_key");

        // Collect components on Windows. On other platforms this returns
        // an empty struct — fill it yourself with whatever stable IDs
        // your platform exposes.
        auto components = authcord::collect_hwid_components();
        std::cout << "Collected components:\n"
                  << "  sid          = " << components.sid          << "\n"
                  << "  cpu_id       = " << components.cpu_id       << "\n"
                  << "  machine_guid = " << components.machine_guid << "\n";

        // Validate using the components overload. `legacy_hwid` is your
        // existing client-side HWID string, sent as a fallback so users
        // on LEGACY-strategy apps keep working.
        const std::string legacy_hwid = "PC-12345"; // your existing logic
        auto result = client.validate(
            /*app_id*/      "your_app_id",
            /*discord_id*/  "123456789012345678",
            /*components*/  components,
            /*hwid*/        legacy_hwid);

        if (result.valid) {
            std::cout << "Access granted for "
                      << (result.user ? result.user->username : std::string{"?"})
                      << std::endl;
        } else {
            std::cerr << "Access denied: " << result.reason << std::endl;
            return 1;
        }
    } catch (const authcord::AuthCordError& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
