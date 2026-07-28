#pragma once
#include <string>

namespace loguard {

struct Config {
    std::string bot_token;
    std::string chat_id;
    std::string hostname;
    std::string os_info;             // e.g. "Ubuntu 24.04" -- cosmetic, shown in alerts
    int heartbeat_minutes = 15;      // 0 disables heartbeat
    bool self_heal_pam   = true;     // re-add PAM line if watchdog finds it missing
    bool valid = false;              // true once bot_token + chat_id are present
    std::string missing_reason;

    // Session Monitor (v2) settings
    int process_poll_seconds  = 5;    // how often to scan `ps` for new processes per active session
    bool enable_geoip         = true; // look up country/city/ISP for remote IPs via ip-api.com
    int high_risk_threshold   = 100;  // immediate alert fires once a session's score reaches this
};

// Returns Config with .valid=false and a human-readable .missing_reason
// if the file is absent or required fields are empty. Never throws.
Config load_config(const std::string& path);

// Writes the config as TOML with 0600 permissions (atomic).
bool save_config(const std::string& path, const Config& c);

std::string mask_token(const std::string& token);

} // namespace loguard
