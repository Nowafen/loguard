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

    // Anti-tamper hardening (v2.2)
    bool enable_immutable        = true; // chattr +i on binaries + PAM files after `enable`
    std::string healthcheck_url;         // external dead-man's-switch ping URL (e.g. healthchecks.io); empty = off
    int deadman_interval_seconds = 120;  // how often the daemon pings healthcheck_url

    // Admin passphrase gate: required before `disable`/`uninstall`/`edit`
    // once set (via `loguard set-password`). Only a salted SHA-256 hash is
    // ever stored -- never the passphrase itself.
    std::string admin_passphrase_hash;
    std::string admin_passphrase_salt;

    // sudo-style cached auth: once you enter the passphrase successfully,
    // it is not asked again for this many seconds IF the request comes
    // from the same parent shell process (see auth_session_key() in
    // main.cpp). 0 disables caching (always prompt).
    int passphrase_cache_seconds = 300;
};

// Returns Config with .valid=false and a human-readable .missing_reason
// if the file is absent or required fields are empty. Never throws.
Config load_config(const std::string& path);

// Writes the config as TOML with 0600 permissions (atomic).
bool save_config(const std::string& path, const Config& c);

std::string mask_token(const std::string& token);

} // namespace loguard
