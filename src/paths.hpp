#pragma once
// Central place for every filesystem path Loguard touches.
// Keeping them in one header means packaging/install.sh and the
// C++ sources can never drift apart.

namespace loguard::paths {

inline constexpr const char* kInstallDir      = "/opt/loguard/bin";
inline constexpr const char* kMainBinary      = "/opt/loguard/bin/loguard";
inline constexpr const char* kHookBinary      = "/opt/loguard/bin/loguard-notify";
inline constexpr const char* kCliSymlink      = "/usr/local/bin/loguard";

inline constexpr const char* kConfigDir       = "/etc/loguard";
inline constexpr const char* kConfigFile      = "/etc/loguard/config.toml";
inline constexpr const char* kPamManifest     = "/etc/loguard/pam_manifest.list";
inline constexpr const char* kIntegrityFile   = "/etc/loguard/integrity.sha256";

inline constexpr const char* kStateDir        = "/var/lib/loguard";
inline constexpr const char* kQueueFile       = "/var/lib/loguard/queue.jsonl";

// Session monitoring (v2)
inline constexpr const char* kSessionsDir     = "/var/lib/loguard/sessions";
inline constexpr const char* kSessionQueueFile= "/var/lib/loguard/sessions/events.jsonl";
inline constexpr const char* kSessionByTtyDir = "/var/lib/loguard/sessions/by_tty";
inline constexpr const char* kGeoCacheFile    = "/var/lib/loguard/sessions/geo_cache.jsonl";
inline constexpr const char* kSeenCountriesFile = "/var/lib/loguard/sessions/seen_countries.list";

inline constexpr const char* kLogDir          = "/var/log/loguard";
inline constexpr const char* kAlertLog        = "/var/log/loguard/alert.log";
inline constexpr const char* kTamperLog       = "/var/log/loguard/tamper.log";
inline constexpr const char* kSessionLog      = "/var/log/loguard/sessions.log";
inline constexpr const char* kSuspiciousLog   = "/var/log/loguard/suspicious.log";

inline constexpr const char* kRunDir          = "/run/loguard";
inline constexpr const char* kPidFile         = "/run/loguard/loguard.pid";

inline constexpr const char* kVersion         = "0.1.1";
inline constexpr const char* kGithubRepo      = "Nowafen/Loguard";

} // namespace loguard::paths
