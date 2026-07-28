#pragma once
#include <string>
#include <vector>
#include <ctime>

namespace loguard::session {

enum class SessionType {
    InteractiveSSH,
    ConsoleLogin,
    GraphicalLogin,
    PrivilegeEscalation, // sudo / pkexec
    UserSwitch,          // su
    SystemSession,        // cron / at / anacron
    BackgroundService,    // systemd
    Unknown
};

struct TypeInfo {
    SessionType type;
    std::string label;   // "Interactive Remote Login"
    std::string emoji;   // "🔐"
    bool alertable;       // false => only logged, never sent to Telegram (noise reduction)
};

// Classifies a session from its PAM service name + TTY. This is the single
// source of truth for "what kind of session is this" across the hook,
// daemon, and any future collector (logind, auditd, ...).
TypeInfo classify(const std::string& service, const std::string& tty);

struct TimelineEvent {
    long ts = 0;
    std::string label; // e.g. "Login", "sudo bash", "curl http://..."
};

struct ProcRecord {
    long ts = 0;
    int pid = 0;
    int ppid = 0;
    std::string comm;  // e.g. "curl"
    std::string args;  // full command line
};

struct RiskEntry {
    std::string reason; // "SSH Login", "Reverse Shell"
    int points = 0;
};

struct Session {
    std::string id;
    SessionType type = SessionType::Unknown;
    std::string type_label, type_emoji;
    bool alertable = true;

    std::string user;
    int uid = -1, gid = -1;
    std::string group_name;
    std::string hostname;

    std::string source_ip;      // "local" if not remote
    std::string reverse_dns;
    std::string country, country_code, city, isp;
    bool remote = false;
    bool geo_looked_up = false;

    std::string auth_method;    // "Public Key" / "Password" / "Unknown"
    std::string service;        // PAM service, e.g. "sshd"
    std::string tty;
    std::string shell;
    std::string home;
    std::string cwd;
    bool interactive = false;

    time_t login_time = 0;
    time_t logout_time = 0;     // 0 while still active

    std::vector<TimelineEvent> timeline;
    std::vector<ProcRecord> processes;
    std::vector<std::string> files_modified;
    std::vector<RiskEntry> risk_entries;
    bool privilege_escalation = false;
    int suspicious_count = 0;
    int network_connections = 0;

    int risk_score() const;
    std::string risk_label() const; // "LOW" / "MEDIUM" / "HIGH"
    std::string risk_emoji() const; // 🟢 🟡 🔴
    std::string duration_str() const;

    void add_timeline(const std::string& label, long ts = 0);

    // Rich HTML alert sent immediately at login.
    std::string build_initial_alert_html() const;
    // Rich HTML summary sent at logout.
    std::string build_summary_html() const;
};

} // namespace loguard::session
