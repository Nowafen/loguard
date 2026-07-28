#include "paths.hpp"
#include "util.hpp"
#include "config.hpp"
#include "telegram.hpp"
#include "queue.hpp"
#include "pam.hpp"
#include "integrity.hpp"
#include "session.hpp"
#include "session_queue.hpp"
#include "geoip.hpp"
#include "risk_engine.hpp"
#include "pattern_matcher.hpp"
#include "process_monitor.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

using namespace loguard;
namespace fs = std; // (no <filesystem> dependency kept deliberately minimal)

namespace {

volatile sig_atomic_t g_stop = 0;
void handle_signal(int) { g_stop = 1; }

void require_root(const char* action) {
    if (!util::is_root()) {
        std::cerr << "Error: `" << action << "` must be run as root (use sudo)\n";
        std::exit(1);
    }
}

// ---------- pidfile helpers ----------
bool daemon_is_running() {
    auto lines = util::read_lines(paths::kPidFile);
    if (lines.empty()) return false;
    pid_t pid = 0;
    try { pid = std::stoi(lines[0]); } catch (...) { return false; }
    if (pid <= 0) return false;
    return kill(pid, 0) == 0;
}

void write_pidfile() {
    util::make_dirs(paths::kRunDir, 0755);
    util::write_file_atomic(paths::kPidFile, std::to_string(getpid()) + "\n", 0644);
}

// ---------- shared: one tamper/integrity check pass ----------
// Returns true if everything looks fine.
bool run_check_pass(const Config& cfg, bool attempt_self_heal) {
    std::vector<std::string> problems;

    if (!daemon_is_running()) {
        problems.push_back("loguardd daemon is not running");
    }

    auto tampered = pam::tampered_files();
    for (auto& f : tampered) problems.push_back("PAM hook missing/removed from: " + f);

    auto bad_hashes = integrity::verify();
    for (auto& p : bad_hashes) problems.push_back("Integrity: " + p);

    if (problems.empty()) return true;

    std::string report = "TAMPER/HEALTH ALERT on " + cfg.hostname + ":\n";
    for (auto& p : problems) report += " - " + p + "\n";
    util::log_line(paths::kTamperLog, report);

    if (cfg.valid) {
        std::string html = "<b>Loguard Health Alert</b>\nHost: <code>" + cfg.hostname + "</code>\n";
        for (auto& p : problems) html += "- " + p + "\n";
        // Sent directly (bypassing the queue) so a struggling queue doesn't
        // delay a tamper alert; if this direct send fails it also gets
        // queued below so it's retried like a normal alert.
        bool sent = telegram::send_message(cfg.bot_token, cfg.chat_id, html);
        if (!sent) {
            queue::Event e;
            e.ts = time(nullptr);
            e.user = "-"; e.service = "loguard-check"; e.from = "-"; e.tty = "-";
            e.msg = report;
            e.html_msg = html;
            queue::push(paths::kQueueFile, e);
        }
    }

    if (attempt_self_heal && cfg.self_heal_pam && !tampered.empty() && util::is_root()) {
        int n = pam::enable();
        util::log_line(paths::kTamperLog, "self-heal: re-applied PAM hook to " + std::to_string(n) + " file(s)");
    }

    return false;
}

// ---------- queue delivery pass ----------
void process_queue_once(const Config& cfg) {
    if (!cfg.valid) return;
    auto events = queue::load_all(paths::kQueueFile);
    if (events.empty()) return;

    std::vector<queue::Event> remaining;
    int sent = 0, failed = 0;
    for (auto& e : events) {
        bool ok = telegram::send_message(cfg.bot_token, cfg.chat_id, e.html_msg);
        std::string tag = ok ? "SENT  " : "FAILED";
        util::log_line(paths::kAlertLog,
            tag + " | " + e.user + " | " + e.service + " | " + e.from + " | " + e.tty);
        if (ok) { sent++; }
        else {
            e.attempts++;
            if (e.attempts < 500) remaining.push_back(e); // cap to avoid unbounded growth
            failed++;
        }
    }
    queue::rewrite(paths::kQueueFile, remaining);
    if (sent || failed) {
        util::log_line(paths::kAlertLog,
            "QUEUE | processed=" + std::to_string(sent + failed) +
            " sent=" + std::to_string(sent) + " pending=" + std::to_string(remaining.size()));
    }
}

// ================= Session Monitor (v2) =================
//
// Active sessions live only in this process's memory while the daemon is
// up (kept simple on purpose -- see README "Known limitations"). Two
// timers drive it: handle_session_events() drains session_start/
// session_end events written by the PAM hook, and poll_active_sessions()
// periodically scans `ps` for new child processes of each active session,
// running them through the pattern matcher + risk engine.

std::map<std::string, session::Session> g_sessions;
std::map<std::string, std::set<int>> g_known_pids;
std::set<std::string> g_high_risk_alerted;

// Sends `html` now; if delivery fails, falls back to the retry queue so a
// blip in network connectivity never silently drops a session alert.
void send_or_queue(const Config& cfg, const std::string& html,
                    const std::string& user, const std::string& service) {
    if (!cfg.valid) return;
    bool ok = telegram::send_message(cfg.bot_token, cfg.chat_id, html);
    util::log_line(paths::kAlertLog, std::string(ok ? "SENT  " : "FAILED") +
                    " | " + user + " | " + service);
    if (!ok) {
        queue::Event e;
        e.ts = time(nullptr);
        e.user = user; e.service = service; e.from = "-"; e.tty = "-";
        e.msg = "(session alert, see html_msg)";
        e.html_msg = html;
        queue::push(paths::kQueueFile, e);
    }
}

void log_session_line(const std::string& line) {
    util::log_line(paths::kSessionLog, line);
}

void apply_login_risk(session::Session& s) {
    using namespace loguard::risk;
    switch (s.type) {
        case session::SessionType::InteractiveSSH: add(s, "SSH Login", kSshLogin); break;
        case session::SessionType::ConsoleLogin:
        case session::SessionType::GraphicalLogin: add(s, "Console Login", kConsoleLogin); break;
        case session::SessionType::PrivilegeEscalation: add(s, "sudo", kSudo); s.privilege_escalation = true; break;
        case session::SessionType::UserSwitch: add(s, "su", kSu); break;
        default: break;
    }
    if (s.remote && s.geo_looked_up && !s.country_code.empty() &&
        risk::is_new_country(s.user, s.country_code)) {
        add(s, "New Country (" + s.country + ")", kNewCountrySeen);
    }
}

void handle_session_events(const Config& cfg) {
    for (auto& ev : session_queue::drain()) {
        if (ev.type == "session_start") {
            session::Session s;
            s.id = ev.session_id;
            auto ti = session::classify(ev.service, ev.tty);
            s.type = ti.type; s.type_label = ti.label; s.type_emoji = ti.emoji; s.alertable = ti.alertable;
            s.user = ev.user; s.uid = (int)ev.uid; s.gid = (int)ev.gid; s.group_name = ev.group;
            s.hostname = ev.hostname; s.source_ip = ev.source_ip; s.remote = ev.remote;
            s.auth_method = ev.auth_method; s.service = ev.service; s.tty = ev.tty;
            s.shell = ev.shell; s.home = ev.home; s.cwd = ev.home; s.interactive = ev.interactive;
            s.login_time = ev.ts;
            s.add_timeline("Login", ev.ts);

            if (s.remote && cfg.enable_geoip) {
                auto geo = geoip::lookup(s.source_ip);
                if (geo.ok && !geo.is_private) {
                    s.country = geo.country; s.country_code = geo.country_code;
                    s.city = geo.city; s.isp = geo.isp; s.geo_looked_up = true;
                }
            }

            apply_login_risk(s);

            log_session_line("START " + s.id + " | " + s.type_label + " | user=" + s.user +
                              " tty=" + s.tty + " ip=" + s.source_ip + " risk=" + std::to_string(s.risk_score()));

            if (s.alertable) {
                send_or_queue(cfg, s.build_initial_alert_html(), s.user, s.service);
            }

            g_sessions[s.id] = std::move(s);
            g_known_pids[ev.session_id] = {};

        } else if (ev.type == "session_end") {
            auto it = g_sessions.find(ev.session_id);
            if (it == g_sessions.end()) continue; // daemon restarted mid-session, or already closed
            session::Session& s = it->second;
            s.logout_time = ev.ts;
            s.add_timeline("Logout", ev.ts);

            log_session_line("END   " + s.id + " | duration=" + s.duration_str() +
                              " risk=" + std::to_string(s.risk_score()) + " (" + s.risk_label() + ")");

            if (s.alertable) {
                send_or_queue(cfg, s.build_summary_html(), s.user, s.service);
            }

            g_sessions.erase(it);
            g_known_pids.erase(ev.session_id);
            g_high_risk_alerted.erase(ev.session_id);
        }
    }
}

void poll_active_sessions(const Config& cfg) {
    if (g_sessions.empty()) return;
    auto all_procs = procmon::list_processes();

    for (auto& [id, s] : g_sessions) {
        auto& known = g_known_pids[id];
        auto fresh = procmon::poll_session(all_procs, s.tty, s.user, known);

        for (auto& p : fresh) {
            session::ProcRecord rec;
            rec.ts = time(nullptr); rec.pid = p.pid; rec.ppid = p.ppid;
            rec.comm = p.comm; rec.args = p.args;
            s.processes.push_back(rec);

            auto match = pattern::classify_command(p.comm, p.args, s.shell);
            if (match.category == pattern::Category::None) continue;

            s.add_timeline(p.args.empty() ? p.comm : p.args);

            if (match.category == pattern::Category::ReverseShell) {
                risk::add(s, "Reverse Shell", match.risk_points);
                s.suspicious_count++;
                util::log_line(paths::kSuspiciousLog, "REVERSE-SHELL | session=" + id +
                                " user=" + s.user + " cmd=" + p.args);
                std::ostringstream html;
                html << "🔴 <b>REVERSE SHELL DETECTED</b> ⚠️\n━━━━━━━━━━━━━━━━━━━━\n"
                     << "🆔 <code>" << id << "</code>\n👤 " << s.user << "\n"
                     << "❌ <code>" << p.args << "</code>\n"
                     << "📍 PID: " << p.pid << "\n━━━━━━━━━━━━━━━━━━━━\n"
                     << "Risk: 🔴 HIGH (+" << match.risk_points << ", total " << s.risk_score() << ")";
                send_or_queue(cfg, html.str(), s.user, s.service);

            } else if (match.category == pattern::Category::PrivilegeEscalation) {
                s.privilege_escalation = true;
                risk::add(s, match.reason, match.risk_points);
                std::ostringstream html;
                html << "🔴 <b>Privilege Escalation</b>\n━━━━━━━━━━━━━━━━━━━━\n"
                     << "🆔 <code>" << id << "</code>\n👤 " << s.user << "\n"
                     << "⬆️ <code>" << p.args << "</code>\n📟 " << s.tty
                     << "\n━━━━━━━━━━━━━━━━━━━━\nRisk: +" << match.risk_points
                     << " (total " << s.risk_score() << ")";
                send_or_queue(cfg, html.str(), s.user, s.service);

            } else { // Suspicious
                s.suspicious_count++;
                risk::add(s, match.reason, match.risk_points);
                util::log_line(paths::kSuspiciousLog, "SUSPICIOUS | session=" + id +
                                " user=" + s.user + " cmd=" + p.args);
                std::ostringstream html;
                html << "⚠️ <b>Suspicious Process</b>\n━━━━━━━━━━━━━━━━━━━━\n"
                     << "🆔 <code>" << id << "</code>\n👤 " << s.user << "\n"
                     << "📋 <code>" << p.args << "</code>\n📍 PID: " << p.pid
                     << "\n━━━━━━━━━━━━━━━━━━━━\nRisk: +" << match.risk_points
                     << " (total " << s.risk_score() << ")";
                send_or_queue(cfg, html.str(), s.user, s.service);
            }

            if (risk::crossed_high_risk(s) && !g_high_risk_alerted.count(id)) {
                g_high_risk_alerted.insert(id);
                std::ostringstream html;
                html << "🔴 <b>HIGH RISK SESSION</b>\n━━━━━━━━━━━━━━━━━━━━\n"
                     << "🆔 <code>" << id << "</code>\n👤 " << s.user
                     << "\nScore: " << s.risk_score() << " (threshold "
                     << cfg.high_risk_threshold << ")\n"
                     << "This session has accumulated multiple risk signals -- review immediately.";
                send_or_queue(cfg, html.str(), s.user, s.service);
            }
        }
    }
}

// ---------- daemon main loop ----------
int cmd_daemon() {
    require_root("loguard daemon");
    util::make_dirs(paths::kStateDir, 0700);
    util::make_dirs(paths::kLogDir, 0700);
    util::make_dirs(paths::kSessionsDir, 0700);
    util::make_dirs(paths::kSessionByTtyDir, 0700);
    write_pidfile();

    std::signal(SIGTERM, handle_signal);
    std::signal(SIGINT, handle_signal);

    util::log_line(paths::kAlertLog, "loguardd started (pid " + std::to_string(getpid()) + ")");

    time_t last_heartbeat = 0, last_check = 0, last_session_poll = 0;
    while (!g_stop) {
        Config cfg = load_config(paths::kConfigFile);

        process_queue_once(cfg);
        handle_session_events(cfg);

        time_t now = time(nullptr);
        int poll_every = cfg.process_poll_seconds > 0 ? cfg.process_poll_seconds : 5;
        if (now - last_session_poll >= poll_every) {
            poll_active_sessions(cfg);
            last_session_poll = now;
        }
        if (cfg.valid && cfg.heartbeat_minutes > 0 &&
            now - last_heartbeat >= cfg.heartbeat_minutes * 60) {
            std::string html = "<b>Loguard heartbeat</b>\nHost: <code>" + cfg.hostname +
                                "</code>\nStatus: alive\nTime: <code>" + util::now_str() + "</code>";
            bool ok = telegram::send_message(cfg.bot_token, cfg.chat_id, html);
            util::log_line(paths::kAlertLog, std::string("HEARTBEAT | ") + (ok ? "sent" : "failed"));
            last_heartbeat = now;
        }

        if (now - last_check >= 60) {
            run_check_pass(cfg, /*self_heal=*/true);
            last_check = now;
        }

        for (int i = 0; i < 30 && !g_stop; ++i) usleep(100000); // ~3s, but wakes up fast on signal
    }

    util::log_line(paths::kAlertLog, "loguardd stopping (pid " + std::to_string(getpid()) + ")");
    unlink(paths::kPidFile);
    return 0;
}

int cmd_check() {
    Config cfg = load_config(paths::kConfigFile);
    bool ok = run_check_pass(cfg, /*self_heal=*/util::is_root());
    return ok ? 0 : 2;
}

// ---------- CLI: status / logs / queue ----------
void print_status() {
    std::cout << "Loguard v" << paths::kVersion << " -- login alert status\n\n";

    if (daemon_is_running()) {
        std::cout << "Daemon:      running\n";
    } else {
        std::cout << "Daemon:      NOT running        [run: sudo systemctl start loguard]\n";
    }

    auto active = pam::active_files();
    auto tampered = pam::tampered_files();
    if (!active.empty() && tampered.empty()) {
        std::cout << "PAM hook:    active in " << active.size() << " file(s)\n";
        for (auto& f : active) std::cout << "               - " << f << "\n";
    } else if (!tampered.empty()) {
        std::cout << "PAM hook:    TAMPERED / INCOMPLETE\n";
        for (auto& f : tampered) std::cout << "               - " << f << "\n";
    } else {
        std::cout << "PAM hook:    not enabled         [run: sudo loguard enable]\n";
    }

    Config cfg = load_config(paths::kConfigFile);
    if (cfg.valid) {
        std::cout << "Config:      valid (" << paths::kConfigFile << ")\n";
        std::cout << "Telegram:    configured (chat " << cfg.chat_id << ")\n";
    } else {
        std::cout << "Config:      INVALID -- " << cfg.missing_reason << "\n";
        std::cout << "             run: sudo loguard edit\n";
    }

    auto integrity_problems = integrity::verify();
    std::cout << "Integrity:   " << (integrity_problems.empty() ? "OK" : "PROBLEM DETECTED") << "\n";
    for (auto& p : integrity_problems) std::cout << "               - " << p << "\n";

    auto pending = queue::load_all(paths::kQueueFile);
    std::cout << "Queue:       " << pending.size() << " pending message(s)\n";

    auto logs = util::read_lines(paths::kAlertLog);
    std::string last = "never";
    for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
        if (it->find("SENT") != std::string::npos || it->find("FAILED") != std::string::npos) {
            last = *it; break;
        }
    }
    std::cout << "Last alert:  " << last << "\n";
    std::cout << "Version:     " << paths::kVersion << "\n";
}

void print_logs(int n) {
    auto lines = util::read_lines(paths::kAlertLog);
    int start = std::max(0, (int)lines.size() - n);
    std::cout << "Last " << (lines.size() - start) << " log line(s):\n";
    for (int i = (int)lines.size() - 1; i >= start; --i) std::cout << lines[i] << "\n";
}

void print_queue() {
    auto events = queue::load_all(paths::kQueueFile);
    std::cout << "Pending alerts: " << events.size() << " unsent message(s)\n";
    if (events.empty()) return;
    std::cout << "Preview (first 5):\n";
    for (size_t i = 0; i < events.size() && i < 5; ++i) {
        std::string oneline = events[i].msg;
        for (auto& c : oneline) if (c == '\n') c = ' ';
        std::cout << "  " << (i + 1) << ": " << oneline << " (attempts=" << events[i].attempts << ")\n";
    }
    if (events.size() > 5) std::cout << "  ... and " << (events.size() - 5) << " more.\n";
}

void print_sessions(int n) {
    // The CLI is a short-lived process and the daemon's active-session map
    // lives only in loguardd's memory, so this reads the session log
    // (every start/end line the daemon has written) rather than live state.
    auto lines = util::read_lines(paths::kSessionLog);
    if (lines.empty()) { std::cout << "No session activity recorded yet.\n"; return; }
    int start = std::max(0, (int)lines.size() - n);
    std::cout << "Last " << (lines.size() - start) << " session event(s) "
                 "(run on the host itself; for live state use the Telegram alerts):\n";
    for (int i = start; i < (int)lines.size(); ++i) std::cout << lines[i] << "\n";
}

// ---------- CLI: edit wizard ----------
void edit_wizard() {
    Config cfg = load_config(paths::kConfigFile);
    if (cfg.hostname.empty()) cfg.hostname = util::hostname_str();

    FILE* tty = fopen("/dev/tty", "r+");
    if (!tty) { std::cerr << "No interactive terminal available.\n"; return; }

    auto prompt = [&](const std::string& q) -> std::string {
        fprintf(tty, "%s", q.c_str());
        fflush(tty);
        char buf[512] = {0};
        if (!fgets(buf, sizeof(buf), tty)) return "";
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    };

    while (true) {
        fprintf(tty, "\nLoguard Configuration Wizard\nConfig file: %s\n\n", paths::kConfigFile);
        fprintf(tty, "Current Settings:\n");
        fprintf(tty, "1. Bot Token  -> %s\n", mask_token(cfg.bot_token).c_str());
        fprintf(tty, "2. Chat ID    -> %s\n", cfg.chat_id.empty() ? "(not set)" : cfg.chat_id.c_str());
        fprintf(tty, "3. Hostname   -> %s\n", cfg.hostname.c_str());
        fprintf(tty, "4. Heartbeat  -> every %d minute(s) (0 = disabled)\n", cfg.heartbeat_minutes);
        fprintf(tty, "5. Save & Exit\n6. Exit without saving\n\n");
        std::string choice = prompt("Enter choice [1-6]: ");

        if (choice == "1") {
            std::string v = prompt("Enter Bot Token (Enter to keep current): ");
            if (!v.empty()) cfg.bot_token = v;
        } else if (choice == "2") {
            std::string v = prompt("Enter Chat ID (Enter to keep current): ");
            if (!v.empty()) cfg.chat_id = v;
        } else if (choice == "3") {
            std::string v = prompt("Enter custom hostname (Enter for system default): ");
            cfg.hostname = v.empty() ? util::hostname_str() : v;
        } else if (choice == "4") {
            std::string v = prompt("Heartbeat interval in minutes (0 = disabled): ");
            try { cfg.heartbeat_minutes = std::stoi(v); } catch (...) {}
        } else if (choice == "5") {
            if (cfg.bot_token.empty() || cfg.chat_id.empty()) {
                fprintf(tty, "Warning: Bot Token and Chat ID are REQUIRED to receive alerts.\n");
            }
            util::make_dirs(paths::kConfigDir, 0700);
            save_config(paths::kConfigFile, cfg);
            fprintf(tty, "Configuration saved. Now run: sudo loguard test\n");
            break;
        } else if (choice == "6") {
            fprintf(tty, "No changes saved.\n");
            break;
        } else {
            fprintf(tty, "Invalid option.\n");
        }
    }
    fclose(tty);
}

// ---------- CLI: enable/disable/test/restart/uninstall ----------
void cmd_enable() {
    require_root("loguard enable");
    util::make_dirs(paths::kStateDir, 0700);
    util::make_dirs(paths::kLogDir, 0700);
    util::make_dirs(paths::kSessionsDir, 0700);
    util::make_dirs(paths::kSessionByTtyDir, 0700);
    int n = pam::enable();
    integrity::save_manifest();
    std::string out;
    util::run_capture({"systemctl", "daemon-reload"}, &out);
    util::run_capture({"systemctl", "enable", "--now", "loguard.service"}, &out);
    util::run_capture({"systemctl", "enable", "--now", "loguard-check.timer"}, &out);
    std::cout << "Loguard enabled -- PAM hook applied to " << n << " file(s).\n";
    std::cout << "Monitoring: SSH, Console, SU, SUDO, Graphical login\n";
    if (!daemon_is_running()) {
        std::cout << "Note: could not confirm loguardd is running via systemd on this system.\n";
        std::cout << "      If you are not using systemd, start it manually, e.g. with OpenRC:\n";
        std::cout << "      sudo rc-service loguard start && sudo rc-update add loguard default\n";
    }
}

void cmd_disable() {
    require_root("loguard disable");
    int n = pam::disable();
    std::string out;
    util::run_capture({"systemctl", "stop", "loguard.service"}, &out);
    util::run_capture({"systemctl", "stop", "loguard-check.timer"}, &out);
    std::cout << "Loguard disabled -- PAM hook removed from " << n << " file(s).\n";
    std::cout << "The daemon itself was stopped too; alerts are fully paused.\n";
}

void cmd_test() {
    require_root("loguard test");
    Config cfg = load_config(paths::kConfigFile);
    if (!cfg.valid) {
        std::cerr << "Cannot send test: " << cfg.missing_reason << "\n";
        std::cerr << "Run: sudo loguard edit\n";
        std::exit(1);
    }
    std::string html = "<b>Loguard Test Message</b>\nHost: <code>" + cfg.hostname +
                        "</code>\nTime: <code>" + util::now_str() + "</code>\nStatus: Working!";
    bool ok = telegram::send_message(cfg.bot_token, cfg.chat_id, html);
    if (ok) std::cout << "Test message sent successfully!\n";
    else {
        std::cerr << "Failed to send test message. Check your Bot Token and Chat ID, "
                     "and that this machine can reach api.telegram.org.\n";
        std::exit(1);
    }
}

void cmd_uninstall() {
    require_root("loguard uninstall");
    std::cout << "WARNING: this will completely remove Loguard from this system:\n"
                 "  - all configuration, logs, and pending alerts\n"
                 "  - all PAM rules\n"
                 "  - the loguard command itself\n\n"
                 "Type 'yes' to proceed: ";
    std::string ans; std::getline(std::cin, ans);
    if (ans != "yes") { std::cout << "Uninstall cancelled.\n"; return; }

    pam::disable();
    std::string out;
    util::run_capture({"systemctl", "disable", "--now", "loguard.service"}, &out);
    util::run_capture({"systemctl", "disable", "--now", "loguard-check.timer"}, &out);
    util::run_capture({"rm", "-rf", "/opt/loguard"}, &out);
    util::run_capture({"rm", "-rf", paths::kConfigDir}, &out);
    util::run_capture({"rm", "-rf", paths::kLogDir}, &out);
    util::run_capture({"rm", "-rf", paths::kStateDir}, &out);
    util::run_capture({"rm", "-f", paths::kCliSymlink}, &out);
    std::cout << "Loguard has been completely removed.\n";
}

// ---------- update: GitHub Releases + semver + checksum verification ----------
namespace update_impl {

// Returns every value of `"key":"..."` in order of appearance (not a real
// JSON parser, but sufficient for GitHub's stable, well-ordered API output).
std::vector<std::string> all_values(const std::string& json, const std::string& key) {
    std::vector<std::string> out;
    std::string needle = "\"" + key + "\":\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(needle, pos);
        if (pos == std::string::npos) break;
        pos += needle.size();
        std::string val;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) { pos++; }
            val += json[pos++];
        }
        out.push_back(val);
        pos++;
    }
    return out;
}

std::string detect_arch() {
    std::string out;
    util::run_capture({"uname", "-m"}, &out);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

// Parses a `SHA256SUMS`-style file: lines of "<hex hash>  <filename>".
// Returns the hash for the given filename, or "" if not found.
std::string find_sha_for(const std::string& sums_content, const std::string& filename) {
    std::istringstream in(sums_content);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(filename) != std::string::npos) {
            std::istringstream ls(line);
            std::string hash;
            ls >> hash;
            return hash;
        }
    }
    return "";
}

} // namespace update_impl

void cmd_update() {
    require_root("loguard update");
    using namespace update_impl;

    std::cout << "Checking for updates (current: v" << paths::kVersion << ")...\n";
    std::string api_url = std::string("https://api.github.com/repos/") + paths::kGithubRepo + "/releases/latest";
    std::string json;
    int rc = util::run_capture({"curl", "-fsSL", "-H", "Accept: application/vnd.github+json", api_url}, &json, 20);
    if (rc != 0 || json.empty()) {
        std::cerr << "Could not reach GitHub Releases API. Check network connectivity.\n";
        std::exit(1);
    }

    auto tag = util::json_field(json, "tag_name");
    if (!tag) { std::cerr << "Unexpected response from GitHub (no tag_name found).\n"; std::exit(1); }
    std::string remote_version = *tag;
    if (!remote_version.empty() && remote_version[0] == 'v') remote_version.erase(0, 1);

    if (util::semver_compare(remote_version, paths::kVersion) <= 0) {
        std::cout << "You are up to date (v" << paths::kVersion << ").\n";
        return;
    }

    std::cout << "New version available: v" << remote_version << " (current: v" << paths::kVersion << ")\n";
    std::cout << "Proceed with update? [y/N]: ";
    std::string ans; std::getline(std::cin, ans);
    if (ans != "y" && ans != "Y") { std::cout << "Update cancelled.\n"; return; }

    std::string arch = detect_arch();
    std::string asset_name = "loguard-linux-" + arch + ".tar.gz";

    auto names = all_values(json, "name");
    auto urls = all_values(json, "browser_download_url");
    std::string asset_url, sums_url;
    for (size_t i = 0; i < names.size() && i < urls.size(); ++i) {
        if (names[i] == asset_name) asset_url = urls[i];
        if (names[i] == "SHA256SUMS") sums_url = urls[i];
    }
    if (asset_url.empty() || sums_url.empty()) {
        std::cerr << "No release asset found for this architecture (" << arch << ").\n";
        std::cerr << "Expected an asset named '" << asset_name << "' plus 'SHA256SUMS' on the release.\n";
        std::exit(1);
    }

    std::string tmp_tar = "/tmp/loguard-update.tar.gz";
    std::string tmp_sums = "/tmp/loguard-update.sha256sums";
    std::string out;
    if (util::run_capture({"curl", "-fsSL", "-o", tmp_tar, asset_url}, &out, 60) != 0) {
        std::cerr << "Download failed: " << asset_name << "\n"; std::exit(1);
    }
    if (util::run_capture({"curl", "-fsSL", "-o", tmp_sums, sums_url}, &out, 30) != 0) {
        std::cerr << "Download failed: SHA256SUMS\n"; std::exit(1);
    }

    std::string sums_content;
    { std::ifstream in(tmp_sums); std::ostringstream ss; ss << in.rdbuf(); sums_content = ss.str(); }
    std::string expected = find_sha_for(sums_content, asset_name);
    std::string actual = util::sha256_file(tmp_tar);
    if (expected.empty() || expected != actual) {
        std::cerr << "Checksum verification FAILED for " << asset_name << ".\n";
        std::cerr << "Refusing to install a binary whose checksum does not match the published SHA256SUMS.\n";
        std::cerr << "This can mean a corrupted download, a network tamperer, or a compromised release --\n";
        std::cerr << "in all three cases the safe thing to do is stop here.\n";
        std::exit(1);
    }
    std::cout << "Checksum verified OK (" << actual.substr(0, 16) << "...)\n";

    std::string extract_dir = "/tmp/loguard-update-extract";
    util::run_capture({"rm", "-rf", extract_dir}, &out);
    util::make_dirs(extract_dir, 0700);
    if (util::run_capture({"tar", "-xzf", tmp_tar, "-C", extract_dir}, &out, 30) != 0) {
        std::cerr << "Failed to extract update archive.\n"; std::exit(1);
    }

    auto copy_binary_atomic = [](const std::string& from, const std::string& to) -> bool {
        std::ifstream in(from, std::ios::binary);
        if (!in.good()) return false;
        std::ostringstream ss; ss << in.rdbuf();
        return util::write_file_atomic(to, ss.str(), 0755);
    };

    std::string new_main = extract_dir + "/loguard";
    std::string new_hook = extract_dir + "/loguard-notify";
    if (!util::file_exists(new_main) || !util::file_exists(new_hook)) {
        std::cerr << "Update archive did not contain the expected binaries.\n"; std::exit(1);
    }

    util::run_capture({"systemctl", "stop", "loguard.service"}, &out);
    bool ok1 = copy_binary_atomic(new_main, paths::kMainBinary);
    bool ok2 = copy_binary_atomic(new_hook, paths::kHookBinary);
    if (!ok1 || !ok2) {
        std::cerr << "Failed to install new binaries (permissions?). Aborting.\n"; std::exit(1);
    }
    integrity::save_manifest();
    util::run_capture({"systemctl", "start", "loguard.service"}, &out);

    std::cout << "Updated to v" << remote_version << ". Run `loguard status` to confirm.\n";
}

void print_help() {
    std::cout <<
R"HLP(Loguard v)HLP" << paths::kVersion << R"HLP( -- real-time, tamper-resistant Linux
login alerts delivered to Telegram (SSH, sudo, su, console, graphical).

USAGE
  loguard <command> [arguments]

GETTING STARTED (first time on a new machine)
  1. sudo loguard edit           configure your Telegram Bot Token & Chat ID
  2. sudo loguard test           send a test message to confirm it works
  3. sudo loguard enable         turn on real-time monitoring

COMMANDS
  status              Show full health status: daemon, PAM hook, config,
                       integrity check, pending queue, last alert.

  enable              Activate monitoring: adds the PAM hook to every login
                       path (SSH/console/su/sudo/graphical), starts the
                       background daemon (loguardd) and the watchdog timer,
                       and records an integrity manifest for tamper checks.
                       Requires root.

  disable             Pauses everything: removes the PAM hook and stops the
                       daemon. Configuration and logs are kept.
                       Requires root.

  test                Sends one test message right now, so you can confirm
                       your Bot Token / Chat ID are correct before enabling.
                       Requires root (reads the config file).

  edit                Interactive wizard to set/change the Bot Token,
                       Chat ID, hostname label, and heartbeat interval.
                       Requires root.

  logs [n]            Show the last n delivery log lines (default 20).
                       Every send attempt (SENT/FAILED) is recorded here.

  queue               Show how many alerts are waiting to be delivered
                       (e.g. because the network was down) and preview the
                       first few.

  sessions [n]        Show the last n session start/end log lines
                       (default 40) -- classification, risk score, and
                       duration for every tracked session on this host.

  clear-queue         Permanently discard all pending (undelivered) alerts.
                       Asks for confirmation. Requires root.

  check               Run one watchdog pass right now: verifies the daemon
                       is alive, the PAM hook is still present in every file
                       Loguard added it to, and the installed binaries
                       match their recorded checksums. If anything is
                       wrong, sends an immediate Telegram alert and (if
                       enabled) re-applies the PAM hook automatically.
                       This is what the system timer runs every minute;
                       you can also run it manually any time.

  update              Checks GitHub Releases for a newer version, verifies
                       its checksum, and replaces the binary atomically.
                       Requires root.

  restart             Re-applies the PAM hook (disable, then enable) --
                       useful after a config change or manual PAM edits.
                       Requires root.

  uninstall           Completely removes Loguard: PAM rules, binaries,
                       config, logs, and the systemd units. Asks for
                       confirmation. Requires root.

  version             Print the installed version.

  help                Show this help.

TELEGRAM SETUP (one-time, before `loguard edit`)
  1. Message @BotFather on Telegram: /newbot        -> copy the Bot Token
  2. Start a chat with your new bot: /start
  3. Message @userinfobot to get your numeric Chat ID

HOW IT WORKS (Session Monitor v2)
  - A tiny hook (loguard-notify) fires on PAM session open AND close and
    writes a session_start/session_end event to a local file -- this never
    touches the network, so a slow/offline connection never delays login.
  - Every session is classified (Interactive SSH, Console, Privilege
    Escalation, User Switch, System Session, Background Service) with a
    unique Session ID; pure system housekeeping (cron/systemd) is logged
    but never sent as a Telegram alert.
  - The daemon (loguardd) polls `ps` every few seconds for each active
    session's new child processes (matched by TTY + user), checks them
    against a suspicious-binary list and reverse-shell patterns, and
    raises a Risk Score using the rules in risk_engine.hpp.
  - Remote logins are enriched with GeoIP (country/city/ISP via
    ip-api.com, cached locally) and get a "new country" risk bonus the
    first time a user logs in from a given country.
  - At logout, a full Session Summary is sent: duration, timeline,
    processes seen, privilege escalation flag, and the final risk score.
  - A separate watchdog pass (`loguard check`, run every minute via a
    systemd timer independent of the daemon) verifies the daemon, the PAM
    rules, and the binaries themselves haven't been tampered with, and
    alerts immediately if so.
  - No component can PERFECTLY guarantee delivery against an attacker who
    gains full root access to this exact machine forever (they could, in
    the extreme, wipe the disk). What this design guarantees is that
    quietly disabling alerts without a trace is hard and, in almost every
    realistic case, itself triggers an alert before it succeeds.
  - NOT implemented in this version: file-integrity monitoring (e.g.
    /etc/passwd, authorized_keys changes) and network-connection
    monitoring. Both are reserved as a future file-monitor / net-monitor
    module (see risk_engine.hpp for the already-reserved point values).

FILE LOCATIONS
  Config:            /etc/loguard/config.toml
  PAM manifest:       /etc/loguard/pam_manifest.list
  Integrity hashes:   /etc/loguard/integrity.sha256
  Alert log:          /var/log/loguard/alert.log
  Tamper/health log:  /var/log/loguard/tamper.log
  Session log:        /var/log/loguard/sessions.log
  Suspicious log:     /var/log/loguard/suspicious.log
  Pending queue:      /var/lib/loguard/queue.jsonl
  Session events:     /var/lib/loguard/sessions/events.jsonl
  GeoIP cache:        /var/lib/loguard/sessions/geo_cache.jsonl
  Daemon binary:      /opt/loguard/bin/loguard
  PAM hook binary:    /opt/loguard/bin/loguard-notify
  CLI:                /usr/local/bin/loguard (symlink)

GitHub: https://github.com/)HLP" << paths::kGithubRepo << "\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "status";

    if (cmd == "help" || cmd == "-h" || cmd == "--help") { print_help(); return 0; }
    if (cmd == "version" || cmd == "-v" || cmd == "--version") { std::cout << paths::kVersion << "\n"; return 0; }
    if (cmd == "status" || cmd.empty()) { print_status(); return 0; }
    if (cmd == "logs") {
        int n = 20;
        if (argc > 2) { try { n = std::stoi(argv[2]); } catch (...) {} }
        if (n > 200) n = 200;
        print_logs(n);
        return 0;
    }
    if (cmd == "queue") { print_queue(); return 0; }
    if (cmd == "sessions") {
        int n = 40;
        if (argc > 2) { try { n = std::stoi(argv[2]); } catch (...) {} }
        if (n > 500) n = 500;
        print_sessions(n);
        return 0;
    }
    if (cmd == "clear-queue") {
        require_root("loguard clear-queue");
        std::cout << "Clear all pending alerts? This cannot be undone [y/N]: ";
        std::string ans; std::getline(std::cin, ans);
        if (ans == "y" || ans == "Y") {
            queue::rewrite(paths::kQueueFile, {});
            std::cout << "Pending queue cleared.\n";
        } else {
            std::cout << "Aborted.\n";
        }
        return 0;
    }
    if (cmd == "edit") { require_root("loguard edit"); edit_wizard(); return 0; }
    if (cmd == "enable") { cmd_enable(); return 0; }
    if (cmd == "disable") { cmd_disable(); return 0; }
    if (cmd == "restart") { cmd_disable(); cmd_enable(); return 0; }
    if (cmd == "test") { cmd_test(); return 0; }
    if (cmd == "check") { return cmd_check(); }
    if (cmd == "uninstall") { cmd_uninstall(); return 0; }
    if (cmd == "daemon") { return cmd_daemon(); }
    if (cmd == "update") { cmd_update(); return 0; }

    std::cerr << "Unknown command: " << cmd << "\n\n";
    print_help();
    return 1;
}