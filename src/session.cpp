#include "session.hpp"
#include "geoip.hpp"
#include "util.hpp"
#include <sstream>
#include <set>
#include <algorithm>

namespace loguard::session {

namespace {
bool in_list(const std::string& v, std::initializer_list<const char*> list) {
    for (auto* s : list) if (v == s) return true;
    return false;
}
}

TypeInfo classify(const std::string& service, const std::string& tty) {
    if (in_list(service, {"cron", "crond", "CRON", "anacron", "at", "atd", "batch"})) {
        return {SessionType::SystemSession, "System Session", "⚙️", false};
    }
    if (in_list(service, {"systemd", "systemd-user"}) || tty == "systemd") {
        return {SessionType::BackgroundService, "Background Service", "⚙️", false};
    }
    if (in_list(service, {"sudo", "sudo-i"})) {
        return {SessionType::PrivilegeEscalation, "Privilege Escalation", "🔴", true};
    }
    if (service == "su") {
        return {SessionType::UserSwitch, "User Switch", "🔁", true};
    }
    if (service == "sshd") {
        return {SessionType::InteractiveSSH, "Interactive Remote Login", "🔐", true};
    }
    if (in_list(service, {"lightdm", "gdm-password", "gdm-launch-environment", "sddm"})) {
        return {SessionType::GraphicalLogin, "Graphical Login", "🖼️", true};
    }
    if (service == "login" || tty.rfind("tty", 0) == 0) {
        return {SessionType::ConsoleLogin, "Console Login", "🖥️", true};
    }
    return {SessionType::Unknown, "Session", "❔", true};
}

void Session::add_timeline(const std::string& label, long ts) {
    TimelineEvent e;
    e.ts = ts ? ts : time(nullptr);
    e.label = label;
    timeline.push_back(e);
}

int Session::risk_score() const {
    int total = 0;
    for (auto& r : risk_entries) total += r.points;
    return total;
}

std::string Session::risk_label() const {
    int s = risk_score();
    if (s >= 100) return "HIGH";
    if (s >= 40) return "MEDIUM";
    return "LOW";
}

std::string Session::risk_emoji() const {
    std::string l = risk_label();
    if (l == "HIGH") return "🔴";
    if (l == "MEDIUM") return "🟡";
    return "🟢";
}

std::string Session::duration_str() const {
    time_t end = logout_time ? logout_time : time(nullptr);
    return util::format_duration(static_cast<long>(end - login_time));
}

std::string Session::build_initial_alert_html() const {
    std::ostringstream o;
    o << type_emoji << " <b>" << type_label << "</b>\n";
    o << "━━━━━━━━━━━━━━━━━━━━\n";
    o << "👤 <b>User</b>\n" << user << " (uid=" << uid << ")\n\n";

    if (remote) {
        o << "🌍 <b>Source</b>\n" << source_ip;
        if (!reverse_dns.empty()) o << " (" << reverse_dns << ")";
        o << "\n";
        if (geo_looked_up && !country.empty()) {
            std::string flag = geoip::flag_emoji(country_code);
            o << (flag.empty() ? "" : flag + " ") << country;
            if (!city.empty()) o << " / " << city;
            o << "\n";
            if (!isp.empty()) o << "🏢 " << isp << "\n";
        }
        o << "\n";
    } else {
        o << "📍 <b>Source</b>\nLocal console\n\n";
    }

    o << "💻 <b>Host</b>\n" << hostname << "\n\n";
    if (!auth_method.empty())
        o << "🔑 <b>Auth</b>\n" << auth_method << "\n\n";
    if (!shell.empty())
        o << "🖥 <b>Shell</b>\n" << shell << "\n\n";
    o << "📟 <b>TTY</b>\n" << tty << "\n\n";
    o << "🕒 <b>Time</b>\n<code>" << util::now_str() << "</code>\n\n";
    o << "🆔 <b>Session</b>\n<code>" << id << "</code>\n";
    o << "━━━━━━━━━━━━━━━━━━━━\n";
    o << "Risk: " << risk_emoji() << " " << risk_label() << " (" << risk_score() << ")";
    return o.str();
}

std::string Session::build_summary_html() const {
    std::ostringstream o;
    o << "📋 <b>Session Summary</b>\n";
    o << "━━━━━━━━━━━━━━━━━━━━\n";
    o << "🆔 <code>" << id << "</code>\n";
    o << "👤 " << user << " (uid=" << uid << ")\n";
    if (remote) {
        o << "🌍 " << source_ip;
        if (geo_looked_up && !country.empty()) {
            std::string flag = geoip::flag_emoji(country_code);
            o << " " << (flag.empty() ? "" : flag + " ") << country;
        }
        o << "\n";
    }
    o << "⏱ Duration: " << duration_str() << "\n";
    o << "━━━━━━━━━━━━━━━━━━━━\n";

    if (!timeline.empty()) {
        o << "🕐 <b>Timeline</b>\n";
        for (auto& t : timeline) {
            char buf[16];
            struct tm tmv{};
            localtime_r(&t.ts, &tmv);
            strftime(buf, sizeof(buf), "%H:%M", &tmv);
            o << buf << " " << t.label << "\n";
        }
        o << "\n";
    }

    if (!processes.empty()) {
        std::set<std::string> unique_comms;
        for (auto& p : processes) unique_comms.insert(p.comm);
        o << "⚙️ <b>Processes</b>\n";
        for (auto& c : unique_comms) o << c << " ";
        o << "\n\n";
    }

    if (!files_modified.empty()) {
        o << "📁 <b>Files Modified</b>\n";
        for (auto& f : files_modified) o << "✏️ " << f << "\n";
        o << "\n";
    }

    o << "🔐 Privilege Escalation: " << (privilege_escalation ? "Yes" : "No") << "\n";
    o << "⚠️ Suspicious Events: " << suspicious_count << "\n";
    o << "🌐 Network Connections: " << network_connections << "\n";
    o << "━━━━━━━━━━━━━━━━━━━━\n";

    if (!risk_entries.empty()) {
        o << "📊 <b>Risk Score</b>\n";
        for (auto& r : risk_entries) {
            o << r.reason << " +" << r.points << "\n";
        }
        o << "─────────\n";
    }
    o << "Total: " << risk_emoji() << " " << risk_label() << " (" << risk_score() << ")";
    return o.str();
}

} // namespace loguard::session
