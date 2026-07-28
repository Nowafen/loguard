#include "pattern_matcher.hpp"
#include <vector>
#include <algorithm>

namespace loguard::pattern {

namespace {

std::string basename_of(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

const std::vector<std::string>& suspicious_binaries() {
    static const std::vector<std::string> v = {
        "curl", "wget", "nc", "ncat", "netcat", "python", "python2", "python3",
        "perl", "ruby", "php", "sh", "zsh", "ssh", "scp", "sftp", "docker",
        "kubectl", "socat", "telnet"
    };
    return v;
}

const std::vector<std::string>& privesc_binaries() {
    static const std::vector<std::string> v = {"sudo", "su", "pkexec"};
    return v;
}

// Reverse-shell one-liners are recognizable substrings almost regardless of
// how the rest of the command is padded/obfuscated -- checking a handful of
// well-known fragments catches the overwhelming majority of copy-pasted
// reverse shell payloads without needing a full parser.
bool looks_like_reverse_shell(const std::string& args) {
    static const std::vector<std::string> fragments = {
        "bash -i", "sh -i", "-i >&", "/dev/tcp/", "/dev/udp/",
        "nc -e", "ncat -e", "nc.traditional -e",
        "socket.socket(", "socket.SOCK_STREAM",
        "IO::Socket", "php -r", "pty.spawn", "mkfifo",
    };
    for (auto& f : fragments) if (contains(args, f)) return true;
    return false;
}

} // namespace

Match classify_command(const std::string& comm,
                        const std::string& args,
                        const std::string& baseline_shell) {
    std::string base = basename_of(comm);
    std::string base_shell = basename_of(baseline_shell);

    // Reverse shell patterns take priority -- check regardless of binary name,
    // since obfuscated reverse shells often run through the shell itself.
    if (looks_like_reverse_shell(args)) {
        return {Category::ReverseShell, "Reverse shell pattern detected", 100};
    }

    // The session's own login shell process is expected and not, by itself,
    // suspicious -- only what it spawns matters.
    if (base == base_shell && args.find(' ') == std::string::npos) {
        return {Category::None, "", 0};
    }

    for (auto& b : privesc_binaries()) {
        if (base == b) {
            return {Category::PrivilegeEscalation, "Privilege escalation via " + base, 15};
        }
    }

    for (auto& b : suspicious_binaries()) {
        if (base == b) {
            int points = 20;
            if (base == "nc" || base == "ncat" || base == "netcat" || base == "telnet") points = 40;
            return {Category::Suspicious, base, points};
        }
    }

    return {Category::None, "", 0};
}

} // namespace loguard::pattern
