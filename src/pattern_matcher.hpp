#pragma once
#include <string>

namespace loguard::pattern {

enum class Category {
    None,
    Suspicious,           // curl/wget/nc/python/etc -- worth a look
    ReverseShell,         // bash -i, nc -e, python socket, socat, mkfifo, ...
    PrivilegeEscalation   // sudo / su / pkexec spawned mid-session
};

struct Match {
    Category category = Category::None;
    std::string reason;    // human-readable, e.g. "curl" or "Reverse shell pattern"
    int risk_points = 0;
};

// Classifies one process by its binary name (`comm`, e.g. "curl") and its
// full command line (`args`, e.g. "curl http://x/payload.sh"). `comm`
// equal to `baseline_shell` (the session's own login shell) is never
// flagged on its own -- only what that shell spawns matters.
Match classify_command(const std::string& comm,
                        const std::string& args,
                        const std::string& baseline_shell);

} // namespace loguard::pattern