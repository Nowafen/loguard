#pragma once
#include <string>
#include <vector>
#include <set>

namespace loguard::procmon {

struct ProcSnapshot {
    int pid = 0;
    int ppid = 0;
    std::string tty;   // as reported by `ps`, e.g. "pts/0", "tty1", "?"
    std::string user;
    std::string args;  // full command line
    std::string comm;  // basename of the executable (first arg)
};

// Runs `ps -eo pid,ppid,tty,user:32,args --no-headers` once and parses it.
// Uses `ps` (a subprocess, argv-only, no shell) rather than reading
// /proc/*/stat directly -- much less code, and gives us the full command
// line in one call instead of a second read per PID.
std::vector<ProcSnapshot> list_processes();

// Filters `all` down to the processes belonging to one session: same TTY
// and same user, excluding PIDs already present in `known_pids` (which is
// then updated in place with every PID seen this round, so the same
// process is never reported as "new" twice).
std::vector<ProcSnapshot> poll_session(const std::vector<ProcSnapshot>& all,
                                        const std::string& tty,
                                        const std::string& user,
                                        std::set<int>& known_pids);

} // namespace loguard::procmon
