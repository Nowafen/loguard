#include "process_monitor.hpp"
#include "util.hpp"
#include <sstream>

namespace loguard::procmon {

namespace {
std::string basename_of(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}
} // namespace

std::vector<ProcSnapshot> list_processes() {
    std::vector<ProcSnapshot> out;
    std::string raw;
    int rc = util::run_capture({"ps", "-eo", "pid,ppid,tty,user:32,args", "--no-headers"}, &raw, 10);
    if (rc != 0 || raw.empty()) return out;

    std::istringstream in(raw);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        ProcSnapshot p;
        std::string pid_s, ppid_s;
        ls >> pid_s >> ppid_s >> p.tty >> p.user;
        if (pid_s.empty()) continue;
        try {
            p.pid = std::stoi(pid_s);
            p.ppid = std::stoi(ppid_s);
        } catch (...) { continue; }
        std::getline(ls, p.args);
        p.args = util::trim_str(p.args);
        std::string first_tok = p.args.substr(0, p.args.find(' '));
        p.comm = basename_of(first_tok);
        out.push_back(p);
    }
    return out;
}

std::vector<ProcSnapshot> poll_session(const std::vector<ProcSnapshot>& all,
                                        const std::string& tty,
                                        const std::string& user,
                                        std::set<int>& known_pids) {
    std::vector<ProcSnapshot> fresh;
    if (tty.empty() || tty == "?" || tty == "cron" || tty == "unknown") return fresh;

    for (auto& p : all) {
        if (p.tty != tty || p.user != user) continue;
        if (known_pids.count(p.pid)) continue;
        known_pids.insert(p.pid);
        fresh.push_back(p);
    }
    return fresh;
}

} // namespace loguard::procmon
