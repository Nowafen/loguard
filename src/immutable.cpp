#include "immutable.hpp"
#include "paths.hpp"
#include "pam.hpp"
#include "util.hpp"

namespace loguard::immutable {

bool set(const std::string& path, bool on) {
    if (!util::file_exists(path)) return false;
    std::string out;
    int rc = util::run_capture({"chattr", on ? "+i" : "-i", path}, &out, 10);
    return rc == 0;
}

bool is_set(const std::string& path) {
    if (!util::file_exists(path)) return false;
    std::string out;
    int rc = util::run_capture({"lsattr", path}, &out, 10);
    if (rc != 0 || out.empty()) return false;
    auto sp = out.find(' ');
    if (sp == std::string::npos) return false;
    return out.substr(0, sp).find('i') != std::string::npos;
}

void protect_all() {
    set(paths::kMainBinary, true);
    set(paths::kHookBinary, true);
    for (auto& f : pam::active_files()) set(f, true);
}

void unprotect_all() {
    set(paths::kMainBinary, false);
    set(paths::kHookBinary, false);
    // Sweep every candidate file, not just currently-active ones, in case
    // the manifest changed since the flag was applied.
    for (auto& f : pam::candidate_files()) set(f, false);
}

} // namespace loguard::immutable
