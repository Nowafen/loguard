#include "deadman.hpp"
#include "util.hpp"

namespace loguard::deadman {

bool ping(const std::string& url) {
    if (url.empty()) return false;
    std::string out;
    // Same pattern as telegram.cpp: -w prints the HTTP status code to
    // stdout (captured), -o discards the body. No -f flag, since -f can
    // suppress the -w output on error responses on some curl builds.
    int rc = util::run_capture(
        {"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", url},
        &out, 15);
    if (rc != 0) return false;
    return out.find("200") != std::string::npos;
}

} // namespace loguard::deadman
