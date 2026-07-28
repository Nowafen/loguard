#include "session_queue.hpp"
#include "paths.hpp"
#include "util.hpp"

namespace loguard::session_queue {

namespace {
RawEvent parse_line(const std::string& line) {
    RawEvent e;
    if (auto v = util::json_field(line, "type")) e.type = *v;
    if (auto v = util::json_field(line, "session_id")) e.session_id = *v;
    if (auto v = util::json_field_int(line, "ts")) e.ts = *v;
    if (auto v = util::json_field(line, "user")) e.user = *v;
    if (auto v = util::json_field_int(line, "uid")) e.uid = *v;
    if (auto v = util::json_field_int(line, "gid")) e.gid = *v;
    if (auto v = util::json_field(line, "group")) e.group = *v;
    if (auto v = util::json_field(line, "service")) e.service = *v;
    if (auto v = util::json_field(line, "tty")) e.tty = *v;
    if (auto v = util::json_field(line, "hostname")) e.hostname = *v;
    if (auto v = util::json_field(line, "source_ip")) e.source_ip = *v;
    if (auto v = util::json_field(line, "auth_method")) e.auth_method = *v;
    if (auto v = util::json_field(line, "shell")) e.shell = *v;
    if (auto v = util::json_field(line, "home")) e.home = *v;
    e.remote = line.find("\"remote\":true") != std::string::npos;
    e.interactive = line.find("\"interactive\":true") != std::string::npos;
    return e;
}
} // namespace

std::vector<RawEvent> drain() {
    std::vector<RawEvent> out;
    auto lines = util::read_lines(paths::kSessionQueueFile);
    if (lines.empty()) return out;
    // Clear immediately so a slow daemon iteration never double-processes
    // events already read into memory (mirrors queue.cpp's rewrite pattern).
    util::write_file_atomic(paths::kSessionQueueFile, "", 0600);
    for (auto& line : lines) {
        if (line.find("\"type\"") == std::string::npos) continue;
        out.push_back(parse_line(line));
    }
    return out;
}

} // namespace loguard::session_queue
