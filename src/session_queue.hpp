#pragma once
#include <string>
#include <vector>

namespace loguard::session_queue {

struct RawEvent {
    std::string type; // "session_start" | "session_end"
    std::string session_id;
    long ts = 0;

    // Only populated for "session_start"
    std::string user;
    long uid = -1, gid = -1;
    std::string group;
    std::string service, tty, hostname, source_ip, auth_method, shell, home;
    bool remote = false;
    bool interactive = false;
};

// Reads and CLEARS the events file (paths::kSessionQueueFile) atomically,
// same pattern as queue.cpp: the daemon owns draining this file so the
// PAM hook (writer) and daemon (reader) never race past the flock.
std::vector<RawEvent> drain();

} // namespace loguard::session_queue