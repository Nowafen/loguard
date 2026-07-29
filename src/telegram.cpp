#include "telegram.hpp"
#include "util.hpp"
#include <vector>

namespace loguard::telegram {

bool send_message(const std::string& bot_token,
                   const std::string& chat_id,
                   const std::string& html_text) {
    if (bot_token.empty() || chat_id.empty()) return false;

    std::string url = "https://api.telegram.org/bot" + bot_token + "/sendMessage";
    std::vector<std::string> argv = {
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10",
        "--data-urlencode", "chat_id=" + chat_id,
        "--data-urlencode", "text=" + html_text,
        "--data-urlencode", "parse_mode=HTML",
        url
    };

    std::string out;
    int rc = util::run_capture(argv, &out, 15);
    if (rc != 0) return false; // curl itself failed to run/exec/exit nonzero
    return out.find("200") != std::string::npos;
}

long send_message_get_id(const std::string& bot_token,
                          const std::string& chat_id,
                          const std::string& html_text) {
    if (bot_token.empty() || chat_id.empty()) return 0;

    std::string url = "https://api.telegram.org/bot" + bot_token + "/sendMessage";

    // Unlike the old send_message, we need the actual response BODY this
    // time (to read back "message_id"), not just the HTTP status code, so
    // no -o /dev/null here.
    std::vector<std::string> argv = {
        "curl", "-s", "--max-time", "10",
        "--data-urlencode", "chat_id=" + chat_id,
        "--data-urlencode", "text=" + html_text,
        "--data-urlencode", "parse_mode=HTML",
        url
    };

    std::string out;
    int rc = util::run_capture(argv, &out, 15);
    if (rc != 0 || out.empty()) return 0;
    if (out.find("\"ok\":true") == std::string::npos) return 0;

    auto id = util::json_field_int(out, "message_id");
    return id.value_or(0);
}

bool delete_message(const std::string& bot_token,
                     const std::string& chat_id,
                     long message_id) {
    if (bot_token.empty() || chat_id.empty() || message_id <= 0) return false;

    std::string url = "https://api.telegram.org/bot" + bot_token + "/deleteMessage";
    std::vector<std::string> argv = {
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10",
        "--data-urlencode", "chat_id=" + chat_id,
        "--data-urlencode", "message_id=" + std::to_string(message_id),
        url
    };

    std::string out;
    int rc = util::run_capture(argv, &out, 15);
    if (rc != 0) return false;
    return out.find("200") != std::string::npos;
}

} // namespace loguard::telegram
