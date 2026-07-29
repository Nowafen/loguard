#pragma once
#include <string>

namespace loguard::telegram {

// Sends `text` (HTML parse_mode) to the given chat via the Telegram Bot API.
// Implemented by spawning the system `curl` binary with an argv vector
// (never a shell string), so bot tokens / usernames / hostnames can never
// be used for shell injection, and we avoid depending on libcurl-dev
// headers being present at build time on every distro.
// Returns true on HTTP 200.
bool send_message(const std::string& bot_token,
                   const std::string& chat_id,
                   const std::string& html_text);

// Same as send_message, but also returns the sent message's numeric
// message_id (needed so a LATER call can delete this exact message --
// see delete_message below). Returns 0 if the send failed or the id
// could not be parsed out of Telegram's response.
long send_message_get_id(const std::string& bot_token,
                          const std::string& chat_id,
                          const std::string& html_text);

// Deletes a previously-sent message. Telegram allows a bot to delete its
// own messages (generally within 48 hours); used to remove the PREVIOUS
// heartbeat right before sending a new one, so heartbeats don't pile up
// in the chat. Failure (already deleted, too old, etc.) is non-fatal --
// callers should not treat a false return as an error worth alerting on.
bool delete_message(const std::string& bot_token,
                     const std::string& chat_id,
                     long message_id);

} // namespace loguard::telegram
