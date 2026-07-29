#pragma once
#include <string>

namespace loguard::deadman {

// Pings an external dead-man's-switch URL (e.g. a healthchecks.io check:
// https://hc-ping.com/<uuid>) via a plain HTTPS GET through curl.
//
// The point of this is NOT to alert on tamper -- it's the opposite: this
// machine says nothing when everything is fine, and the EXTERNAL service
// (not this host, not anything an on-box attacker controls) is the one
// that raises the alarm if a ping doesn't arrive within its configured
// grace period. That is what makes it survive a full-root compromise of
// this exact machine: disabling this switch quietly requires compromising
// the external service too, not just this box.
//
// Returns true if the ping was delivered (HTTP 2xx). A false return is
// logged by the caller but is not itself treated as a local tamper signal
// -- a dead-man's-switch provider being briefly unreachable is expected
// occasionally and is exactly what its own grace period exists to absorb.
bool ping(const std::string& url);

} // namespace loguard::deadman
