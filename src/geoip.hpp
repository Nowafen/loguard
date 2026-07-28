#pragma once
#include <string>

namespace loguard::geoip {

struct GeoInfo {
    std::string country;      // e.g. "Germany"
    std::string country_code; // e.g. "DE" -- used to pick a flag emoji
    std::string city;         // e.g. "Frankfurt"
    std::string isp;          // e.g. "Hetzner Online GmbH"
    bool is_private = false;  // RFC1918 / loopback -- no lookup performed
    bool ok = false;          // true if we have real data (private counts as ok)
};

// Looks up `ip` via a free, keyless GeoIP API (ip-api.com) over HTTPS using
// curl (same subprocess approach as telegram.cpp -- no libcurl dependency).
// Results are cached on disk (paths::kGeoCacheFile) since ip-api.com is
// rate-limited (45 req/min) and the same attacker/IP often reconnects.
// Private/loopback IPs are detected locally and never sent out.
// Never throws; on any failure returns GeoInfo with ok=false.
GeoInfo lookup(const std::string& ip);

// Returns a flag emoji for a 2-letter ISO country code, or "" if unknown.
std::string flag_emoji(const std::string& country_code);

} // namespace loguard::geoip