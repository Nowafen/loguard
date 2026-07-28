#include "geoip.hpp"
#include "paths.hpp"
#include "util.hpp"
#include <cstdint>

namespace loguard::geoip {

namespace {

bool is_private_ip(const std::string& ip) {
    if (ip.empty() || ip == "local" || ip == "127.0.0.1" || ip == "::1") return true;
    if (ip.rfind("10.", 0) == 0) return true;
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("172.", 0) == 0) {
        // 172.16.0.0 - 172.31.255.255
        auto parts = util::split(ip, '.');
        if (parts.size() > 1) {
            try {
                int second = std::stoi(parts[1]);
                if (second >= 16 && second <= 31) return true;
            } catch (...) {}
        }
    }
    if (ip.rfind("fc", 0) == 0 || ip.rfind("fd", 0) == 0) return true; // ULA IPv6
    return false;
}

// UTF-8 encode a single Unicode codepoint.
std::string utf8_encode(uint32_t cp) {
    std::string out;
    if (cp <= 0x7F) {
        out += char(cp);
    } else if (cp <= 0x7FF) {
        out += char(0xC0 | (cp >> 6));
        out += char(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        out += char(0xE0 | (cp >> 12));
        out += char(0x80 | ((cp >> 6) & 0x3F));
        out += char(0x80 | (cp & 0x3F));
    } else {
        out += char(0xF0 | (cp >> 18));
        out += char(0x80 | ((cp >> 12) & 0x3F));
        out += char(0x80 | ((cp >> 6) & 0x3F));
        out += char(0x80 | (cp & 0x3F));
    }
    return out;
}

std::string cache_lookup(const std::string& ip, GeoInfo& out) {
    for (auto& line : util::read_lines(paths::kGeoCacheFile)) {
        auto v = util::json_field(line, "ip");
        if (!v || *v != ip) continue;
        if (auto c = util::json_field(line, "country")) out.country = *c;
        if (auto c = util::json_field(line, "cc")) out.country_code = *c;
        if (auto c = util::json_field(line, "city")) out.city = *c;
        if (auto c = util::json_field(line, "isp")) out.isp = *c;
        out.ok = true;
        return line;
    }
    return "";
}

void cache_store(const std::string& ip, const GeoInfo& info) {
    std::string line = "{\"ip\":\"" + util::json_escape(ip) + "\","
        "\"country\":\"" + util::json_escape(info.country) + "\","
        "\"cc\":\"" + util::json_escape(info.country_code) + "\","
        "\"city\":\"" + util::json_escape(info.city) + "\","
        "\"isp\":\"" + util::json_escape(info.isp) + "\"}";
    util::append_line_locked(paths::kGeoCacheFile, line);
}

} // namespace

GeoInfo lookup(const std::string& ip) {
    GeoInfo info;
    if (is_private_ip(ip)) {
        info.is_private = true;
        info.ok = true;
        return info;
    }

    if (!cache_lookup(ip, info).empty()) return info;

    std::string url = "https://ip-api.com/json/" + ip +
        "?fields=status,country,countryCode,city,isp,query";
    std::string json;
    int rc = util::run_capture({"curl", "-s", "--max-time", "6", url}, &json, 8);
    if (rc != 0 || json.empty()) return info; // ok stays false -- caller shows "unknown"

    auto status = util::json_field(json, "status");
    if (!status || *status != "success") return info;

    if (auto v = util::json_field(json, "country")) info.country = *v;
    if (auto v = util::json_field(json, "countryCode")) info.country_code = *v;
    if (auto v = util::json_field(json, "city")) info.city = *v;
    if (auto v = util::json_field(json, "isp")) info.isp = *v;
    info.ok = true;

    cache_store(ip, info);
    return info;
}

std::string flag_emoji(const std::string& country_code) {
    if (country_code.size() != 2) return "";
    char a = toupper(country_code[0]), b = toupper(country_code[1]);
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return "";
    uint32_t base = 0x1F1E6;
    return utf8_encode(base + (a - 'A')) + utf8_encode(base + (b - 'A'));
}

} // namespace loguard::geoip
