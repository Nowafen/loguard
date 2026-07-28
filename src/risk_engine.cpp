#include "risk_engine.hpp"
#include "paths.hpp"
#include "util.hpp"

namespace loguard::risk {

int add(session::Session& s, const std::string& reason, int points) {
    session::RiskEntry e;
    e.reason = reason;
    e.points = points;
    s.risk_entries.push_back(e);
    s.add_timeline(reason + " (+" + std::to_string(points) + ")");
    return s.risk_score();
}

bool crossed_high_risk(const session::Session& s) {
    return s.risk_score() >= kHighRiskThreshold;
}

bool is_new_country(const std::string& user, const std::string& country_code) {
    if (country_code.empty()) return false;
    std::string key = user + ":" + country_code;
    for (auto& line : util::read_lines(paths::kSeenCountriesFile)) {
        if (line == key) return false;
    }
    util::append_line_locked(paths::kSeenCountriesFile, key);
    return true;
}

} // namespace loguard::risk
