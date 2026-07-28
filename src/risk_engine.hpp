#pragma once
#include "session.hpp"
#include <string>

namespace loguard::risk {

// Point values from the specification. Kept as named constants (not magic
// numbers scattered across main.cpp) so the scoring model has one place to
// tune.
inline constexpr int kSshLogin              = 10;
inline constexpr int kConsoleLogin          = 5;
inline constexpr int kNewCountrySeen        = 20; // first login ever seen from this country
inline constexpr int kSudo                  = 15;
inline constexpr int kSu                    = 10;
inline constexpr int kSuspiciousProcess     = 20; // default, pattern_matcher can override per-binary
inline constexpr int kReverseShell          = 100;
inline constexpr int kAuthorizedKeysTouched = 80;  // reserved for a future file-monitor module
inline constexpr int kSystemdServiceCreated = 70;  // reserved for a future file-monitor module
inline constexpr int kCronAdded             = 60;  // reserved for a future file-monitor module

inline constexpr int kHighRiskThreshold     = 100;

// Adds one scored entry to the session (updates risk_entries + timeline)
// and returns the session's running total after the addition.
int add(session::Session& s, const std::string& reason, int points);

// True once a session's score crosses kHighRiskThreshold -- callers use
// this to decide whether to fire an immediate "HIGH RISK" alert instead of
// waiting for the session summary.
bool crossed_high_risk(const session::Session& s);

// Has this (user, country) combination logged in before? Backed by a small
// on-disk set at /var/lib/loguard/sessions/seen_countries.list so the
// "new country" bonus only fires the first time, not every login.
bool is_new_country(const std::string& user, const std::string& country_code);

} // namespace loguard::risk