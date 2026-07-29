#pragma once
#include <string>

namespace loguard::immutable {

// Sets or clears the ext2/3/4 "immutable" (+i) attribute via `chattr`.
// While set, even root cannot write, truncate, delete, or rename the file
// without first clearing the flag -- a real (if not absolute) speed bump
// against `rm`, a text editor, or a script that overwrites the file in
// place. Best-effort: filesystems that don't support extended attributes
// (tmpfs, some overlay/container setups) will simply fail here, silently,
// since this is a defense-in-depth layer, not the primary security
// boundary (nothing in Loguard depends on this succeeding).
bool set(const std::string& path, bool on);

// True if the +i attribute is currently present on `path`.
bool is_set(const std::string& path);

// Applies +i to both binaries and every PAM file currently carrying the
// hook (per pam::active_files()). Called at the end of `loguard enable`
// and again after every self-heal.
void protect_all();

// Clears +i from both binaries and EVERY candidate PAM file (not just the
// currently-active ones, in case a stale immutable flag survived a manifest
// change) so that legitimate operations -- disable, restart, update,
// uninstall, or the self-heal rewrite -- can actually modify the files.
// Always call this before writing to a file that protect_all() may have
// touched.
void unprotect_all();

} // namespace loguard::immutable
