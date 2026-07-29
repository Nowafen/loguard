# Loguard
## Real-Time Linux Login Alerts to Telegram

Loguard is a minimal, tamper-resistant login monitor for Linux that delivers **instant Telegram notifications** whenever anyone logs in via SSH, console, sudo, su, or graphical login. It's designed for cloud servers, home labs, and production systems where every unauthorized login attempt needs to be caught *immediately*.


## 🚀 Quick Start

### Create a Telegram Bot

```bash
# Message @BotFather on Telegram:
/newbot

# Name your bot (e.g., "My Server Monitor") and copy the Bot Token
# Start a chat with your new bot: /start

# Get your Chat ID by messaging @userinfobot
```

### Install Loguard

```bash
# One-liner (downloads and installs from GitHub):
curl -fsSL https://raw.githubusercontent.com/Nowafen/Loguard/main/install.sh | sudo bash
```

### Or clone and install locally:

```bash
git clone https://github.com/Nowafen/Loguard.git
cd Loguard
sudo bash install.sh
```

During installation, you'll be prompted for:
- **Bot Token** — from @BotFather
- **Chat ID** — from @userinfobot (a number like `123456789`)
- **Device label** — how you want this server identified in alerts (e.g., "prod-db-1")

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
