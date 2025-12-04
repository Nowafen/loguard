# Loguard

Real-time Telegram notifications for Linux logins (SSH, sudo, su, console, graphical).

## Features

- Offline queue + auto-retry (zero missed alerts)
- One-line install
- CLI management: `loguard status | enable | disable | test | logs | queue | edit | uninstall`
- Works on Ubuntu, Debian, Fedora, RHEL, Arch

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Nowafen/loguard/main/installer.sh)"
```

## Setup

1. Configure: `sudo loguard edit` (add Bot Token & Chat ID)
2. Test: `sudo loguard test`
3. Enable: `sudo loguard enable`

## Commands

| Command              | Description                  |
|----------------------|------------------------------|
| `loguard status`    | Show status                  |
| `loguard enable`    | Activate monitoring          |
| `loguard disable`   | Pause alerts                 |
| `loguard test`      | Send test message            |
| `loguard logs [n]`  | View recent alerts (default 20) |
| `loguard queue`     | Check pending alerts         |
| `loguard edit`      | Interactive config wizard    |
| `loguard uninstall` | Full removal                 |

## Telegram Setup

1. Message [@BotFather](https://t.me/BotFather): `/newbot`
2. Get token
3. Start your bot: `/start`
4. Get Chat ID: [@userinfobot](https://t.me/userinfobot)

## Locations

- Config: `/etc/loguard/config.toml`
- Logs: `/var/log/loguard/`
- Binary: `/opt/loguard/loguard`

## Security

- No external calls except Telegram API
- Local queue storage
- Fully auditable open-source code

## Uninstall

```bash
sudo loguard uninstall
```

[GitHub](https://github.com/Nowafen/loguard) | Author: Nowafen