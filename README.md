# Loguard - Real-time Linux Login Alerts to Telegram

Instantly get notified on Telegram whenever anyone logs into your server — SSH, console, sudo, su, graphical login — everything.

- Zero missed alerts (works offline with queue + retry)
- One-line installation
- Full control with `loguard` command
- 100% open source & transparent
- Works on Ubuntu, Debian, AlmaLinux, Rocky, Fedora, Arch

<img src="https://github.com/Nowafen/loguard/assets/photo.png" alt="Loguard Alert Example" width="400"/>

## One-line Installation

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Nowafen/loguard/main/installer.sh)"
```

## After Installation

1. Edit config:
   ```bash
   sudo loguard edit
   ```
2. Add your Telegram Bot Token and Chat ID
3. Test it:
   ```bash
   sudo loguard test
   ```
4. Enable monitoring:
   ```bash
   sudo loguard enable
   ```

## Available Commands

```bash
sudo loguard              # Show status (same as 'status')
sudo loguard status       # Full system status
sudo loguard enable       # Turn on login monitoring
sudo loguard disable      # Temporarily pause alerts
sudo loguard test         # Send test message
sudo loguard logs         # Show recent login alerts
sudo loguard logs 50      # Show last 50 alerts
sudo loguard queue        # Show pending (unsent) alerts
sudo loguard clear-queue  # Clear pending queue
sudo loguard edit         # Open config in editor
sudo loguard restart      # Re-apply PAM rules
sudo loguard uninstall    # Completely remove Loguard
```

## Get Telegram Bot

1. Talk to [@BotFather](https://t.me/BotFather)
2. Send `/newbot` and follow instructions
3. Copy the token
4. Start bot and send `/start`
5. Get your Chat ID: https://t.me/userinfobot

## Files Location

- Config: `/etc/loguard/config.toml`
- Logs: `/var/log/loguard/`
- Main binary: `/opt/loguard/loguard`

## Security & Privacy

- No external servers
- No data collection
- All code is public and auditable
- Queue stored locally, never lost

## Uninstall (if you ever need to)

```bash
sudo loguard uninstall
```

## Author

Nowafen – exploit developer
GitHub: https://github.com/Nowafen/loguard

---

Created by [MNM](https://x.com/Nowafen) 
