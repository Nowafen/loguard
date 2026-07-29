# Loguard
## Real-Time Linux Login Alerts to Telegram

Loguard is a minimal, tamper-resistant login monitor for Linux that delivers **instant Telegram notifications** whenever anyone logs in via SSH, console, sudo, su, or graphical login. It's designed for cloud servers, home labs, and production systems where every unauthorized login attempt needs to be caught *immediately*.


## Quick Start
### Create a Telegram Bot

```bash
# Message @BotFather on Telegram:
/newbot

# Name your bot (e.g., "My Server Monitor") and copy the Bot Token
# Start a chat with your new bot: /start
# Get your Chat ID by messaging @userinfobot
```

### Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Nowafen/Loguard/main/install.sh | sudo bash
```

During installation, you'll be prompted for:
- **Bot Token** — from @BotFather
- **Chat ID** — from @userinfobot (a number like `123456789`)
- **Device label** — how you want this server identified in alerts (e.g., "prod-db-1")

---

## Troubleshooting

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


---

## 🔄 Updates

Loguard can self-update from GitHub:

```bash
sudo loguard update
```

---

**Happy monitoring!**
