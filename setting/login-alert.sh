#!/bin/bash
# Loguard Login Alert Script - DO NOT EDIT MANUALLY
# Called by PAM on every successful login

CONFIG="/etc/loguard/config.toml"
QUEUE="/var/log/loguard/pending_alerts.jsonl"
LOG="/var/log/loguard/alert.log"

# Exit if config missing or not a session open
[[ -f "$CONFIG" ]] || exit 0
[[ "$PAM_TYPE" == "open_session" ]] || exit 0

# Load config
source <(grep -E '^(bot_token|chat_id|hostname) *=' "$CONFIG" | sed 's/ *= */=/g' 2>/dev/null || true)

BOT_TOKEN="${bot_token:-}"
CHAT_ID="${chat_id:-}"
HOSTNAME="${hostname:-$(hostname)}"

# Skip if no token/chat_id
[[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]] && exit 0

# Gather login info
USER="$PAM_USER"
SERVICE="${PAM_SERVICE:-unknown}"
RHOST="${PAM_RHOST:-${SSH_CLIENT%% *}}"
[[ -z "$RHOST" || "$RHOST" == "?" ]] && RHOST="local"
TTY="${PAM_TTY:-console}"
TIME="$(date '+%Y-%m-%d %H:%M:%S')"

# Build clean, human-readable message
MESSAGE="*New Login Detected*
Host: <code>$HOSTNAME</code>
User: <code>$USER</code>
Service: <code>$SERVICE</code>
From: <code>$RHOST</code>
TTY: <code>$TTY</code>
Time: <code>$TIME</code>"

# Send to Telegram (returns true on HTTP 200)
send_telegram() {
    local text="$1"
    local resp
    resp=$(curl -s -o /dev/null -w "%{http_code}" -m 10 \
        --data "chat_id=$CHAT_ID" \
        --data "text=$text" \
        --data "parse_mode=HTML" \
        "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" 2>/dev/null)
    [[ "$resp" == "200" ]]
}

# Ensure directories exist
mkdir -p "$(dirname "$QUEUE")" "$(dirname "$LOG")"
touch "$QUEUE" "$LOG"

# Add new alert to queue
printf '%s\n' "{\"ts\":$(date +%s),\"user\":\"$USER\",\"service\":\"$SERVICE\",\"from\":\"$RHOST\",\"tty\":\"$TTY\",\"msg\":$(printf '%s' "$MESSAGE" | jq -R .)}" >> "$QUEUE"

# Process entire queue
temp_queue=$(mktemp)
sent_count=0
failed_count=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    msg=$(echo "$line" | jq -r '.msg')
    user=$(echo "$line" | jq -r '.user')
    service=$(echo "$line" | jq -r '.service')
    from=$(echo "$line" | jq -r '.from')
    tty=$(echo "$line" | jq -r '.tty')

    if send_telegram "$msg"; then
        echo "$TIME | SENT   | $user | $service | $from | $tty" >> "$LOG"
        ((sent_count++))
    else
        echo "$line" >> "$temp_queue"
        echo "$TIME | FAILED | $user | $service | $from | $tty" >> "$LOG"
        ((failed_count++))
    fi
done < "$QUEUE"

# Replace queue with only failed ones
mv "$temp_queue" "$QUEUE" 2>/dev/null || rm -f "$temp_queue"
chmod 600 "$QUEUE"

# Summary log
echo "$TIME | QUEUE  | Processed: $((sent_count + failed_count)), Sent: $sent_count, Pending: $failed_count" >> "$LOG"