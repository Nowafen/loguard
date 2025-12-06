#!/bin/bash
# Loguard Login Alert Script - DO NOT EDIT MANUALLY

CONFIG="/etc/loguard/config.toml"
QUEUE="/var/log/loguard/pending_alerts.jsonl"
LOG="/var/log/loguard/alert.log"

[[ -f "$CONFIG" ]] || exit 0
[[ "$PAM_TYPE" == "open_session" ]] || exit 0

# Load config
source <(grep -E '^(bot_token|chat_id|hostname) *=' "$CONFIG" | sed 's/ *= */=/g' 2>/dev/null || true)

[[ -z "$bot_token" || -z "$chat_id" ]] && exit 0

HOSTNAME="${hostname:-$(hostname)}"
USER="$PAM_USER"
SERVICE="${PAM_SERVICE:-unknown}"
FROM="${PAM_RHOST:-${SSH_CLIENT%% *}}"
[[ -z "$FROM" || "$FROM" == "?" ]] && FROM="local"
TTY="${PAM_TTY:-console}"
TIME="$(date '+%Y-%m-%d %H:%M:%S')"

# Clean message (no HTML tags in queue, only in final send)
MESSAGE="*New Login Detected*
Host: $HOSTNAME
User: $USER
Service: $SERVICE
From: $FROM
TTY: $TTY
Time: $TIME"

# Escape for JSON (manual, no jq needed)
escape_json() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g'
}

# Final HTML message for Telegram
HTML_MESSAGE="*New Login Detected*
Host: <code>$HOSTNAME</code>
User: <code>$USER</code>
Service: <code>$SERVICE</code>
From: <code>$FROM</code>
TTY: <code>$TTY</code>
Time: <code>$TIME</code>"

send_telegram() {
    curl -s -o /dev/null -w "%{http_code}" -m 10 \
        --data "chat_id=$chat_id" \
        --data "text=$HTML_MESSAGE" \
        --data "parse_mode=HTML" \
        "https://api.telegram.org/bot$bot_token/sendMessage" 2>/dev/null | grep -q "200"
}

# Ensure files exist
mkdir -p "$(dirname "$QUEUE")" "$(dirname "$LOG")"
touch "$QUEUE" "$LOG"

# Add to queue (clean JSON, no jq)
{
    ts=$(date +%s)
    escaped_msg=$(escape_json "$MESSAGE")
    printf '{"ts":%d,"user":"%s","service":"%s","from":"%s","tty":"%s","msg":"%s"}\n' \
        "$ts" "$USER" "$SERVICE" "$FROM" "$TTY" "$escaped_msg"
} >> "$QUEUE"

# Process queue
temp_queue=$(mktemp)
sent=0 failed=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if send_telegram; then
        echo "$TIME | SENT   | $USER | $SERVICE | $FROM | $TTY" >> "$LOG"
        ((sent++))
    else
        echo "$line" >> "$temp_queue"
        echo "$TIME | FAILED | $USER | $SERVICE | $FROM | $TTY" >> "$LOG"
        ((failed++))
    fi
done < "$QUEUE"

mv "$temp_queue" "$QUEUE" 2>/dev/null || rm -f "$temp_queue"
chmod 600 "$QUEUE"

# Summary
echo "$TIME | QUEUE  | Processed: $((sent + failed)), Sent: $sent, Pending: $failed" >> "$LOG"