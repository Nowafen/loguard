#!/bin/bash
# Loguard Login Alert Script - DO NOT EDIT MANUALLY
CONFIG="/etc/loguard/config.toml"
QUEUE="/var/log/loguard/pending_alerts.jsonl"
LOG="/var/log/loguard/alert.log"

[[ -f "$CONFIG" ]] || exit 0
source <(grep = "$CONFIG" | sed 's/ *= */=/g')

[[ "$PAM_TYPE" != "open_session" ]] && exit 0

mkdir -p "$(dirname "$QUEUE")" "$(dirname "$LOG")"
touch "$QUEUE"

send_telegram() {
    local text="$1"
    curl -s -m 10 --data "chat_id=$chat_id" --data "text=$text" --data "parse_mode=HTML" \
         "https://api.telegram.org/bot$bot_token/sendMessage" > /dev/null 2>&1
}

hostname=${hostname:-$(hostname)}
time=$(date '+%Y-%m-%d %H:%M:%S')
ip=${PAM_RHOST:-${SSH_CLIENT%% *}}
[[ "$ip" == "?" || -z "$ip" ]] && ip="local"

msg="*Login Alert*%0A%F0%9F%94%B8 Host: <code>$hostname</code>%0A%F0%9F%91%A4 User: <code>$PAM_USER</code>%0A%F0%9F%94H From: <code>$ip</code>%0A%F0%9F%96%A5 TTY: <code>$PAM_TTY</code>%0A%F0%9F%95%90 Time: <code>$time</code>"

echo "{\"time\": $(date +%s), \"msg\": \"$msg\"}" >> "$QUEUE"

while IFS= read -r line; do
    msg=$(echo "$line" | jq -r .msg)
    if send_telegram "$msg"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') SENT: $PAM_USER from $ip" >> "$LOG"
    else
        echo "$line" >> "$QUEUE.tmp"
    fi
done < "$QUEUE"
mv "$QUEUE.tmp" "$QUEUE" 2>/dev/null || rm -f "$QUEUE.tmp"
chmod 600 "$QUEUE"
