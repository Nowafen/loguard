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
    local response
    response=$(curl -s -w "%{http_code}" -m 10 --data "chat_id=$chat_id" --data "text=$text" --data "parse_mode=HTML" \
         "https://api.telegram.org/bot$bot_token/sendMessage" 2>/dev/null)
    local http_code="${response: -3}"
    [[ "$http_code" == "200" ]]  # Check HTTP 200 OK
}

hostname=${hostname:-$(hostname)}
time=$(date '+%Y-%m-%d %H:%M:%S')
ip=${PAM_RHOST:-${SSH_CLIENT%% *}}
[[ "$ip" == "?" || -z "$ip" ]] && ip="local"
service=${PAM_SERVICE:-unknown}

msg="*Login Alert*%0A%F0%9F%94%B8 Host: <code>$hostname</code>%0A%F0%9F%91%A4 User: <code>$PAM_USER</code>%0A%F0%9F%94%87 Service: <code>$service</code>%0A%F0%9F%94H From: <code>$ip</code>%0A%F0%9F%96%A5 TTY: <code>${PAM_TTY:-console}</code>%0A%F0%9F%95%90 Time: <code>$time</code>"

timestamp=$(date +%s)
echo "{\"ts\": $timestamp, \"msg\": $(printf '%s' "$msg" | jq -Rs .)}" >> "$QUEUE"

temp_file=$(mktemp)
processed=0
sent=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    msg=$(echo "$line" | jq -r '.msg')
    
    if send_telegram "$msg"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') SENT $PAM_USER $service $ip $PAM_TTY" >> "$LOG"
        ((sent++))
    else
        echo "$line" >> "$temp_file"
        echo "$(date '+%Y-%m-%d %H:%M:%S') FAILED $PAM_USER $service $ip $PAM_TTY" >> "$LOG"
    fi
    ((processed++))
done < "$QUEUE"

mv "$temp_file" "$QUEUE" 2>/dev/null || rm -f "$temp_file"
chmod 600 "$QUEUE"

# Log summary
echo "$(date '+%Y-%m-%d %H:%M:%S') PROCESSED $processed (SENT $sent)" >> "$LOG"