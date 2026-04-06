#!/bin/bash
set -euo pipefail

source .env

BUNDLE_ID="com.netflix.Netflix"
SCRIPT="${1:-hook_netflix.js}"

# Get PID of Netflix from remote device
HOST="${IOS_HOST:-192.168.0.34}"
PID=$(frida-ps -H "$HOST" -a 2>/dev/null | grep "$BUNDLE_ID" | awk '{print $1}')

if [ -z "$PID" ]; then
    echo "Netflix is not running on $HOST"
    echo "Please launch Netflix on the device first."
    exit 1
fi

echo "Found Netflix (PID: $PID) on $HOST"
echo "Attaching with script: $SCRIPT"

frida -p "$PID" -l "$SCRIPT" -H "$HOST"
