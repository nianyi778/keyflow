#!/bin/zsh

set -eu

export HOME="/Users/likai"
export KEYFLOW_DATA_DIR="/Users/likai/Library/Application Support/keyflow"

LOG_FILE="/tmp/keyflow-claude-mcp.log"

exec 2>>"$LOG_FILE"

print -r -- "[$(date '+%Y-%m-%d %H:%M:%S')] starting keyflow mcp wrapper" >&2
print -r -- "cwd=$PWD" >&2
print -r -- "HOME=$HOME" >&2
print -r -- "KEYFLOW_DATA_DIR=$KEYFLOW_DATA_DIR" >&2

exec /Users/likai/.cargo/bin/kf serve
