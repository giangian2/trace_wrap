#!/usr/bin/env bash
set -euo pipefail

STRACE_FIFO="${1:-}"
TCPDUMP_FIFO="${2:-}"

if [ -z "$STRACE_FIFO" ] || [ -z "$TCPDUMP_FIFO" ]; then
    echo "Usage: $0 <strace_fifo> <tcpdump_fifo>"
    exit 1
fi

BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER_BIN="${BIN_DIR}/trace_wrap_c_filter"

if [ ! -x "$FILTER_BIN" ]; then
    FILTER_BIN="trace_wrap_c_filter"
fi

tput civis
clear

cleanup_tui() {
    tput cnorm
    clear
}
trap cleanup_tui EXIT

draw_layout() {
    LINES=$(tput lines)
    COLS=$(tput cols)
    HALF=$((LINES / 2))

    tput cup $HALF 0
    printf '─'%.0s $(seq 1 "$COLS")
    tput cup $HALF 2
    echo -e " \e[1;33m[ CRITICAL SYSCALLS & ERRORS ]\e[0m "

    tput cup 0 2
    echo -e " \e[1;36m[ NETWORK LIVE TRAFFIC (SYS & RAW) ]\e[0m "
}

draw_layout

NET_ROW=1
SYS_ROW=$(( (LINES / 2) + 1 ))
MAX_NET_ROW=$(( (LINES / 2) - 1 ))
MAX_SYS_ROW=$(( LINES - 2 ))

"$FILTER_BIN" "$STRACE_FIFO" "$TCPDUMP_FIFO" | while IFS= read -r line; do
    COLS=$(tput cols)
    TRUNC_LINE="${line:0:$((COLS - 2))}"

    if [[ "$line" == "[SYS_NET]"* ]]; then
        tput cup $NET_ROW 0; tput el
        echo -e "\e[1;32m${TRUNC_LINE}\e[0m"
        ((NET_ROW++))
    elif [[ "$line" == "[RAW_NET]"* ]]; then
        tput cup $NET_ROW 0; tput el
        echo -e "\e[36m${TRUNC_LINE}\e[0m"
        ((NET_ROW++))
    elif [[ "$line" == "[ERR]"* ]] || [[ "$line" == "[SYS]"* ]]; then
        tput cup $SYS_ROW 0; tput el
        if [[ "$line" == "[ERR]"* ]]; then
            echo -e "\e[1;31m${TRUNC_LINE}\e[0m"
        else
            echo -e "\e[37m${TRUNC_LINE}\e[0m"
        fi
        ((SYS_ROW++))
    fi

    if [ "$NET_ROW" -gt "$MAX_NET_ROW" ]; then NET_ROW=1; fi
    if [ "$SYS_ROW" -gt "$MAX_SYS_ROW" ]; then SYS_ROW=$(( (LINES / 2) + 1 )); fi
done
