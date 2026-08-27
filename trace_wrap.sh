#!/usr/bin/env bash

set -euo pipefail

# Ensure script is run with sudo (required for tcpdump)
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run with sudo."
    echo "Usage: sudo $0 <command> [arguments...]"
    exit 1
fi

# Ensure a command was provided
if [ "$#" -lt 1 ]; then
    echo "Error: No command specified."
    echo "Usage: sudo $0 <command> [arguments...]"
    exit 1
fi

CMD=("$@")
RAND_ID=$((RANDOM % 10000))
LOG_DIR="trace_output_${RAND_ID}"

echo "Preparing output directory..."
mkdir -p "${LOG_DIR}"

# Cleanup function to stop tcpdump if the script is interrupted
cleanup() {
    if [ -n "${TCPDUMP_PID:-}" ] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
        kill "${TCPDUMP_PID}" 2>/dev/null || true
    fi
    echo "Done. Outputs saved in: ${LOG_DIR}/"
}
trap cleanup EXIT

# Get the real user ID who invoked sudo to filter network traffic
REAL_UID=${SUDO_UID:-0}

# Start tcpdump on all interfaces filtering by the user ID to reduce noise
echo "Starting network capture..."
tcpdump -i any -nn -w "${LOG_DIR}/traffic.pcap" "user ${REAL_UID}" 2>/dev/null &
TCPDUMP_PID=$!

# Brief pause to let tcpdump initialize
sleep 0.5

# Execute the process with strace
echo "Executing target command under strace..."
echo "--------------------------------------------------------"
strace -f -tt -T -x -o "${LOG_DIR}/syscalls.log" "${CMD[@]}" || true
echo "--------------------------------------------------------"
echo "Target process terminated."
