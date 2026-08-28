#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run with sudo."
    echo "Usage: sudo $0 {shell | <command> [arguments...]}"
    exit 1
fi

if [ "$#" -lt 1 ]; then
    echo "Usage:"
    echo "  sudo $0 shell                     # Opens a traced interactive dev-shell"
    echo "  sudo $0 <command> [arguments...]  # Traces a single command execution"
    exit 1
fi

BIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="$1"

if [ "$MODE" == "shell" ]; then
    if ! command -v tmux &>/dev/null; then
        echo "Error: tmux is required for interactive shell mode."
        exit 1
    fi

    RAND_ID=$((RANDOM % 10000))
    LOG_DIR="/tmp/trace_output_${RAND_ID}"
    mkdir -p "${LOG_DIR}"

    STRACE_FIFO="${LOG_DIR}/strace.fifo"
    TCPDUMP_FIFO="${LOG_DIR}/tcpdump.fifo"
    mkfifo "${STRACE_FIFO}" "${TCPDUMP_FIFO}"

    SESSION_NAME="trace_shell_${RAND_ID}"

    echo "Starting background network capture..."
    tcpdump -i any -nn -l 'tcp or udp' 2>/dev/null > "${TCPDUMP_FIFO}" &
    TCPDUMP_PID=$!

    echo "Launching interactive dev-shell in tmux..."
    tmux new-session -d -s "${SESSION_NAME}"

    ENV_PS1="\[\e[32m\](trace-shell)\[\e[0m\] \u@\h:\w# "
    tmux send-keys -t "${SESSION_NAME}" \
      "strace -f -tt -T -e trace=file,network,process -o '${STRACE_FIFO}' bash --rcfile <(echo \"export PS1='${ENV_PS1}'\")" C-m

    tmux split-window -v -t "${SESSION_NAME}" -p 40
    tmux send-keys -t "${SESSION_NAME}" "${BIN_DIR}/trace_wrap_tui.sh '${STRACE_FIFO}' '${TCPDUMP_FIFO}'" C-m

    tmux select-pane -t "${SESSION_NAME}" -U

    cleanup_shell() {
        kill "${TCPDUMP_PID}" 2>/dev/null || true
        rm -rf "${LOG_DIR}"
    }
    trap cleanup_shell EXIT

    tmux attach-session -t "${SESSION_NAME}"
    exit 0
fi

# --- Modalità Singolo Comando (Fall-through) ---
CMD=("$@")
RAND_ID=$((RANDOM % 10000))
LOG_DIR="trace_output_${RAND_ID}"

echo "Preparing output directory..."
mkdir -p "${LOG_DIR}"

echo "Starting network capture..."
tcpdump -i any -nn -w "${LOG_DIR}/raw_traffic.pcap" 2>/dev/null &
TCPDUMP_PID=$!

cleanup_cmd() {
    if [ -n "${TCPDUMP_PID:-}" ] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
        kill "${TCPDUMP_PID}" 2>/dev/null || true
    fi
    if [ -f "${LOG_DIR}/raw_traffic.pcap" ]; then
        mv "${LOG_DIR}/raw_traffic.pcap" "${LOG_DIR}/traffic.pcap"
    fi
    echo "Done. Outputs saved in: ${LOG_DIR}/"
}
trap cleanup_cmd EXIT

sleep 0.5

echo "Executing target command under strace..."
echo "--------------------------------------------------------"
strace -f -tt -T -x -o "${LOG_DIR}/syscalls.log" "${CMD[@]}" || true
echo "--------------------------------------------------------"
echo "Target process terminated.""
