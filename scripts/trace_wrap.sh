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

    if [ ! -t 0 ] || [ ! -t 1 ]; then
        echo "Error: shell mode needs an interactive terminal (stdin/stdout are not a tty)."
        exit 1
    fi

    # sudo strips $TMUX, so a nested tmux would start unnoticed and the OUTER
    # server would swallow every Ctrl-b. Walk the process tree to catch it.
    running_inside_tmux() {
        [ -n "${TMUX:-}" ] && return 0
        local pid=$PPID stat rest
        while [ "${pid:-0}" -gt 1 ]; do
            [ -r "/proc/${pid}/comm" ] || return 1
            case "$(cat "/proc/${pid}/comm")" in tmux*) return 0 ;; esac
            stat=$(cat "/proc/${pid}/stat" 2>/dev/null) || return 1
            rest=${stat#*") "}
            # shellcheck disable=SC2086
            set -- $rest
            pid=$2
        done
        return 1
    }

    NESTED=0
    if running_inside_tmux; then
        NESTED=1
        echo "Warning: you are already inside tmux. Use F9 / F10 to move between"
        echo "         panes - Ctrl-b would be swallowed by the outer session."
        sleep 2
    fi

    RAND_ID=$((RANDOM % 10000))
    LOG_DIR="/tmp/trace_output_${RAND_ID}"
    mkdir -p "${LOG_DIR}"

    STRACE_FIFO="${LOG_DIR}/strace.fifo"
    mkfifo "${STRACE_FIFO}"

    SESSION_NAME="trace_shell_${RAND_ID}"

    echo "Launching interactive dev-shell in tmux..."
    tmux new-session -d -s "${SESSION_NAME}"

    ENV_PS1="\[\e[32m\](trace-shell)\[\e[0m\] \u@\h:\w# "
    tmux send-keys -t "${SESSION_NAME}" \
      "strace -f -tt -T -yy -e trace=file,network,process,desc -o '${STRACE_FIFO}' bash --rcfile <(echo \"export PS1='${ENV_PS1}'\")" C-m

    # tmux >= 3.4 dropped -p in favour of -l <n>%; keep both for older tmux
    tmux split-window -v -t "${SESSION_NAME}" -l 40% 2>/dev/null \
      || tmux split-window -v -t "${SESSION_NAME}" -p 40
    tmux send-keys -t "${SESSION_NAME}" "${BIN_DIR}/trace_wrap_mon '${STRACE_FIFO}'" C-m

    tmux select-pane -t "${SESSION_NAME}" -U

    # Prefix-free pane switching: works even when this tmux is nested inside
    # another one, where Ctrl-b belongs to the outer server.
    # F9/F10 are plain CSI sequences every terminal agrees on; Alt+arrow
    # depends on the emulator, so it is offered as a convenience only.
    tmux bind-key -n F9      select-pane -U
    tmux bind-key -n F10     select-pane -D
    tmux bind-key -n M-Up    select-pane -U
    tmux bind-key -n M-Down  select-pane -D
    tmux bind-key -n M-Left  select-pane -U
    tmux bind-key -n M-Right select-pane -D
    # without this tmux waits half a second before deciding an ESC is a Meta
    # prefix, which is what usually breaks Alt+key bindings
    tmux set-option -g escape-time 10

    tmux set-option -t "${SESSION_NAME}" status-left  ""
    tmux set-option -t "${SESSION_NAME}" status-right ""
    tmux set-option -t "${SESSION_NAME}" status-style "bg=colour238,fg=colour252"
    tmux set-option -t "${SESSION_NAME}" status-justify centre
    tmux set-option -t "${SESSION_NAME}" window-status-format ""
    tmux set-option -t "${SESSION_NAME}" window-status-current-format \
        "F9 = traced shell (top)   |   F10 = monitor (bottom)   |   'exit' above to quit"

    # Leaving either pane tears the whole session down, so exiting the traced
    # shell returns from attach-session and lets the EXIT trap clean up.
    tmux set-hook -t "${SESSION_NAME}" pane-exited "kill-session -t ${SESSION_NAME}" 2>/dev/null || true

    cleanup_shell() {
        tmux kill-session -t "${SESSION_NAME}" 2>/dev/null || true
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
strace -f -tt -T -x -yy -o "${LOG_DIR}/syscalls.log" "${CMD[@]}" || true
echo "--------------------------------------------------------"
echo "Target process terminated."
