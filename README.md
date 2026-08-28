# 🔍 trace_wrap

**`trace_wrap`** is a lightweight, high-performance tool designed for developers who need real-time visibility into network traffic and system calls (syscalls) without the noise of traditional tracing tools.

It delivers an interactive terminal workspace (**Traced Dev-Shell**) powered by `tmux` alongside a low-noise, high-contrast TUI that isolates failed syscalls, active socket connections, and network packets live.

---

## ⚡ Key Features

* **Traced Dev-Shell:** Spawns an interactive sub-shell where every executed command is monitored automatically in the background.
* **Low-Noise TUI:** Real-time split display focusing strictly on **Network Events** (socket calls + raw pcap packets) and **Critical Syscalls/Errors** (e.g., missing files, permission issues).
* **Lightweight C Aggregator:** A fast C micro-filter strips high-frequency background noise (`futex`, `epoll_wait`, `clock_gettime`), keeping CPU and RAM consumption close to zero.
* **Single-Command Tracing:** Supports quick tracing and output exporting (`.pcap` / `.log`) for a single target binary or script.
* **Zero Heavy Dependencies:** Built using native **Bash, C, `strace`, `tcpdump`, and `tmux`**.

---

## 📋 System Requirements

To run `trace_wrap`, ensure your Linux environment has the following packages installed:

* `gcc` & `make` (to build the C filter)
* `strace`
* `tcpdump`
* `tmux` (required for interactive `shell` mode)
* `root` / `sudo` privileges (required by `strace` and network interface packet capture)

On Debian/Ubuntu-based distributions, install them via:
```bash
sudo apt update
sudo apt install build-essential strace tcpdump tmux

```

---

## 🛠️ Installation

1. Clone the repository:
```bash
git clone [https://github.com/giangian2/trace_wrap.git](https://github.com/giangian2/trace_wrap.git)
cd trace_wrap

```


2. Compile the C aggregator and install binaries system-wide (defaults to `/usr/local/bin`):
```bash
make
sudo make install

```



*(To uninstall at any time: `sudo make uninstall`)*

---

## 🚀 Usage

### 1. Interactive Traced Dev-Shell (Recommended)

Launches a monitored sub-shell inside a split `tmux` window:

```bash
sudo trace_wrap shell

```

* **Top Pane:** Your interactive shell identified by the `(trace-shell)` prompt. Run any command, script, or `curl` request here.
* **Bottom Pane:** Real-time TUI dashboard displaying active connections and failed system calls.

To exit the dev-shell, simply type `exit`.

---

### 2. Single Command Mode

To trace a one-off execution and save full logs for offline analysis:

```bash
sudo trace_wrap curl -s [https://api.github.com](https://api.github.com)

```

Upon execution completion, logs are stored in `trace_output_<ID>/`:

* `syscalls.log`: Complete `strace` log output.
* `traffic.pcap`: Native packet capture file ready for Wireshark analysis.

---

## 📂 Architecture

```text
+-----------------------------------------------------------------+
|                       TMUX DEV-SHELL                            |
|                                                                 |
|  [Top Pane] USER SHELL (trace-shell)                            |
|    ├── strace (syscalls) ---> /tmp/strace.fifo ────┐            |
|    └── tcpdump (pcap)     ---> /tmp/tcpdump.fifo ──┼┐           |
|                                                    ||           |
|  [Bottom Pane] TUI MONITOR                         vv           |
|    trace_wrap_tui.sh <--- [trace_wrap_c_filter (Poll & Mux)]   |
+-----------------------------------------------------------------+

```

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
