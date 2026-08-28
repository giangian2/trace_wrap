# 🔍 trace_wrap

**`trace_wrap`** is a lightweight, high-performance tool designed for developers who need real-time visibility into what a process does to the network and to the filesystem, without the noise of traditional tracing tools.

It delivers an interactive terminal workspace (**Traced Dev-Shell**) powered by `tmux` alongside a low-noise, high-contrast TUI that isolates failed syscalls and live socket activity — who talked, over which protocol, in which direction, with whom, how many bytes, and how long it took.

---

## ⚡ Key Features

* **Traced Dev-Shell:** Spawns an interactive sub-shell where every executed command is monitored automatically in the background.
* **Low-Noise TUI:** Real-time split display focusing strictly on **Network Events** (socket activity, rendered one line per call) and **Files, Processes & Errors** (e.g., missing files, permission issues, signals, exits).
* **Single C Monitor:** Parsing and rendering live in one binary (`trace_wrap_mon`). High-frequency background noise (`futex`, `epoll_wait`, `clock_gettime`) is stripped by exact syscall name, keeping CPU and RAM consumption close to zero.
* **One source, no correlation:** `strace -yy` annotates every descriptor with the socket behind it — `5<TCP:[172.17.163.162:52590->104.20.23.154:443]>` — so the network view is built from the syscalls themselves. No packet capture to sift, nothing to guess about which packets belong to the traced process, no `CAP_NET_RAW`.
* **Traffic, not just plumbing:** `read`/`write`/`readv`/`writev` count as network events when the descriptor is a socket, which is how most programs actually talk (curl, nginx and anything on a generic I/O layer never call `send()`). `setsockopt` and friends are filtered out; `EAGAIN`/`EINPROGRESS` on a non-blocking socket are shown as flow control, not as failures.
* **Navigable TUI:** Scrollback ring buffer per pane, pause, live substring filtering, and `r` to drop back to the raw strace line behind any event.
* **Single-Command Tracing:** Supports quick tracing and output exporting (`.pcap` / `.log`) for a single target binary or script.
* **Zero Heavy Dependencies:** Built using native **Bash, C, `strace` and `tmux`** (`tcpdump` only for the offline `.pcap` of single-command mode).

---

## 📋 System Requirements

To run `trace_wrap`, ensure your Linux environment has the following packages installed:

* `gcc` & `make` (to build the C monitor — no ncurses or other libraries required)
* `strace` (with `-yy`, i.e. 4.15 or newer)
* `tmux` (required for interactive `shell` mode)
* `tcpdump` (only for the `.pcap` written by single-command mode)
* `root` / `sudo` privileges (required by `strace` to follow the traced shell, and by `tcpdump` to open the interface)

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


2. Compile the C monitor and install binaries system-wide (defaults to `/usr/local/bin`):
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
* **Bottom Pane:** Real-time TUI dashboard. The top half lists network activity, one line per socket call:

```text
16:42:07.564 118149 TCP      ↓ recvfrom  172.66.147.243:443       585 B  0.000112s
16:42:07.578 118149 TCP      ↑ sendto    172.66.147.243:443        24 B  0.000094s
16:42:07.580 118149 TCP      × close     172.66.147.243:443              0.000101s
```

  `↑` out, `↓` in, `→` connect, `←` accept, `×` shutdown/close. The bottom half lists file and process activity plus anything that failed.

Moving between the two panes (`F9`/`F10` are bound without a prefix, so they work
even if this tmux is nested inside another one):

| Key | Pane |
|---|---|
| `F9` | traced shell (top) |
| `F10` | monitor (bottom) |

TUI keys (bottom pane):

| Key | Action |
|---|---|
| `Tab` | switch the active pane (net / sys) |
| `↑` `↓` `PgUp` `PgDn` | scroll the active pane's history |
| `End` / `G` | jump back to the live tail |
| `Space` | pause the view (events keep being collected) |
| `r` | toggle between the rendered network line and the raw `strace` line behind it |
| `/` | filter both panes by substring; empty filter clears it |
| `c` | clear the active pane |
| `q` | quit the monitor |

To exit the dev-shell, simply type `exit`.

---

### 2. Single Command Mode

To trace a one-off execution and save full logs for offline analysis:

```bash
sudo trace_wrap curl -s [https://api.github.com](https://api.github.com)

```

Upon execution completion, logs are stored in `trace_output_<ID>/`:

* `syscalls.log`: Complete `strace -yy` log output, descriptors annotated with the socket or file behind them.
* `traffic.pcap`: Native packet capture file ready for Wireshark analysis. The live monitor no longer needs it, but on the wire is still the only place to see the handshake, retransmissions, resets, and traffic a *different* process sent on your behalf (a DNS resolver, for instance).

---

## 📂 Architecture

```text
+------------------------------------------------------------------+
|                        TMUX DEV-SHELL                            |
|                                                                  |
|  [Top Pane] USER SHELL (trace-shell)                             |
|    +-- strace -f -yy -e trace=file,network,process,desc          |
|          --> /tmp/trace_output_N/strace.fifo -------------+      |
|                                                           |      |
|  [Bottom Pane]                                            v      |
|    trace_wrap_mon   poll(2) -> parse -> Event -> ring buffers    |
|                     -> ANSI two-pane render (scroll/pause/filter)|
+------------------------------------------------------------------+
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
