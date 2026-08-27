# Process Trace Wrapper

A simple and universal Linux utility to profile a process by capturing 100% of its system calls and network activity during its lifecycle. 

It works out-of-the-box for any type of application (including Spring Boot, gRPC, and multi-threaded programs) without needing to know or specify target network ports or IP addresses.

## Prerequisites

```bash
sudo apt update && sudo apt install -y strace tcpdump
```

## Installation

1. Clone this repository:
   ```bash
   git clone <your-repository-url>
   cd <repository-folder>
   ```

2. Make the script executable:
   ```bash
   chmod +x trace-wrap.sh
   ```

## Usage

Run the script using `sudo` followed by the command you want to profile:

```bash
sudo ./trace-wrap.sh java -jar your-spring-app.jar
```

## Output Files

Upon termination, the script generates an output directory named `trace_output_[RANDOM_ID]/` containing:

* **`syscalls.log`**: A complete text log containing every system call, arguments, execution microsecond timestamps, and PID tracking for every thread.
* **`traffic.pcap`**: A raw network capture file containing all packets transmitted during the process lifetime, openable in **Wireshark**.
