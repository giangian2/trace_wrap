#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>

#define MAX_LINE 2048

static const char *ignored_syscalls[] = {
    "futex", "epoll_wait", "epoll_ctl", "clock_gettime", "gettimeofday",
    "rt_sigprocmask", "rt_sigaction", "mmap", "munmap", "mprotect",
    "brk", "close", "read", "write", "fstat", "newfstatat", "poll", "pselect6", NULL
};

static int is_ignored(const char *line) {
    for (int i = 0; ignored_syscalls[i] != NULL; i++) {
        if (strstr(line, ignored_syscalls[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static void parse_strace(char *line) {
    if (is_ignored(line)) return;

    if (strstr(line, "connect(") || strstr(line, "sendto(") || strstr(line, "accept(") || strstr(line, "recvfrom(")) {
        printf("[SYS_NET] %s", line);
    } else if (strstr(line, "= -1 ") || strstr(line, "= -2")) {
        printf("[ERR] %s", line);
    } else if (strstr(line, "openat(") || strstr(line, "execve(") || strstr(line, "clone(") || strstr(line, "unlink(")) {
        printf("[SYS] %s", line);
    }
    fflush(stdout);
}

static void parse_pcap_text(char *line) {
    // Esclude traffico di loopback interno e query DNS locali per ridurre rumore
    if (strstr(line, "127.0.0.1") && strstr(line, ".53")) return;

    printf("[RAW_NET] %s", line);
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <strace_fifo> <tcpdump_fifo>\n", argv[0]);
        return 1;
    }

    int fd_strace = open(argv[1], O_RDONLY | O_NONBLOCK);
    int fd_tcpdump = open(argv[2], O_RDONLY | O_NONBLOCK);

    if (fd_strace < 0 || fd_tcpdump < 0) {
        perror("Error opening FIFOs");
        return 1;
    }

    struct pollfd fds[2];
    fds[0].fd = fd_strace;
    fds[0].events = POLLIN;
    fds[1].fd = fd_tcpdump;
    fds[1].events = POLLIN;

    char buf[MAX_LINE];
    FILE *stream_strace = fdopen(fd_strace, "r");
    FILE *stream_tcpdump = fdopen(fd_tcpdump, "r");

    while (1) {
        int ret = poll(fds, 2, 100);
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                if (fgets(buf, sizeof(buf), stream_strace)) {
                    parse_strace(buf);
                }
            }
            if (fds[1].revents & POLLIN) {
                if (fgets(buf, sizeof(buf), stream_tcpdump)) {
                    parse_pcap_text(buf);
                }
            }
        }
    }

    fclose(stream_strace);
    fclose(stream_tcpdump);
    return 0;
}
