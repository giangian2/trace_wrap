/*
 * trace_wrap_mon - live monitor for trace_wrap.
 *
 * Reads strace's output from a FIFO, parses each line into a structured event
 * and renders it in a two-pane terminal UI: network activity on top, file and
 * process activity plus errors below.
 *
 * There used to be a second source here - tcpdump - and a whole flow-table
 * machinery whose only job was to guess which packets on the wire belonged to
 * the traced process. It is gone. strace -yy annotates every descriptor with
 * the socket behind it, endpoints included, so the network view is built from
 * the syscalls themselves: who talked, over which protocol, in which
 * direction, with whom, how many bytes, and how long it took. No correlation
 * to get wrong, no privileges to ask for, no packets to sift.
 *
 * Terminal handling is raw termios + ANSI escapes; no ncurses dependency.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "RingBuffer.h"
#include "Trace.h"
#include "UI.h"

Event  *g_ring[PANE_N];               /* one heap ring buffer per pane */
size_t  g_scroll[PANE_N];             /* how far back each pane is scrolled */

static void copy_until(char *dst, size_t cap, const char *src, const char *stop) {
    size_t k = 0;
    while (src[k] && !strchr(stop, src[k]) && k < cap - 1) { dst[k] = src[k]; k++; }
    dst[k] = '\0';
}

/* Finds the first "<IDENT:[...]>" of the line and pulls it apart. Plain-file
 * annotations carry no "IDENT:[" and are skipped, which is exactly how a read
 * on a socket is told apart from a read on a file. */
static int scan_fd_annot(const char *line, FdInfo *fi) {
    fi->proto[0] = fi->local[0] = fi->peer[0] = '\0';

    for (const char *p = strchr(line, '<'); p; p = strchr(p + 1, '<')) {
        const char *c = p + 1;
        while (isalnum((unsigned char)*c) || *c == '_' || *c == '-') c++;
        if (*c != ':' || c[1] != '[' || c == p + 1) continue;

        size_t plen = (size_t)(c - p - 1);
        if (plen >= sizeof(fi->proto)) plen = sizeof(fi->proto) - 1;
        memcpy(fi->proto, p + 1, plen);
        fi->proto[plen] = '\0';

        const char *body = c + 2;
        const char *arrow = strstr(body, "->");
        const char *end   = strchr(body, ']');
        if (arrow && end && arrow < end) {
            copy_until(fi->local, sizeof(fi->local), body, "-");
            copy_until(fi->peer,  sizeof(fi->peer),  arrow + 2, "]");
        }
        return 1;
    }
    return 0;
}

/* -yy labels pipes and anonymous inodes with the same "IDENT:[...]" shape it
 * uses for sockets, so the identifier itself has to be looked at before a
 * read() is called network activity. */
static int proto_is_socket(const char *proto) {
    static const char *fam[] = { "TCP", "UDP", "UNIX", "NETLINK", "SCTP",
                                 "ICMP", "RAW", "PACKET", "SOCK", NULL };
    for (int i = 0; fam[i]; i++)
        if (strncmp(proto, fam[i], strlen(fam[i])) == 0) return 1;
    return 0;
}

/* A unix socket names a path instead of an endpoint. */
static void scan_unix_path(const char *line, char *dst, size_t cap) {
    const char *p = strstr(line, "sun_path=\"");
    if (!p) { *dst = '\0'; return; }
    copy_until(dst, cap, p + 10, "\"");
}

/* The sockaddr of a connect()/sendto() still matters: at connect time the
 * socket is not established yet, so the annotation has no peer in it.
 * IPv4 comes as        inet_addr("140.82.121.5")
 * and IPv6 as          inet_pton(AF_INET6, "2606:4700::1", &sin6_addr)
 * - the address is the first quoted string after the marker either way, so
 * look for the quote rather than assuming it comes right after. */
static void scan_sockaddr_peer(const char *line, char *dst, size_t cap) {
    const char *a = strstr(line, "inet_addr(");
    const char *b = strstr(line, "inet_pton(");
    if (!a || (b && b < a)) a = b;
    if (a) a = strchr(a, '"');
    if (!a) { *dst = '\0'; return; }

    char ip[ENDP_LEN];
    copy_until(ip, sizeof(ip), a + 1, "\"");

    const char *h = strstr(line, "htons(");
    int port = h ? atoi(h + 6) : 0;

    /* An IPv6 address is full of colons; bracket it so the port stays legible,
     * the way strace's own annotations write it. */
    if (strchr(ip, ':')) {
        if (port) snprintf(dst, cap, "[%.45s]:%d", ip, port);
        else      snprintf(dst, cap, "[%.45s]", ip);
    } else {
        if (port) snprintf(dst, cap, "%.45s:%d", ip, port);
        else      snprintf(dst, cap, "%s", ip);
    }
}

static const char *dir_glyph(Dir d) {
    switch (d) {
        case D_OUT:    return "\xe2\x86\x91";   /* up arrow    */
        case D_IN:     return "\xe2\x86\x93";   /* down arrow  */
        case D_CONN:   return "\xe2\x86\x92";   /* right arrow */
        case D_ACCEPT: return "\xe2\x86\x90";   /* left arrow  */
        case D_CLOSE:  return "\xc3\x97";       /* multiply    */
        default:       return " ";
    }
}

Dir dir_of(const char *name) {
    if (!strncmp(name, "send", 4) || !strcmp(name, "write") ||
        !strcmp(name, "writev"))                        return D_OUT;
    if (!strncmp(name, "recv", 4) || !strcmp(name, "read") ||
        !strcmp(name, "readv"))                         return D_IN;
    if (!strcmp(name, "connect"))                       return D_CONN;
    if (!strncmp(name, "accept", 6))                    return D_ACCEPT;
    if (!strcmp(name, "shutdown") || !strcmp(name, "close")) return D_CLOSE;
    return D_PLAIN;
}

/* strace -T appends the time spent inside the call: "... = 0 <0.000123>" */
static void scan_duration(const char *line, char *dst, size_t cap) {
    *dst = '\0';
    size_t n = strlen(line);
    if (n < 4 || line[n - 1] != '>') return;
    const char *lt = NULL;
    for (const char *p = line + n - 1; p > line; p--)
        if (*p == '<') { lt = p; break; }
    if (lt && isdigit((unsigned char)lt[1]))
        copy_until(dst, cap, lt + 1, ">");
}

/* "= -1 ECONNREFUSED (Connection refused)" -> "ECONNREFUSED" */
static void scan_errno(const char *ret, char *dst, size_t cap) {
    *dst = '\0';
    if (!ret || *ret != '-') return;
    const char *p = ret;
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    if (isupper((unsigned char)*p)) copy_until(dst, cap, p, " (");
}

/* A non-blocking socket reports "would block" and "in progress" as errors.
 * They are ordinary flow control, not failures, and colouring them red would
 * paint half the screen for any async client. */
static int errno_benign(const char *e) {
    return !strcmp(e, "EAGAIN") || !strcmp(e, "EWOULDBLOCK") ||
           !strcmp(e, "EINPROGRESS") || !strcmp(e, "EINTR");
}

/* Builds the one-line rendering of a network syscall. Returns 0 to drop the
 * event entirely - plumbing calls and reads that moved nothing. */
static int fmt_net(Event *e, const char *p, const char *ret) {
    FdInfo fi;
    scan_fd_annot(p, &fi);

    Dir  d = dir_of(e->name);
    char err[32], dur[16], peer[ENDP_LEN], info[64] = "";

    scan_errno(ret, err, sizeof(err));
    scan_duration(p, dur, sizeof(dur));

    /* Nothing moved and nothing broke: a poll disguised as a read. */
    if ((d == D_OUT || d == D_IN) && err[0] && errno_benign(err)) return 0;

    e->failed = err[0] && !errno_benign(err);

    snprintf(peer, sizeof(peer), "%s", fi.peer);
    if (!peer[0]) scan_sockaddr_peer(p, peer, sizeof(peer));
    if (!peer[0]) scan_unix_path(p, peer, sizeof(peer));
    if (!peer[0] && fi.local[0]) snprintf(peer, sizeof(peer), "%s", fi.local);

    if (err[0]) {
        snprintf(info, sizeof(info), "%s", err);
    } else if ((d == D_OUT || d == D_IN) && ret) {
        long n = strtol(ret, NULL, 10);
        if (n >= 0) snprintf(info, sizeof(info), "%ld B", n);
    }
    if (dur[0]) {
        size_t at = strlen(info);
        snprintf(info + at, sizeof(info) - at, "%s%ss", at ? "  " : "", dur);
    }

    snprintf(e->disp, sizeof(e->disp), "%-12.12s %6ld %-8.8s %s %-9.9s %-24.24s %s",
             e->ts, e->pid, fi.proto[0] ? fi.proto : "-",
             dir_glyph(d), e->name, peer[0] ? peer : "-", info);
    return 1;
}

/* ------------------------------------------------------------------- ring */

static void pane_push(int pane, const Event *e) {
    ring_insert(g_ring[pane], *e);
    /* A frozen view must stay frozen: if we are scrolled back (or paused),
     * push the anchor along with the new entry so it doesn't slide into view. */
    if ((g_scroll[pane] > 0 || g_paused) && g_scroll[pane] < RING_CAP)
        g_scroll[pane]++;
}

/* ---------------------------------------------------------------- parsing */

/* Socket plumbing: it says nothing about who talked to whom, and setsockopt
 * alone fires four times per connection. */
static const char *netquiet[] = {
    "setsockopt", "getsockopt", "getsockname", "getpeername", "socketpair",
    NULL
};

static const char *netcalls[] = {
    "socket", "socketpair", "connect", "accept", "accept4", "bind", "listen",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "send", "recv", "getpeername", "getsockname", "setsockopt", "getsockopt",
    "shutdown",
    NULL
};

/* Nothing here is a network call by name - it depends entirely on what the
 * descriptor turns out to be. Most programs never call send()/recv() at all:
 * curl, nginx and anything built on a generic I/O layer write to a socket the
 * same way they write to a file, so without these the network pane would show
 * the connect() and none of the conversation that follows. */
static const char *iocalls[] = {
    "read", "write", "readv", "writev", "pread64", "pwrite64",
    "preadv", "pwritev", "preadv2", "pwritev2", "sendfile", "close",
    NULL
};

static const char *ignored[] = {
    "futex", "epoll_wait", "epoll_pwait", "epoll_ctl", "clock_gettime",
    "clock_nanosleep", "gettimeofday", "rt_sigprocmask", "rt_sigaction",
    "rt_sigreturn", "mmap", "mmap2", "munmap", "mprotect", "brk", "close",
    "read", "pread64", "write", "pwrite64", "fstat", "newfstatat", "lseek",
    "poll", "ppoll", "pselect6", "select", "getpid", "gettid", "sched_yield",
    NULL
};

static const char *filecalls[] = {
    "open", "openat", "openat2", "creat", "execve", "execveat", "fork",
    "vfork", "clone", "clone3", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat", "chown",
    "fchownat", "truncate", "ftruncate", "symlink", "symlinkat", "link",
    "mount", "umount2", "ptrace", "kill",
    NULL
};

static int name_in(const char *name, const char **list) {
    for (int i = 0; list[i]; i++)
        if (strcmp(name, list[i]) == 0) return 1;
    return 0;
}

/* Copies a syscall identifier out of *p; returns its length. */
static size_t take_name(const char *p, char *dst, size_t cap) {
    size_t k = 0;
    while ((isalnum((unsigned char)p[k]) || p[k] == '_') && k < cap - 1) {
        dst[k] = p[k];
        k++;
    }
    dst[k] = '\0';
    return k;
}

/* Returns 1 if the line produced an event worth showing, 0 to drop it. */
static int parse_strace(const char *line, Event *e) {
    const char *p = line;

    e->pid = -1;
    e->failed = 0;
    e->ts[0] = '\0';
    e->name[0] = '\0';
    e->disp[0] = '\0';
    snprintf(e->text, sizeof(e->text), "%s", line);

    while (*p == ' ' || *p == '\t') p++;

    if (strncmp(p, "[pid", 4) == 0) {            /* "[pid  1234] ..."       */
        p += 4;
        while (*p == ' ') p++;
        e->pid = strtol(p, (char **)&p, 10);
        while (*p && *p != ']') p++;
        if (*p == ']') p++;
    } else if (isdigit((unsigned char)*p)) {     /* "1234  12:00:00 ..."    */
        char *end;
        long v = strtol(p, &end, 10);
        if (end > p && (*end == ' ' || *end == '\t')) { e->pid = v; p = end; }
    }
    while (*p == ' ' || *p == '\t') p++;

    if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) && p[2] == ':') {
        size_t k = 0;
        while (p[k] && p[k] != ' ' && k < sizeof(e->ts) - 1) { e->ts[k] = p[k]; k++; }
        e->ts[k] = '\0';
        p += k;
        while (*p == ' ') p++;
    }

    if (strncmp(p, "---", 3) == 0) {             /* "--- SIGSEGV ... ---"   */
        e->type = EV_ERR;
        snprintf(e->name, sizeof(e->name), "signal");
        return 1;
    }
    if (strncmp(p, "+++", 3) == 0) {             /* "+++ exited with 1 +++" */
        e->type = EV_SYS;
        e->failed = strstr(p, "exited with 0") == NULL;
        snprintf(e->name, sizeof(e->name), "exit");
        return 1;
    }
    if (strncmp(p, "<...", 4) == 0) {            /* "<... connect resumed>" */
        p += 4;
        while (*p == ' ') p++;
    }

    size_t nlen = take_name(p, e->name, sizeof(e->name));
    if (nlen == 0) return 0;
    if (p[nlen] != '(' && strstr(p + nlen, "resumed") == NULL) return 0;

    /* The return value is after the LAST " = ": arguments can contain one. */
    const char *ret = NULL, *q = p;
    while ((q = strstr(q, " = ")) != NULL) { ret = q + 3; q += 3; }
    if (ret && *ret == '-') e->failed = 1;

    if (name_in(e->name, netcalls)) {
        if (name_in(e->name, netquiet)) return 0;
        e->type = EV_NET;
        return fmt_net(e, p, ret);
    }
    /* read/write/close are in the ignore list because on a file they are
     * noise; on a socket they are the traffic itself. The annotation decides,
     * so this has to come first. */
    if (name_in(e->name, iocalls)) {
        FdInfo fi;
        if (scan_fd_annot(p, &fi) && proto_is_socket(fi.proto)) {
            e->type = EV_NET;
            return fmt_net(e, p, ret);
        }
    }
    if (name_in(e->name, ignored))   return 0;
    if (name_in(e->name, filecalls)) e->type = EV_SYS;
    else if (e->failed)              e->type = EV_ERR;
    else                             return 0;
    return 1;
}

static void emit(const Event *e) {
    pane_push(e->type == EV_NET ? PANE_NET : PANE_SYS, e);
    g_dirty = 1;
}

static void src_line(char *line) {
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = '\0';
    if (n == 0) return;

    Event e;
    if (parse_strace(line, &e)) emit(&e);
}

static void src_pump(Source *s) {
    if (s->fd < 0) return;

    for (;;) {
        /* A line longer than the buffer would wedge us forever: flush it and
         * start over, which also proves to the compiler that len stays in
         * range for the read() below. */
        if (s->len >= sizeof(s->buf) - 1) {
            s->buf[sizeof(s->buf) - 1] = '\0';
            src_line(s->buf);
            s->len = 0;
        }

        size_t room = sizeof(s->buf) - 1 - s->len;
        if (room > sizeof(s->buf) - 1) room = sizeof(s->buf) - 1;   /* gcc hint */

        ssize_t n = read(s->fd, s->buf + s->len, room);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            s->eof = 1;
            break;
        }
        if (n == 0) { s->eof = 1; break; }

        s->len += (size_t)n;
        s->buf[s->len] = '\0';

        char *start = s->buf, *nl;
        while ((nl = memchr(start, '\n', s->len - (size_t)(start - s->buf)))) {
            *nl = '\0';
            src_line(start);
            start = nl + 1;
        }
        s->len -= (size_t)(start - s->buf);
        memmove(s->buf, start, s->len);
    }
}

/* -------------------------------------------------------------------- main */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <strace_fifo>\n", argv[0]);
        return 1;
    }

    Source src = {0};
    src.fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    if (src.fd < 0) {
        perror("Error opening FIFO");
        return 1;
    }
    if (!isatty(STDOUT_FILENO)) {
        fprintf(stderr, "%s: stdout must be a terminal\n", argv[0]);
        return 1;
    }

    term_setup();

    struct pollfd fds[2];
    fds[0].fd = src.fd;       fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO; fds[1].events = POLLIN;

    while (!g_quit && !g_signalled) {
        if (g_resized) { g_resized = 0; term_size(); g_dirty = 1; }

        int ret = poll(fds, 2, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* POLLHUP without POLLIN is the writer closing: drain, then stop
         * polling this fd. Leaving it armed would spin the loop at 100% CPU
         * once the traced shell exits. */
        if (fds[0].fd >= 0 && (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            src_pump(&src);
            if (src.eof) { fds[0].fd = -1; g_dirty = 1; }
        }
        if (fds[1].revents & POLLIN) read_keys();

        if (g_dirty) render();
    }

    return 0;
}
