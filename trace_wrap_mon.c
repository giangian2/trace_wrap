/*
 * trace_wrap_mon - live monitor for trace_wrap.
 *
 * Reads two FIFOs (strace text output, tcpdump text output), parses each line
 * into a structured event, and renders them in a two-pane terminal UI.
 * Replaces the old trace_wrap_c_filter + trace_wrap_tui.sh pair: parsing and
 * rendering now share one process, so the parsed fields survive all the way to
 * the screen and can be scrolled, paused and filtered.
 *
 * Terminal handling is raw termios + ANSI escapes; no ncurses dependency.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#define MAX_LINE   2048
#define RING_CAP   8192
#define SRC_BUF    (MAX_LINE * 4)
#define OUT_BUF    (1 << 20)
#define MAX_FILTER 96

/* ------------------------------------------------------------------ events */

typedef enum { EV_SYS_NET = 0, EV_RAW_NET, EV_SYS, EV_ERR } EvType;

typedef struct {
    EvType type;
    long   pid;              /* -1 when unknown */
    int    failed;           /* syscall returned a negative value */
    char   ts[24];           /* timestamp as printed by strace -tt */
    char   name[32];         /* syscall name, or "pkt" for raw packets */
    char   text[MAX_LINE];   /* full original line, newline stripped */
} Event;

typedef struct {
    Event  ev[RING_CAP];
    size_t head;             /* next slot to write */
    size_t count;            /* live entries, capped at RING_CAP */
    size_t total;            /* events ever pushed, for the status bar */
    size_t scroll;           /* 0 = follow tail, N = N matching lines back */
} Ring;

enum { PANE_NET = 0, PANE_SYS = 1, PANE_N = 2 };

static Ring g_ring[PANE_N];

/* How tightly raw tcpdump lines are filtered against what strace saw. */
typedef enum {
    PKT_FLOW = 0,   /* both endpoints must match a socket of the traced proc */
    PKT_PEER,       /* any peer address the traced process talked to         */
    PKT_ALL,        /* everything tcpdump hands us                           */
    PKT_MODE_N
} PktMode;

/* --------------------------------------------------------------- ui state */

static int   g_rows = 24, g_cols = 80;
static int   g_active = PANE_SYS;
static int   g_paused = 0;
static int   g_quit = 0;
static int   g_dirty = 1;
static int   g_editing = 0;                  /* filter prompt is open */
static char  g_filter[MAX_FILTER] = "";
static int   g_pkt_mode = PKT_FLOW;          /* how hard to filter raw packets */
static char  g_edit[MAX_FILTER] = "";
static size_t g_edit_len = 0;

static volatile sig_atomic_t g_resized = 1;
static volatile sig_atomic_t g_signalled = 0;

/* Sockets the traced process opened, keyed by the (pid, fd) pair strace
 * prints. tcpdump sees every packet on the host and has no idea which process
 * owns one; strace knows the process but never sees the wire. The connection
 * itself is the bridge - and it has to be the whole connection, because a peer
 * address alone is not discriminating: two programs both talking to GitHub
 * share it, and every packet of the other one would be attributed to us. */
#define MAX_FLOWS 128
#define ADDR_LEN  46                          /* fits an IPv6 text address */

typedef struct {
    long pid, fd;                             /* identity, as strace sees it */
    char peer_ip[ADDR_LEN];  int peer_port;   /* port 0 = not known (yet)    */
    char loc_ip[ADDR_LEN];   int loc_port;
    int  probes;                              /* /proc lookups already spent */
} Flow;

static Flow g_flow[MAX_FLOWS];
static int  g_flow_n;
static int  g_flow_next;                      /* round-robin slot once full */

static struct termios g_saved_tio;
static int g_tio_saved = 0;

/* ------------------------------------------------------------ output buffer
 * One write() per frame: assembling the whole screen in memory and flushing it
 * in a single syscall is what keeps the redraw flicker-free.
 */

static char   g_out[OUT_BUF];
static size_t g_outlen;

static void oput(const char *s, size_t n) {
    if (g_outlen + n > sizeof(g_out)) n = sizeof(g_out) - g_outlen;
    memcpy(g_out + g_outlen, s, n);
    g_outlen += n;
}

static void ostr(const char *s) { oput(s, strlen(s)); }

static void ofmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(g_out + g_outlen, sizeof(g_out) - g_outlen, fmt, ap);
    va_end(ap);
    if (n > 0) g_outlen += (size_t)n < sizeof(g_out) - g_outlen
                         ? (size_t)n : sizeof(g_out) - g_outlen - 1;
}

static void oflush(void) {
    size_t off = 0;
    while (off < g_outlen) {
        ssize_t n = write(STDOUT_FILENO, g_out + off, g_outlen - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    g_outlen = 0;
}

/* --------------------------------------------------- flow correlation */

static Flow *flow_get(long pid, long fd) {
    if (pid < 0 || fd < 0) return NULL;
    for (int i = 0; i < g_flow_n; i++)
        if (g_flow[i].pid == pid && g_flow[i].fd == fd) return &g_flow[i];

    Flow *f;
    if (g_flow_n < MAX_FLOWS) {
        f = &g_flow[g_flow_n++];
    } else {
        f = &g_flow[g_flow_next];
        g_flow_next = (g_flow_next + 1) % MAX_FLOWS;
    }
    memset(f, 0, sizeof(*f));
    f->pid = pid;
    f->fd  = fd;
    return f;
}

static int addr_wildcard(const char *ip) {
    return strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "::") == 0;
}

static int addr_loopback(const char *ip) {
    return strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0;
}

/* Pulls one endpoint out of the sockaddr strace prints:
 *   {sa_family=AF_INET,  sin_port=htons(443),  sin_addr=inet_addr("140.82.121.5")}
 *   {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton("2001:db8::1")}
 * Returns 1 when at least an address came out.                              */
static int scan_sockaddr(const char *s, char *ip, size_t cap, int *port) {
    ip[0] = '\0';
    *port = 0;

    const char *a = strstr(s, "inet_addr(\"");
    const char *b = strstr(s, "inet_pton(\"");
    if (!a || (b && b < a)) a = b;
    if (!a) return 0;
    a += 11;                                  /* both markers are 11 chars */

    size_t k = 0;
    while (a[k] && a[k] != '"' && k < cap - 1) { ip[k] = a[k]; k++; }
    ip[k] = '\0';

    const char *h = strstr(s, "htons(");
    if (h) *port = atoi(h + 6);
    return ip[0] != '\0';
}

/* Rows of /proc/net/{tcp,udp}{,6} carry the socket inode and its local port:
 *   sl  local_address rem_address st tx:rx tr:when rtx uid timeout inode
 *    0: 0100007F:1F90 00000000:0000 0A ...                          20095
 * Addresses are hex; only the port after the colon interests us here.       */
static int proc_port_of_inode(const char *table, unsigned long want, int *port) {
    FILE *fp = fopen(table, "r");
    if (!fp) return 0;

    char line[512];
    int found = 0;
    while (!found && fgets(line, sizeof(line), fp)) {
        unsigned int  lport;
        unsigned long ino;
        if (sscanf(line, " %*d: %*64[0-9A-Fa-f]:%X %*64[0-9A-Fa-f]:%*X"
                         " %*X %*X:%*X %*X:%*X %*X %*d %*d %lu",
                   &lport, &ino) == 2 && ino == want) {
            *port = (int)lport;
            found = 1;
        }
    }
    fclose(fp);
    return found;
}

/* The local port is what actually discriminates one process from another, but
 * waiting for getsockname() to hand it to us is hopeless: hardly any program
 * calls it. Do instead what ss and lsof do - /proc/<pid>/fd/<n> names the
 * socket inode, and the /proc/net tables map that inode to a port. Needs no
 * cooperation from the traced program, only that the socket still be open
 * when we look, which for anything but the shortest exchange it is.         */
static void flow_probe_local(Flow *f) {
    if (f->loc_port || f->probes >= 3) return;
    f->probes++;

    char path[64], link[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd/%ld", f->pid, f->fd);
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n <= 0) return;
    link[n] = '\0';

    unsigned long ino;
    if (sscanf(link, "socket:[%lu]", &ino) != 1) return;

    static const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6",
                                    "/proc/net/udp", "/proc/net/udp6", NULL };
    for (int i = 0; tables[i]; i++)
        if (proc_port_of_inode(tables[i], ino, &f->loc_port)) return;
}

/* One end of a packet against one end of a flow. Unknown fields do not veto:
 * a flow we only know the port of still matches on that port. */
static int end_eq(const char *ip, int port, const char *fip, int fport) {
    if (!fip[0] && !fport)               return 0;   /* nothing known at all */
    if (fip[0] && strcmp(ip, fip) != 0)  return 0;
    if (fport  && port != fport)         return 0;
    return 1;
}

/* tcpdump -nn writes an endpoint as "address.port", so the port is whatever
 * follows the LAST dot - true of 192.168.1.10.52134 and of 2001:db8::1.443
 * alike. The 'tcp or udp' filter guarantees a port is always there.         */
static int split_end(const char *tok, size_t len, char *ip, size_t cap, int *port) {
    while (len && (tok[len - 1] == ':' || tok[len - 1] == ',')) len--;

    const char *dot = NULL;
    for (size_t i = 0; i < len; i++)
        if (tok[i] == '.') dot = tok + i;
    if (!dot || dot + 1 >= tok + len) return 0;

    for (const char *c = dot + 1; c < tok + len; c++)
        if (!isdigit((unsigned char)*c)) return 0;

    size_t iplen = (size_t)(dot - tok);
    if (iplen == 0 || iplen >= cap) return 0;
    memcpy(ip, tok, iplen);
    ip[iplen] = '\0';
    *port = atoi(dot + 1);
    return 1;
}

/* The two ends sit around the '>' that follows the IP/IP6 keyword:
 *   15:04:23.918 eth0  Out IP 192.168.1.10.52134 > 140.82.121.5.443: Flags [S] */
static int pkt_ends(const char *line, char *sip, int *sport,
                                      char *dip, int *dport) {
    const char *p;
    if ((p = strstr(line, " IP ")) != NULL)       p += 4;
    else if ((p = strstr(line, " IP6 ")) != NULL) p += 5;
    else return 0;

    const char *beg = p;
    while (*p && *p != ' ') p++;
    if (!split_end(beg, (size_t)(p - beg), sip, ADDR_LEN, sport)) return 0;

    while (*p == ' ') p++;
    if (*p != '>') return 0;
    p++;
    while (*p == ' ') p++;

    beg = p;
    while (*p && *p != ' ') p++;
    return split_end(beg, (size_t)(p - beg), dip, ADDR_LEN, dport);
}

static int pkt_is_ours(const char *line) {
    char sip[ADDR_LEN], dip[ADDR_LEN];
    int  sport, dport;
    if (!pkt_ends(line, sip, &sport, dip, &dport)) return 0;

    for (int i = 0; i < g_flow_n; i++) {
        Flow *f = &g_flow[i];
        if (!f->peer_ip[0] && !f->peer_port) continue;

        /* No local end yet - the program never called bind/getsockname and the
         * socket was already gone when /proc was read. Fall back to the peer
         * end, still tighter than matching an IP anywhere in the line. */
        if (!f->loc_ip[0] && !f->loc_port) {
            if (end_eq(sip, sport, f->peer_ip, f->peer_port) ||
                end_eq(dip, dport, f->peer_ip, f->peer_port)) return 1;
            continue;
        }
        if (end_eq(sip, sport, f->loc_ip,  f->loc_port) &&
            end_eq(dip, dport, f->peer_ip, f->peer_port)) return 1;
        if (end_eq(sip, sport, f->peer_ip, f->peer_port) &&
            end_eq(dip, dport, f->loc_ip,  f->loc_port))  return 1;
    }
    return 0;
}

/* Loose mode: any peer address anywhere in the line, whatever the ports. */
static int pkt_has_peer(const char *line) {
    for (int i = 0; i < g_flow_n; i++)
        if (g_flow[i].peer_ip[0] && strstr(line, g_flow[i].peer_ip)) return 1;
    return 0;
}

static int matches(const Event *e) {
    if (e->type == EV_RAW_NET) {
        if (g_pkt_mode == PKT_FLOW && !pkt_is_ours(e->text))  return 0;
        if (g_pkt_mode == PKT_PEER && !pkt_has_peer(e->text)) return 0;
    }
    return g_filter[0] == '\0' || strcasestr(e->text, g_filter) != NULL;
}

/* ------------------------------------------------------------------- ring */

static Event *ring_at(Ring *r, size_t k) {   /* k = 0 is the oldest entry */
    return &r->ev[(r->head + RING_CAP - r->count + k) % RING_CAP];
}

static void ring_push(Ring *r, const Event *e) {
    r->ev[r->head] = *e;
    r->head = (r->head + 1) % RING_CAP;
    if (r->count < RING_CAP) r->count++;
    r->total++;
    /* A frozen view must stay frozen: if we are scrolled back (or paused) and
     * the new event would be visible, push the anchor along with it. */
    if ((r->scroll > 0 || g_paused) && matches(e) && r->scroll < RING_CAP)
        r->scroll++;
}

/* ---------------------------------------------------------------- parsing */

static const char *ignored[] = {
    "futex", "epoll_wait", "epoll_pwait", "epoll_ctl", "clock_gettime",
    "clock_nanosleep", "gettimeofday", "rt_sigprocmask", "rt_sigaction",
    "rt_sigreturn", "mmap", "mmap2", "munmap", "mprotect", "brk", "close",
    "read", "pread64", "write", "pwrite64", "fstat", "newfstatat", "lseek",
    "poll", "ppoll", "pselect6", "select", "getpid", "gettid", "sched_yield",
    NULL
};

static const char *netcalls[] = {
    "socket", "socketpair", "connect", "accept", "accept4", "bind", "listen",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
    "getpeername", "getsockname", "setsockopt", "shutdown",
    NULL
};

/* Only these carry a PEER address. bind/getsockname/socketpair report the
 * LOCAL end - feeding those to the peer table poisons it with our own IP,
 * which then matches every single packet on the host. */
static const char *peercalls[] = {
    "connect", "accept", "accept4", "sendto", "recvfrom", "sendmsg",
    "recvmsg", "sendmmsg", "recvmmsg", "getpeername",
    NULL
};

/* ...and these carry the LOCAL one. Keeping the two apart is the whole point:
 * a local address in the peer column matches every packet on the host. */
static const char *localcalls[] = {
    "bind", "getsockname",
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

/* The descriptor is the first argument: "connect(3, {...}". */
static long take_arg_fd(const char *p) {
    const char *o = strchr(p, '(');
    if (!o) return -1;
    char *end;
    long v = strtol(o + 1, &end, 10);
    return end > o + 1 ? v : -1;
}

/* Feeds one network syscall into the flow table, so that raw tcpdump lines can
 * later be matched against real connections instead of bare peer addresses. */
static void track_flow(const Event *e, const char *p, const char *ret) {
    int is_peer  = name_in(e->name, peercalls);
    int is_local = name_in(e->name, localcalls);
    if (!is_peer && !is_local) return;

    char ip[ADDR_LEN];
    int  port;
    if (!scan_sockaddr(p, ip, sizeof(ip), &port)) return;
    if (is_peer && (addr_wildcard(ip) || addr_loopback(ip))) return;

    /* accept() hands back a NEW descriptor, and it is that one - not the
     * listening socket - that the packets belong to. */
    long fd;
    if (ret && (strcmp(e->name, "accept") == 0 || strcmp(e->name, "accept4") == 0))
        fd = strtol(ret, NULL, 10);
    else
        fd = take_arg_fd(p);

    Flow *f = flow_get(e->pid, fd);
    if (!f) return;

    if (is_peer) {
        /* A different peer on the same fd means the number was recycled onto
         * another socket: the local end we had cached no longer applies. */
        if (f->peer_ip[0] && strcmp(f->peer_ip, ip) != 0) {
            f->loc_ip[0] = '\0';
            f->loc_port  = 0;
            f->probes    = 0;
        }
        snprintf(f->peer_ip, sizeof(f->peer_ip), "%s", ip);
        if (port) f->peer_port = port;
        flow_probe_local(f);
    } else {
        if (!addr_wildcard(ip)) snprintf(f->loc_ip, sizeof(f->loc_ip), "%s", ip);
        if (port) f->loc_port = port;
    }
}

/* Returns 1 if the line produced an event worth showing, 0 to drop it. */
static int parse_strace(const char *line, Event *e) {
    const char *p = line;

    e->pid = -1;
    e->failed = 0;
    e->ts[0] = '\0';
    e->name[0] = '\0';
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

    if (name_in(e->name, ignored))        return 0;
    if (name_in(e->name, netcalls))       { e->type = EV_SYS_NET; track_flow(e, p, ret); }
    else if (name_in(e->name, filecalls)) e->type = EV_SYS;
    else if (e->failed)                   e->type = EV_ERR;
    else                                  return 0;
    return 1;
}

static int parse_pcap(const char *line, Event *e) {
    if (*line == '\0') return 0;
    /* local resolver chatter: loopback traffic on port 53 */
    if (strstr(line, "127.0.0.1") && strstr(line, ".53")) return 0;

    e->type = EV_RAW_NET;
    e->pid = -1;
    e->failed = 0;
    e->ts[0] = '\0';
    snprintf(e->name, sizeof(e->name), "pkt");
    snprintf(e->text, sizeof(e->text), "%s", line);
    return 1;
}

static void emit(const Event *e) {
    ring_push(&g_ring[e->type == EV_SYS_NET || e->type == EV_RAW_NET
                      ? PANE_NET : PANE_SYS], e);
    g_dirty = 1;
}

/* ------------------------------------------------------------ line sources
 * read() on a non-blocking fd hands back arbitrary chunks, so each source
 * keeps a carry buffer holding the tail of a line until its newline shows up.
 */

typedef struct {
    int    fd;
    int    eof;
    size_t len;
    char   buf[SRC_BUF];
    int  (*parse)(const char *line, Event *e);
} Source;

static void src_line(Source *s, char *line) {
    size_t n = strlen(line);
    while (n && (line[n - 1] == '\r' || line[n - 1] == ' ')) line[--n] = '\0';
    if (n == 0) return;

    Event e;
    if (s->parse(line, &e)) emit(&e);
}

static void src_pump(Source *s) {
    if (s->fd < 0) return;

    for (;;) {
        ssize_t n = read(s->fd, s->buf + s->len, sizeof(s->buf) - s->len - 1);
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
            src_line(s, start);
            start = nl + 1;
        }
        s->len -= (size_t)(start - s->buf);
        memmove(s->buf, start, s->len);

        /* A line longer than the buffer would wedge us forever: flush it. */
        if (s->len == sizeof(s->buf) - 1) {
            s->buf[s->len] = '\0';
            src_line(s, s->buf);
            s->len = 0;
        }
    }
}

/* ------------------------------------------------------------- terminal io */

static void term_restore(void) {
    ostr("\x1b[?25h"      /* show cursor          */
         "\x1b[0m"        /* reset attributes     */
         "\x1b[?1049l");  /* leave alternate screen */
    oflush();
    if (g_tio_saved) tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_tio);
}

static void on_winch(int sig) { (void)sig; g_resized = 1; }
static void on_term(int sig)  { (void)sig; g_signalled = 1; }

static void term_setup(void) {
    if (tcgetattr(STDIN_FILENO, &g_saved_tio) == 0) {
        struct termios raw = g_saved_tio;
        raw.c_lflag &= ~(ICANON | ECHO | ISIG);
        raw.c_iflag &= ~(IXON | ICRNL);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        g_tio_saved = 1;
    }
    atexit(term_restore);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_winch;
    sigaction(SIGWINCH, &sa, NULL);
    sa.sa_handler = on_term;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    ostr("\x1b[?1049h"    /* alternate screen: the shell scrollback survives */
         "\x1b[?25l"      /* hide cursor                                     */
         "\x1b[2J");      /* clear                                           */
    oflush();
}

static void term_size(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
        g_rows = ws.ws_row;
        g_cols = ws.ws_col;
    }
    if (g_rows < 8)  g_rows = 8;
    if (g_cols < 20) g_cols = 20;
    if (g_cols > MAX_LINE - 1) g_cols = MAX_LINE - 1;
}

/* --------------------------------------------------------------- rendering */

static const char *ev_color(const Event *e) {
    if (e->failed) return "\x1b[1;31m";
    switch (e->type) {
        case EV_SYS_NET: return "\x1b[1;32m";
        case EV_RAW_NET: return "\x1b[36m";
        case EV_ERR:     return "\x1b[1;31m";
        default:         return "\x1b[37m";
    }
}

static void draw_row(int row, const char *color, const char *text) {
    ofmt("\x1b[%d;1H\x1b[K", row);
    if (color) ostr(color);
    int budget = g_cols - 1;
    int len = (int)strlen(text);
    oput(text, (size_t)(len < budget ? len : budget));
    ostr("\x1b[0m");
}

/* Walks the ring backwards collecting the visible slice, then paints it. */
static void draw_pane(int pane, int top, int height, const char *title) {
    Ring *r = &g_ring[pane];
    size_t idx[512];
    int cap = height < 512 ? height : 512;
    int found = 0;
    size_t skipped = 0, shown_total = 0;

    for (size_t k = r->count; k-- > 0; ) {
        Event *e = ring_at(r, k);
        if (!matches(e)) continue;
        shown_total++;
        if (skipped < r->scroll) { skipped++; continue; }
        if (found < cap) idx[found++] = k;
    }
    /* Scrolled past the top (ring evicted entries under us): clamp and repaint. */
    if (found == 0 && r->scroll > 0 && shown_total > 0) {
        r->scroll = shown_total > (size_t)cap ? shown_total - (size_t)cap : 0;
        draw_pane(pane, top, height, title);
        return;
    }

    int active = (pane == g_active);
    ofmt("\x1b[%d;1H\x1b[K", top - 1);
    ofmt("%s %s ", active ? "\x1b[1;33m" : "\x1b[1;36m", title);
    if (shown_total < r->total) ofmt("\x1b[0m\x1b[2m%zu/%zu ev", shown_total, r->total);
    else                        ofmt("\x1b[0m\x1b[2m%zu ev", r->total);
    if (r->scroll) ofmt("  \x1b[1;35m^%zu", r->scroll);
    ostr("\x1b[0m");

    for (int i = 0; i < height; i++) {
        int row = top + height - 1 - i;      /* newest at the bottom */
        if (i < found) {
            Event *e = ring_at(r, idx[i]);
            draw_row(row, ev_color(e), e->text);
        } else {
            ofmt("\x1b[%d;1H\x1b[K", row);
        }
    }
}

static void draw_status(void) {
    ofmt("\x1b[%d;1H\x1b[K\x1b[7m", g_rows);

    if (g_editing) {
        ofmt(" filter: %s_", g_edit);
    } else {
        ofmt(" %s ", g_paused ? "\x1b[1;31mPAUSED\x1b[0m\x1b[7m" : "LIVE");
        ofmt("| %s ", g_active == PANE_NET ? "net" : "sys");
        if (g_filter[0]) ofmt("| /%s ", g_filter);
        static const char *pkt_name[] = { "flow", "peer", "ALL-HOST" };
        ofmt("| pkts:%s(%d) ", pkt_name[g_pkt_mode], g_flow_n);
        ostr("| tab pane  \xe2\x86\x91\xe2\x86\x93/pgup/pgdn scroll  end live  "
             "space pause  / filter  a pkts  c clear  q quit");
    }
    ostr("\x1b[0m");
}

static void render(void) {
    int split  = g_rows / 2;
    int h_net  = split - 2;
    int h_sys  = g_rows - 1 - split;

    g_outlen = 0;
    draw_pane(PANE_NET, 2, h_net, "[ NETWORK LIVE TRAFFIC (SYS & RAW) ]");
    draw_pane(PANE_SYS, split + 1, h_sys, "[ CRITICAL SYSCALLS & ERRORS ]");
    draw_status();
    oflush();
    g_dirty = 0;
}

/* ------------------------------------------------------------------- input */

static void scroll_by(int delta) {
    Ring *r = &g_ring[g_active];
    if (delta > 0) r->scroll += (size_t)delta;
    else if ((size_t)(-delta) >= r->scroll) r->scroll = 0;
    else r->scroll -= (size_t)(-delta);
    if (r->scroll > r->count) r->scroll = r->count;
    g_dirty = 1;
}

static void key_edit(char c) {
    if (c == '\r' || c == '\n') {
        memcpy(g_filter, g_edit, sizeof(g_filter));
        g_editing = 0;
        g_ring[PANE_NET].scroll = g_ring[PANE_SYS].scroll = 0;
    } else if (c == 27) {
        g_editing = 0;
    } else if ((c == 127 || c == 8) && g_edit_len) {
        g_edit[--g_edit_len] = '\0';
    } else if (isprint((unsigned char)c) && g_edit_len < sizeof(g_edit) - 1) {
        g_edit[g_edit_len++] = c;
        g_edit[g_edit_len] = '\0';
    }
    g_dirty = 1;
}

static void key_normal(const char *b, size_t n, size_t *consumed) {
    int page = (g_rows / 2) - 3;
    if (page < 1) page = 1;
    *consumed = 1;

    if (b[0] == 27 && n >= 3 && b[1] == '[') {      /* CSI sequence */
        *consumed = 3;
        switch (b[2]) {
            case 'A': scroll_by(1);      return;
            case 'B': scroll_by(-1);     return;
            case 'Z': g_active ^= 1; g_dirty = 1; return;   /* shift-tab */
            case 'H': scroll_by((int)g_ring[g_active].count); return;
            case 'F': scroll_by(-(int)g_ring[g_active].count); return;
            case '5': case '6':
                if (n >= 4 && b[3] == '~') {
                    *consumed = 4;
                    scroll_by(b[2] == '5' ? page : -page);
                }
                return;
            default: return;
        }
    }

    switch (b[0]) {
        case 'q': case 3:  g_quit = 1; break;                 /* q / ctrl-c */
        case '\t': g_active ^= 1; g_dirty = 1; break;
        case ' ':  g_paused = !g_paused;
                   if (!g_paused) g_ring[g_active].scroll = 0;
                   g_dirty = 1; break;
        case '/': case 'f':
                   g_editing = 1; g_edit[0] = '\0'; g_edit_len = 0;
                   g_dirty = 1; break;
        case 'a': g_pkt_mode = (g_pkt_mode + 1) % PKT_MODE_N;
                  g_ring[PANE_NET].scroll = 0; g_dirty = 1; break;
        case 'c': memset(&g_ring[g_active], 0, sizeof(Ring)); g_dirty = 1; break;
        case 'g': scroll_by((int)g_ring[g_active].count); break;
        case 'G': case 'e': scroll_by(-(int)g_ring[g_active].count); break;
        default: break;
    }
}

static void read_keys(void) {
    char b[256];
    ssize_t n = read(STDIN_FILENO, b, sizeof(b));
    if (n <= 0) return;

    size_t i = 0;
    while (i < (size_t)n) {
        if (g_editing) { key_edit(b[i]); i++; continue; }
        size_t used = 1;
        key_normal(b + i, (size_t)n - i, &used);
        i += used;
    }
}

/* -------------------------------------------------------------------- main */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <strace_fifo> <tcpdump_fifo>\n", argv[0]);
        return 1;
    }

    Source src[2] = {0};
    src[0].fd = open(argv[1], O_RDONLY | O_NONBLOCK);
    src[0].parse = parse_strace;
    src[1].fd = open(argv[2], O_RDONLY | O_NONBLOCK);
    src[1].parse = parse_pcap;

    if (src[0].fd < 0 || src[1].fd < 0) {
        perror("Error opening FIFOs");
        return 1;
    }
    if (!isatty(STDOUT_FILENO)) {
        fprintf(stderr, "%s: stdout must be a terminal\n", argv[0]);
        return 1;
    }

    term_setup();

    struct pollfd fds[3];
    fds[0].fd = src[0].fd; fds[0].events = POLLIN;
    fds[1].fd = src[1].fd; fds[1].events = POLLIN;
    fds[2].fd = STDIN_FILENO; fds[2].events = POLLIN;

    while (!g_quit && !g_signalled) {
        if (g_resized) { g_resized = 0; term_size(); g_dirty = 1; }

        int ret = poll(fds, 3, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < 2; i++) {
            if (fds[i].fd < 0) continue;
            /* POLLHUP without POLLIN is the writer closing: drain, then stop
             * polling this fd. Leaving it armed is what made the old filter
             * spin at 100% CPU once the traced shell exited. */
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                src_pump(&src[i]);
                if (src[i].eof) { fds[i].fd = -1; g_dirty = 1; }
            }
        }
        if (fds[2].revents & POLLIN) read_keys();

        if (g_dirty) render();
    }

    return 0;
}
