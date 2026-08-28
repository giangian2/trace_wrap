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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#define MAX_LINE   2048
#define DISP_LEN   192
#define RING_CAP   4096
#define SRC_BUF    (MAX_LINE * 4)
#define OUT_BUF    (1 << 20)
#define MAX_FILTER 96
#define ENDP_LEN   64

/* ------------------------------------------------------------------ events */

typedef enum { EV_NET = 0, EV_SYS, EV_ERR } EvType;

typedef struct {
    EvType type;
    long   pid;                /* -1 when unknown */
    int    failed;             /* syscall returned a real error */
    char   ts[16];             /* timestamp as printed by strace -tt */
    char   name[32];           /* syscall name */
    char   text[MAX_LINE];     /* the original strace line, newline stripped */
    char   disp[DISP_LEN];     /* rendered network line; empty for EV_SYS */
} Event;

typedef struct {
    Event  ev[RING_CAP];
    size_t head;               /* next slot to write */
    size_t count;              /* live entries, capped at RING_CAP */
    size_t total;              /* events ever pushed, for the status bar */
    size_t scroll;             /* 0 = follow tail, N = N matching lines back */
} Ring;

enum { PANE_NET = 0, PANE_SYS = 1, PANE_N = 2 };

static Ring g_ring[PANE_N];

/* --------------------------------------------------------------- ui state */

static int   g_rows = 24, g_cols = 80;
static int   g_active = PANE_NET;
static int   g_paused = 0;
static int   g_quit = 0;
static int   g_dirty = 1;
static int   g_editing = 0;                  /* filter prompt is open */
static int   g_raw = 0;                      /* show raw strace lines up top */
static char  g_filter[MAX_FILTER] = "";
static char  g_edit[MAX_FILTER] = "";
static size_t g_edit_len = 0;

static volatile sig_atomic_t g_resized = 1;
static volatile sig_atomic_t g_signalled = 0;

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

/* --------------------------------------------------------- network events
 * strace -yy annotates every descriptor with what sits behind it:
 *   5<TCP:[172.17.163.162:52590->104.20.23.154:443]>   an established socket
 *   5<TCP:[967498]>                                    a socket, not yet connected
 *   7<UDP:[965268]>
 *   3<UNIX-STREAM:[965263]>                            a unix socket
 *   3</etc/passwd>                                     a plain file
 * Everything the old flow table used to reconstruct from /proc is right here,
 * on the very line that reports the syscall.
 */

typedef struct {
    char proto[12];            /* "TCP", "UDP", "UNIX-STREAM", ... */
    char local[ENDP_LEN];      /* "172.17.163.162:52590", or empty */
    char peer[ENDP_LEN];       /* "104.20.23.154:443", or empty     */
} FdInfo;

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

/* A unix socket names a path instead of an endpoint. */
static void scan_unix_path(const char *line, char *dst, size_t cap) {
    const char *p = strstr(line, "sun_path=\"");
    if (!p) { *dst = '\0'; return; }
    copy_until(dst, cap, p + 10, "\"");
}

/* The sockaddr of a connect()/sendto() still matters: at connect time the
 * socket is not established yet, so the annotation has no peer in it. */
static void scan_sockaddr_peer(const char *line, char *dst, size_t cap) {
    const char *a = strstr(line, "inet_addr(\"");
    const char *b = strstr(line, "inet_pton(\"");
    if (!a || (b && b < a)) a = b;
    if (!a) { *dst = '\0'; return; }

    char ip[ENDP_LEN];
    copy_until(ip, sizeof(ip), a + 11, "\"");

    const char *h = strstr(line, "htons(");
    if (h) snprintf(dst, cap, "%.45s:%d", ip, atoi(h + 6));
    else   snprintf(dst, cap, "%s", ip);
}

typedef enum { D_PLAIN, D_OUT, D_IN, D_CONN, D_ACCEPT, D_CLOSE } Dir;

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

static Dir dir_of(const char *name) {
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

    snprintf(e->disp, sizeof(e->disp), "%-12.12s %6ld  %-11.11s %s %-9.9s %-42.42s %s",
             e->ts, e->pid, fi.proto[0] ? fi.proto : "-",
             dir_glyph(d), e->name, peer[0] ? peer : "-", info);
    return 1;
}

/* ------------------------------------------------------------------- ring */

static const char *ev_shown(const Event *e) {
    return (e->type == EV_NET && !g_raw && e->disp[0]) ? e->disp : e->text;
}

static int matches(const Event *e) {
    if (g_filter[0] == '\0') return 1;
    return strcasestr(e->text, g_filter) != NULL ||
           (e->disp[0] && strcasestr(e->disp, g_filter) != NULL);
}

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

    if (name_in(e->name, ignored))  return 0;
    if (name_in(e->name, netcalls)) {
        if (name_in(e->name, netquiet)) return 0;
        e->type = EV_NET;
        return fmt_net(e, p, ret);
    }
    if (name_in(e->name, filecalls)) e->type = EV_SYS;
    else if (e->failed)              e->type = EV_ERR;
    else                             return 0;
    return 1;
}

static void emit(const Event *e) {
    ring_push(&g_ring[e->type == EV_NET ? PANE_NET : PANE_SYS], e);
    g_dirty = 1;
}

/* ------------------------------------------------------------- line source
 * read() on a non-blocking fd hands back arbitrary chunks, so the source keeps
 * a carry buffer holding the tail of a line until its newline shows up.
 */

typedef struct {
    int    fd;
    int    eof;
    size_t len;
    char   buf[SRC_BUF];
} Source;

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
            src_line(start);
            start = nl + 1;
        }
        s->len -= (size_t)(start - s->buf);
        memmove(s->buf, start, s->len);
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
        case EV_NET: {
            Dir d = dir_of(e->name);
            if (d == D_OUT)  return "\x1b[1;32m";   /* outbound: bright green */
            if (d == D_IN)   return "\x1b[36m";     /* inbound: cyan          */
            if (d == D_CONN || d == D_ACCEPT) return "\x1b[1;33m";  /* setup  */
            return "\x1b[37m";
        }
        case EV_ERR: return "\x1b[1;31m";
        default:     return "\x1b[37m";
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
            draw_row(row, ev_color(e), ev_shown(e));
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
        if (g_raw)       ostr("| RAW ");
        ostr("| tab pane  \xe2\x86\x91\xe2\x86\x93/pgup/pgdn scroll  end live  "
             "space pause  / filter  r raw  c clear  q quit");
    }
    ostr("\x1b[0m");
}

static void render(void) {
    int split  = g_rows / 2;
    int h_net  = split - 2;
    int h_sys  = g_rows - 1 - split;

    g_outlen = 0;
    draw_pane(PANE_NET, 2, h_net,
              "[ NETWORK  time      pid  proto       dir op        peer ]");
    draw_pane(PANE_SYS, split + 1, h_sys, "[ FILES, PROCESSES & ERRORS ]");
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
        case 'r': g_raw = !g_raw; g_dirty = 1; break;
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
