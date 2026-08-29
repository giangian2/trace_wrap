/*
 * UI.c - terminal handling, rendering and input for trace_wrap_mon.
 *
 * Everything here only ever reads events out of g_ring (owned and written by
 * trace_wrap_mon.c); it never parses strace output itself.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include "RingBuffer.h"
#include "Trace.h"
#include "UI.h"

#define OUT_BUF (1 << 20)

int g_quit  = 0;
int g_dirty = 1;
volatile sig_atomic_t g_resized   = 1;
volatile sig_atomic_t g_signalled = 0;

/* --------------------------------------------------------------- ui state */

static int g_rows = 24, g_cols = 80;
static int g_active = PANE_NET;
int        g_paused = 0;
static int g_raw = 0;                      /* show raw strace lines up top */

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

void term_setup(void) {
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

void term_size(void) {
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

static const char *ev_shown(const Event *e) {
    return (e->type == EV_NET && !g_raw && e->disp[0]) ? e->disp : e->text;
}

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
    Event *ring   = g_ring[pane];
    size_t count  = ring_count(ring);
    size_t total  = ring_total(ring);
    size_t scroll = g_scroll[pane];

    size_t idx[512];
    int cap = height < 512 ? height : 512;
    int found = 0;
    size_t skipped = 0;

    for (size_t k = count; k-- > 0; ) {
        if (skipped < scroll) { skipped++; continue; }
        if (found < cap) idx[found++] = k;
    }
    /* Scrolled past the top (ring evicted entries under us): clamp and repaint. */
    if (found == 0 && scroll > 0 && count > 0) {
        g_scroll[pane] = count > (size_t)cap ? count - (size_t)cap : 0;
        draw_pane(pane, top, height, title);
        return;
    }

    int active = (pane == g_active);
    ofmt("\x1b[%d;1H\x1b[K", top - 1);
    ofmt("%s %s ", active ? "\x1b[1;33m" : "\x1b[1;36m", title);
    if (count < total) ofmt("\x1b[0m\x1b[2m%zu/%zu ev", count, total);
    else                ofmt("\x1b[0m\x1b[2m%zu ev", total);
    if (scroll) ofmt("  \x1b[1;35m^%zu", scroll);
    ostr("\x1b[0m");

    for (int i = 0; i < height; i++) {
        int row = top + height - 1 - i;      /* newest at the bottom */
        if (i < found) {
            Event *e = &ring[ring_at(ring, idx[i])];
            draw_row(row, ev_color(e), ev_shown(e));
        } else {
            ofmt("\x1b[%d;1H\x1b[K", row);
        }
    }
}

static void draw_status(void) {
    ofmt("\x1b[%d;1H\x1b[K\x1b[7m", g_rows);

    ofmt(" %s ", g_paused ? "\x1b[1;31mPAUSED\x1b[0m\x1b[7m" : "LIVE");
    ofmt("| %s ", g_active == PANE_NET ? "net" : "sys");
    if (g_raw) ostr("| RAW ");
    ostr("| tab pane  \xe2\x86\x91\xe2\x86\x93/pgup/pgdn scroll  end live  "
         "space pause  r raw  c clear  q quit");
    ostr("\x1b[0m");
}

void render(void) {
    int split  = g_rows / 2;
    int h_net  = split - 2;
    int h_sys  = g_rows - 1 - split;

    g_outlen = 0;
    draw_pane(PANE_NET, 2, h_net,
              "[ NETWORK - time pid proto dir syscall peer bytes/duration ]");
    draw_pane(PANE_SYS, split + 1, h_sys, "[ FILES, PROCESSES & ERRORS ]");
    draw_status();
    oflush();
    g_dirty = 0;
}

/* ------------------------------------------------------------------- input */

static void scroll_by(int delta) {
    size_t *scroll = &g_scroll[g_active];
    if (delta > 0) *scroll += (size_t)delta;
    else if ((size_t)(-delta) >= *scroll) *scroll = 0;
    else *scroll -= (size_t)(-delta);
    size_t count = ring_count(g_ring[g_active]);
    if (*scroll > count) *scroll = count;
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
            case 'H': scroll_by((int)ring_count(g_ring[g_active])); return;
            case 'F': scroll_by(-(int)ring_count(g_ring[g_active])); return;
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
                   if (!g_paused) g_scroll[g_active] = 0;
                   g_dirty = 1; break;
        case 'r': g_raw = !g_raw; g_dirty = 1; break;
        case 'c': ring_free(g_ring[g_active]);
                   g_ring[g_active] = NULL;
                   g_scroll[g_active] = 0;
                   g_dirty = 1; break;
        case 'g': scroll_by((int)ring_count(g_ring[g_active])); break;
        case 'G': case 'e': scroll_by(-(int)ring_count(g_ring[g_active])); break;
        default: break;
    }
}

void read_keys(void) {
    char b[256];
    ssize_t n = read(STDIN_FILENO, b, sizeof(b));
    if (n <= 0) return;

    size_t i = 0;
    while (i < (size_t)n) {
        size_t used = 1;
        key_normal(b + i, (size_t)n - i, &used);
        i += used;
    }
}
