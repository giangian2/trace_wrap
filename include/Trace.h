#include <stddef.h>
#ifndef TRACE_H
#define TRACE_H
#define MAX_LINE   2048
#define DISP_LEN   192
#define ENDP_LEN   64
#define SRC_BUF    (MAX_LINE * 4)


typedef enum { 
    EV_NET = 0, 
    EV_SYS, 
    EV_ERR 
} EvType;

typedef struct {
    EvType type;
    long   pid;                /* -1 when unknown */
    int    failed;             /* syscall returned a real error */
    char   ts[16];             /* timestamp as printed by strace -tt */
    char   name[32];           /* syscall name */
    char   text[MAX_LINE];     /* the original strace line, newline stripped */
    char   disp[DISP_LEN];     /* rendered network line; empty for EV_SYS */
} Event;

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

/* line source read() on a non-blocking fd hands back arbitrary chunks, 
 * so the source keeps a carry buffer holding the tail of a line until 
 * its newline shows up.
 */
typedef struct {
    int    fd;
    int    eof;
    size_t len;
    char   buf[SRC_BUF];
} Source;

/* direction a syscall moved data in, shared between the parser (chooses the
 * glyph/label) and the UI (chooses the row colour) */
typedef enum { 
    D_PLAIN, 
    D_OUT, 
    D_IN, 
    D_CONN, 
    D_ACCEPT, 
    D_CLOSE 
} Dir;

Dir dir_of(const char *name);

/* one ring buffer per pane, defined in trace_wrap_mon.c, read by UI.c */
enum { PANE_NET = 0, PANE_SYS = 1, PANE_N = 2 };
extern Event  *g_ring[PANE_N];
extern size_t  g_scroll[PANE_N];

#endif