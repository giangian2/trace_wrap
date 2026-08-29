#ifndef UI_H
#define UI_H
#include <signal.h>

extern int g_quit;
extern int g_dirty;
extern int g_paused;        /* read by pane_push() to anchor a frozen view */
extern volatile sig_atomic_t g_resized;
extern volatile sig_atomic_t g_signalled;

void term_setup(void);
void term_size(void);
void render(void);
void read_keys(void);

#endif
