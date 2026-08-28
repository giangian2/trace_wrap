CC = gcc
CFLAGS = -O2 -Wall -Wextra
TARGET_C = trace_wrap_mon
PREFIX ?= /usr/local/bin

.PHONY: all clean install uninstall

all: $(TARGET_C)

$(TARGET_C): trace_wrap_mon.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET_C)

install: all
	install -d $(DESTDIR)$(PREFIX)
	install -m 755 trace_wrap.sh $(DESTDIR)$(PREFIX)/trace_wrap
	install -m 755 $(TARGET_C) $(DESTDIR)$(PREFIX)/$(TARGET_C)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/trace_wrap
	rm -f $(DESTDIR)$(PREFIX)/trace_wrap_tui.sh
	rm -f $(DESTDIR)$(PREFIX)/trace_wrap_c_filter
	rm -f $(DESTDIR)$(PREFIX)/$(TARGET_C)
