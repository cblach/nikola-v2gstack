CC=clang
AR=ar
CFLAGS=-g -Os -Wall -pedantic

PREFIX=/usr/local
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include

TARGET=libnikolav2g.a
HEADER=nikolav2g.h

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

$(TARGET): $(OBJECTS)
	$(AR) rcs $(TARGET) $(OBJECTS)

$(OBJECTS): $(HEADER)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -D $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	install -D $(HEADER) $(DESTDIR)$(INCDIR)/$(HEADER)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: install clean
