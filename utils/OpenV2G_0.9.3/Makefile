CC=clang
AR=ar
CFLAGS=-g -Os -Wall -pedantic -std=gnu11

PREFIX=/usr/local
LIBDIR=$(PREFIX)/lib
INCDIR=$(PREFIX)/include

TARGET=libOpenV2G.a

SOURCES=$(wildcard src/appHandshake/*.c src/codec/*.c src/din/*.c src/transport/*.c src/xmldsig/*.c)
HEADERS=$(wildcard src/appHandshake/*.h src/codec/*.h src/din/*.h src/transport/*.h src/xmldsig/*.h)
OBJECTS=$(SOURCES:.c=.o)
INCLUDEDIRS=$(wildcard src/*)
INCLUDES=$(INCLUDEDIRS:%=-I%)

$(TARGET): $(OBJECTS)
	$(AR) rcs $(TARGET) $(OBJECTS)

$(OBJECTS): $(HEADERS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	install -D $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	install -d $(DESTDIR)$(INCDIR)/OpenV2G
	install $(HEADERS) $(DESTDIR)$(INCDIR)/OpenV2G

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: install clean
