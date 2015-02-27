CC=clang -std=gnu11
AS=clang -integrated-as -mllvm --x86-asm-syntax=intel
CFLAGS=-Os
AFLAGS=
PREFIX=/usr/local
LIBDIR=$(PREFIX)/lib
ARCH=$(shell sh ./arch.sh $(CC) $(CFLAGS))

LIB=libmultitask.a
HEADER=multitask.h

SOURCES=\
	../chan.c\
	../iochan.c\
	../lock.c\
	../qlock.c\
	../queue.c\
	../ref.c\
	../rendez.c\
	../task.c\
	../task-$(ARCH).s\
	../timechan.c\
	../timequeue.c\

TMP=$(SOURCES:.c=.o)

OBJECTS=$(TMP:.s=.o)

HEADERS=\
	../multitask-impl.h\
	u.h\
	libc.h\
	$(HEADER)\

all: $(LIB)

$(SOURCES): $(HEADERS)

.s.o:
	$(AS) $(AFLAGS) -c -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -I. -c -o $@ $<

$(HEADER): $(HEADER).in
	sed -e "/%HEADER%/{r ../$(HEADER)" -e "d}" $< > $@

$(LIB): $(OBJECTS)
	ar rusc $@ $(OBJECTS)

install: $(LIB)
	install -D -m 644 $(HEADER) "$(DESTDIR)/$(PREFIX)/include/$(HEADER)"
	install -D -m 644 $(LIB) "$(DESTDIR)/$(LIBDIR)/$(LIB)"

clean:
	rm -f $(OBJECTS) $(LIB) $(HEADER)
