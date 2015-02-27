CC=clang -std=gnu11
AS=clang -integrated-as -mllvm --x86-asm-syntax=intel
CFLAGS=-Os
AFLAGS=
PREFIX=/usr/local
ARCH=$(shell sh ./arch.sh $(CC) $(CFLAGS))

LIB=libmultitask.a

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
	multitask.h\

all: $(LIB)

$(SOURCES): $(HEADERS)

.s.o:
	$(AS) $(AFLAGS) -c -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -I. -c -o $@ $<

multitask.h: multitask.h.in
	sed -e '/%HEADER%/{r ../multitask.h' -e 'd}' $< > $@

$(LIB): $(OBJECTS)
	ar r $@ $(OBJECTS)

install: $(LIB)
	cp -f multitask.h "$(DESTDIR)/$(PREFIX)/include/"
	cp -f $(LIB) "$(DESTDIR)/$(PREFIX)/lib/"

clean:
	rm -f $(OBJECTS) $(LIB) multitask.h
