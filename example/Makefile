CC=clang
LD=clang
CFLAGS=-g -Os -Wall -pedantic
LDFLAGS=

TARGET=example.out

SOURCES=$(wildcard *.c slac/*.c)
OBJECTS=$(SOURCES:.c=.o)

LIBS=\
	-L..\
	-lnikolav2g\
	-lmultitask\
	-lOpenV2G\
	-lpolarssl\
	-lm\
	-lrt\
	-lpthread\

INCLUDES=-I..

all: $(TARGET)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all
