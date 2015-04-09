CC=clang
LD=clang
CFLAGS=-g -Os -Wall -pedantic
LDFLAGS=

TARGET=secc_test

SOURCES=\
	secc_test.c\
	../client.c\

HEADERS=\

OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\
	-L../..\
	-lnikolav2g\
	-lmultitask\
	-lOpenV2G\
	-lpolarssl\
	-lm\
	-lrt\
	-lpthread\

INCLUDES=-I../..

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)

all: $(TARGET)
