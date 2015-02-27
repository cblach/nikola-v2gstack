CC=clang
LD=ar
CFLAGS=-Wall -pedantic -std=gnu11
LDFLAGS=rcs

TARGET=libnikolav2g.a

SOURCES=\
    sdp.c\
    plc_eth.c\
    tlsconn.c\
    map.c\
    session.c\

HEADERS=\
    plc_eth.h\
    libnikolav2g.h\
    map.h\
    homeplug.h\

OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\
/usr/local/lib/libmbedtls.a\
utils/libmultitask/unix/libmultitask.a\
utils/OpenV2G_0.9.3/libOpenV2G.a\


INCLUDES=\
    -Iutils/libmultitask/unix\
    -Iutils/OpenV2G_0.9.3/src/codec\
    -Iutils/OpenV2G_0.9.3/src/appHandshake\
    -Iutils/OpenV2G_0.9.3/src/transport\

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)
