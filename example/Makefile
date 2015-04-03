CC=clang
LD=clang -Wall -pedantic -std=gnu11 -fno-strict-aliasing
CFLAGS=
LDFLAGS=

TARGET=example.out

SOURCES=\
    test.c\
    example_server.c\
    example_client.c\
    slac/slacassoc.c\
    slac/powerlinegp_evse_slac.c\

HEADERS=\

OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\
../libnikolav2g.a\
../utils/libmultitask/unix/libmultitask.a\
../utils/OpenV2G_0.9.3/libOpenV2G.a\
/usr/local/lib/libmbedtls.a\
-lm\
-lrt\
-lpthread\

INCLUDES=\
    -Islac/\
    -I../\
    -I../utils/libmultitask/unix\
    -I../utils/OpenV2G_0.9.3/src/codec\
    -I../utils/OpenV2G_0.9.3/src/appHandshake\
    -I../utils/OpenV2G_0.9.3/src/transport\
    -I../utils/OpenV2G_0.9.3/src/xmldsig\

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)
