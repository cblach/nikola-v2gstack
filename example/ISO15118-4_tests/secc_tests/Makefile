CC=clang
LD=clang -Wall -pedantic -std=gnu11 -fno-strict-aliasing
CFLAGS=
LDFLAGS=

TARGET=secc_test.out

SOURCES=\
    secc_test.c\

HEADERS=\

OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\
../../../libnikolav2g.a\
-lmultitask\
-lOpenV2G\
-lmbedtls\
-lm\
-lrt\
-lpthread\

INCLUDES=\
    -I../../\
    -I../../../\
    -I../../../utils/libmultitask/unix\
    -I../../../utils/OpenV2G_0.9.3/src/codec\
    -I../../../utils/OpenV2G_0.9.3/src/appHandshake\
    -I../../../utils/OpenV2G_0.9.3/src/transport\
    -I../../../utils/OpenV2G_0.9.3/src/xmldsig\

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)
