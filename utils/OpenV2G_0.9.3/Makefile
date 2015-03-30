CC=clang -Wall -pedantic -std=gnu11
LD=ar
CFLAGS=
LDFLAGS=rcs

TARGET=libOpenV2G.a

SOURCES=\
    src/codec/BitEncoderChannel.c\
    src/codec/BitOutputStream.c\
    src/codec/ByteEncoderChannel.c\
    src/codec/v2gEXIDatatypesDecoder.c\
    src/codec/v2gEXIDatatypes.c\
    src/codec/AbstractEncoderChannel.c\
    src/codec/EXIHeaderDecoder.c\
    src/codec/BitDecoderChannel.c\
    src/codec/BitInputStream.c\
    src/codec/AbstractDecoderChannel.c\
    src/codec/ByteDecoderChannel.c\
    src/codec/ByteStream.c\
    src/codec/EXIHeaderEncoder.c\
    src/codec/MethodsBag.c\
    src/codec/v2gEXIDatatypesEncoder.c\
    src/transport/v2gtp.c\
    src/appHandshake/appHandEXIDatatypesEncoder.c\
    src/appHandshake/appHandEXIDatatypes.c\
    src/appHandshake/appHandEXIDatatypesDecoder.c\
    src/din/dinEXIDatatypesEncoder.c\
    src/din/dinEXIDatatypes.c\
    src/din/dinEXIDatatypesDecoder.c\
    src/xmldsig/xmldsigEXIDatatypes.c\
    src/xmldsig/xmldsigEXIDatatypesEncoder.c\
    src/xmldsig/xmldsigEXIDatatypesDecoder.c\


OBJECTS=\
    $(SOURCES:.c=.o)\

LIBS=\

INCLUDES=\
    -Isrc/codec\
    -Isrc/transport\
    -Isrc/appHandshake\
    -Isrc/xmldsig\
    -Isrc/din\

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGET)
