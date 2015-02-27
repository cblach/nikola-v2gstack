/*
 * Copyright (C) 2007-2015 Siemens AG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************************
 *
 * @author Daniel.Peintner.EXT@siemens.com
 * @version 0.9.3 
 * @contact Joerg.Heuer@siemens.com
 *
 * <p>Code generated by EXIdizer</p>
 * <p>Schema: V2G_CI_MsgDef.xsd</p>
 *
 *
 ********************************************************************/



#include "DecoderChannel.h"
#include "EXIOptions.h"
#include "BitInputStream.h"
#include "EXITypes.h"
#include "ErrorCodes.h"

#ifndef BYTE_DECODER_CHANNEL_C
#define BYTE_DECODER_CHANNEL_C


#if EXI_OPTION_ALIGNMENT == BYTE_ALIGNMENT

int decode(bitstream_t* stream, uint8_t* b) {
	int errn = 0;
#if EXI_STREAM == BYTE_ARRAY
	if ( (*stream->pos) < stream->size ) {
		*b = stream->data[(*stream->pos)++];
	} else {
		errn = EXI_ERROR_INPUT_STREAM_EOF;
	}
#endif /* EXI_STREAM == BYTE_ARRAY */
#if EXI_STREAM == FILE_STREAM
	*b = (uint8_t)(getc(stream->file));
	/* EOF cannot be used, 0xFF valid value */
	if ( feof(stream->file) || ferror(stream->file) ) {
		errn = EXI_ERROR_INPUT_STREAM_EOF;
	}
#endif /* EXI_STREAM == FILE_STREAM */

	return errn;
}

int decodeBoolean(bitstream_t* stream, int* b) {
	uint8_t bb;
	int errn = decode(stream, &bb);
	*b = (bb == 0) ? 0 : 1;
	return errn;
}

/**
 * Decodes and returns an n-bit unsigned integer using the minimum number of
 * bytes required for n bits.
 */
int decodeNBitUnsignedInteger(bitstream_t* stream, uint16_t nbits, uint32_t* uint32) {
	uint16_t bitsRead = 0;
	uint8_t b;
	int errn = 0;
	*uint32 = 0;

	while (errn == 0 && bitsRead < nbits) {
		errn = decode(stream, &b);
		*uint32 = *uint32 + (uint32_t)(b << bitsRead);
		bitsRead = (uint16_t)(bitsRead + 8);
	}

	return errn;
}

#endif

#endif
