/*! \file   buffer.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Buffer abstraction
 * \details Abstraction of buffered data.
 *
 * \ingroup Core
 */

#include "internal/buffer.h"
#include "imquic/debug.h"

/* Buffer */
imquic_buffer *imquic_buffer_create(uint8_t *bytes, uint64_t size) {
	imquic_buffer *buffer = g_malloc0(sizeof(imquic_buffer));
	if(bytes != NULL && size > 0 && imquic_buffer_append(buffer, bytes, size) < 0) {
		g_free(buffer);
		return NULL;
	}
	return buffer;
}

gboolean imquic_buffer_resize(imquic_buffer *buffer, uint64_t new_size) {
	if(buffer == NULL || buffer->size >= new_size)
		return FALSE;
	if(buffer->bytes == NULL)
		buffer->bytes = g_malloc(new_size);
	else
		buffer->bytes = g_realloc(buffer->bytes, new_size);
	buffer->size = new_size;
	return TRUE;
}

int imquic_buffer_append(imquic_buffer *buffer, uint8_t *bytes, uint64_t length) {
	if(buffer == NULL || bytes == NULL || length == 0)
		return -1;
	if(buffer->size < buffer->length + length) {
		if(!imquic_buffer_resize(buffer, buffer->length + length)) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't resize buffer\n");
			return -1;
		}
	}
	memcpy(buffer->bytes + buffer->length, bytes, length);
	buffer->length += length;
	return 0;
}

void imquic_buffer_shift(imquic_buffer *buffer, uint64_t length) {
	if(buffer == NULL || buffer->bytes == NULL || length == 0)
		return;
	if(length >= buffer->length) {
		buffer->length = 0;
	} else {
		memmove(buffer->bytes, buffer->bytes + length, buffer->length - length);
		buffer->length -= length;
	}
}

void imquic_buffer_destroy(imquic_buffer *buffer) {
	if(buffer != NULL) {
		g_free(buffer->bytes);
		g_free(buffer);
	}
}
