/*! \file   buffer.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Buffer abstraction
 * \details Abstraction of a chunked buffer, to be used either during
 * CRYPTO exchanges in the Initial/Handshake phase, or with STREAM after
 * a connection has been established. It provides a high level interface
 * to adding chunks to the queue (in a gap-aware way), and to retrieving
 * data in an ordered way (waiting in case gaps are encountered).
 *
 * \ingroup Core
 */

#include "internal/buffer.h"
#include "imquic/debug.h"

imquic_buffer *imquic_buffer_create(uint64_t stream_id) {
	imquic_buffer *buf = g_malloc0(sizeof(imquic_buffer));
	buf->stream_id = stream_id;
	return buf;
}

void imquic_buffer_destroy(imquic_buffer *buf) {
	if(buf == NULL)
		return;
	if(buf->chunks != NULL)
		g_list_free_full(buf->chunks, (GDestroyNotify)imquic_buffer_chunk_free);
	g_free(buf);
}

imquic_buffer_chunk *imquic_buffer_chunk_create(uint8_t *data, uint64_t offset, uint64_t length) {
	if(length == 0 || (length > 0 && data == NULL))
		return NULL;
	imquic_buffer_chunk *chunk = g_malloc(sizeof(imquic_buffer_chunk));
	chunk->data = g_malloc(length);
	memcpy(chunk->data, data, length);
	chunk->offset = offset;
	chunk->length = length;
	return chunk;
}

void imquic_buffer_chunk_free(imquic_buffer_chunk *chunk) {
	if(chunk != NULL) {
		g_free(chunk->data);
		g_free(chunk);
	}
}

/* Helpers to add or get from the buffer */
uint64_t imquic_buffer_put(imquic_buffer *buf, uint8_t *data, uint64_t offset, uint64_t length) {
	if(buf == NULL || length == 0 || (length > 0 && data == NULL))
		return 0;
	if(offset < buf->base_offset) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%"SCNu64"] Ignoring already processed chunk (%"SCNu64" < %"SCNu64")\n",
			buf->stream_id, offset, buf->base_offset);
		return 0;
	}
	/* Check where we have to put it */
	GList *temp = buf->chunks;
	if(temp == NULL) {
		/* Empty list, easy enough */
		buf->chunks = g_list_append(buf->chunks, imquic_buffer_chunk_create(data, offset, length));
	} else {
		/* Traverse the list and find the correct insert point */
		gboolean inserted = FALSE;
		imquic_buffer_chunk *tc = NULL, *prev = NULL;
		while(temp) {
			tc = (imquic_buffer_chunk *)temp->data;
			if(tc->offset > offset) {
				/* Insert here */
				if(offset + length > tc->offset) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "[%"SCNu64"] Overlapping buffer (%"SCNu64"+%"SCNu64" > %"SCNu64"), truncating chunk\n",
						buf->stream_id, offset, length, tc->offset);
					length = tc->offset - offset;
				}
				if(prev != NULL && (prev->offset + prev->length > offset)) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "[%"SCNu64"] Overlapping buffer (%"SCNu64"+%"SCNu64" > %"SCNu64"), truncating chunk\n",
						buf->stream_id, prev->offset, prev->length, offset);
					uint64_t diff = prev->offset + prev->length - offset;
					offset += diff;
					data += diff;
					length = (length >= diff ? (length - diff) : 0);
				}
				inserted = TRUE;
				if(length > 0)
					buf->chunks = g_list_insert_before(buf->chunks, temp, imquic_buffer_chunk_create(data, offset, length));
				break;
			}
			prev = tc;
			temp = temp->next;
		}
		if(!inserted) {
			/* Append at the end */
			if(prev != NULL && (prev->offset + prev->length > offset)) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%"SCNu64"] Overlapping buffer (%"SCNu64"+%"SCNu64" > %"SCNu64"), truncating chunk\n",
					buf->stream_id, prev->offset, prev->length, offset);
				uint64_t diff = prev->offset + prev->length - offset;
				offset += diff;
				data += diff;
				length = (length >= diff ? (length - diff) : 0);
			}
			if(length > 0)
				buf->chunks = g_list_insert_before(buf->chunks, temp, imquic_buffer_chunk_create(data, offset, length));
		}
	}
	return length;
}

uint64_t imquic_buffer_append(imquic_buffer *buf, uint8_t *data, uint64_t length) {
	if(buf == NULL || length == 0 || (length > 0 && data == NULL))
		return 0;
	GList *last = g_list_last(buf->chunks);
	imquic_buffer_chunk *last_chunk = (imquic_buffer_chunk *)(last ? last->data : NULL);
	uint64_t offset = last_chunk ? (last_chunk->offset + last_chunk->length) : buf->base_offset;
	/* Always appending, easy enough */
	buf->chunks = g_list_append(buf->chunks, imquic_buffer_chunk_create(data, offset, length));
	return 0;
}

imquic_buffer_chunk *imquic_buffer_peek(imquic_buffer *buf) {
	if(buf == NULL || buf->chunks == NULL)
		return NULL;
	imquic_buffer_chunk *chunk = (imquic_buffer_chunk *)buf->chunks->data;
	if(chunk->offset > buf->base_offset) {
		/* There's still gaps */
		return NULL;
	}
	return chunk;
}

imquic_buffer_chunk *imquic_buffer_get(imquic_buffer *buf) {
	imquic_buffer_chunk *chunk = imquic_buffer_peek(buf);
	if(chunk != NULL) {
		buf->base_offset = chunk->offset + chunk->length;
		buf->chunks = g_list_delete_link(buf->chunks, g_list_first(buf->chunks));
	}
	return chunk;
}

/* Helper to print the contents of a buffer */
void imquic_buffer_print(int level, imquic_buffer *buf) {
	if(buf == NULL)
		return;
	IMQUIC_LOG(level, "Buffer (base offset %"SCNu64", %d chunks)\n",
		buf->base_offset, g_list_length(buf->chunks));
	GList *temp = buf->chunks;
	imquic_buffer_chunk *chunk = NULL;
	while(temp) {
		chunk = (imquic_buffer_chunk *)temp->data;
		IMQUIC_LOG(level, "  -- %"SCNu64"-->%"SCNu64" (length %"SCNu64")\n",
			chunk->offset, chunk->offset + chunk->length, chunk->length);
		temp = temp->next;
	}
}
