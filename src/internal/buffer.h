/*! \file   buffer.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Buffer abstraction (headers)
 * \details Abstraction of a chunked buffer, to be used either during
 * CRYPTO exchanges in the Initial/Handshake phase, or with STREAM after
 * a connection has been established. It provides a high level interface
 * to adding chunks to the queue (in a gap-aware way), and to retrieving
 * data in an ordered way (waiting in case gaps are encountered).
 *
 * \ingroup Core
 */

#ifndef IMQUIC_BUFFER_H
#define IMQUIC_BUFFER_H

#include <stdint.h>

#include <glib.h>

/*! \brief Buffer chunk */
typedef struct imquic_buffer_chunk {
	/*! \brief Data in this buffer chunk */
	uint8_t *data;
	/*! \brief Offset this data is in, in the overall overall buffer */
	uint64_t offset;
	/*! \brief Size of this this buffer chunk */
	uint64_t length;
} imquic_buffer_chunk;
/*! \brief Helper to create a chunk out of existing data
 * @param data The data to put in the chunk
 * @param offset The offset of the data in the parent buffer
 * @param length The size of the data
 * @returns A pointer to a new imquic_buffer_chunk instance, if successful, or NULL otherwise */
imquic_buffer_chunk *imquic_buffer_chunk_create(uint8_t *data, uint64_t offset, uint64_t length);
/*! \brief Helper to quickly free a buffer chunk
 * @param chunk The buffer chunk to free */
void imquic_buffer_chunk_free(imquic_buffer_chunk *chunk);

/*! \brief Buffer made of multiple chunks (possibly with gaps) */
typedef struct imquic_buffer {
	/*! \brief Stream ID this buffer is associated with
	 * @note Ignored when used for \c CRYPTO frames */
	uint64_t stream_id;
	/*! \brief Ordered list of chunks in this buffer */
	GList *chunks;
	/*! \brief Offset in the buffer to start from, when reading chunks from the buffer */
	uint64_t base_offset;
} imquic_buffer;
/*! \brief Helper method to create a new buffer
 * @param stream_id Stream ID this buffer belongs to (ignored when used with \c CRYPTO frames)
 * @returns A pointer to a new imquic_buffer instance, if successful, or NULL otherwise */
imquic_buffer *imquic_buffer_create(uint64_t stream_id);
/*! \brief Helper method to destroy an existing buffer
 * @param buf The imquic_buffer instance to destroy */
void imquic_buffer_destroy(imquic_buffer *buf);

/*! \brief Helper method to add new data to the buffer at a specific offset, as a new chunk
 * @note In case the new data overlaps data already in the buffer, the new data is truncated accordingly to fit
 * @param buf The imquic_buffer instance to add data to
 * @param data The data to add to the buffer
 * @param offset Offset in the overall buffer where this new data should be placed
 * @param length Length of this new data
 * @returns The number of bytes actually added to the buffer in case of success, or 0 otherwise */
uint64_t imquic_buffer_put(imquic_buffer *buf, uint8_t *data, uint64_t offset, uint64_t length);
/*! \brief Helper method to add new data at the end of the buffer, as a new chunk
 * @param buf The imquic_buffer instance to add data to
 * @param data The data to add to the buffer
 * @param length Length of this new data
 * @returns The number of bytes actually added to the buffer in case of success, or 0 otherwise */
uint64_t imquic_buffer_append(imquic_buffer *buf, uint8_t *data, uint64_t length);
/*! \brief Helper method to peek at a buffer and check if there's data to read
 * @note If there's data in the buffer, but the current offset points at a gap
 * of data that hasn't been added yet, this function will not return anything,
 * since this buffer API is conceived to read data in an ordered way. If
 * data is found, the base offset is not modified, which means a new
 * imquic_buffer_peek call will return the same chunk until imquic_buffer_get
 * is called.
 * @param buf The imquic_buffer instance to peek
 * @returns A buffer chunk, if successful, or NULL otherwise */
imquic_buffer_chunk *imquic_buffer_peek(imquic_buffer *buf);
/*! \brief Helper method to get a chunk of data from the buffer
 * @note If there's data in the buffer, but the current offset points at a gap
 * of data that hasn't been added yet, this function will not return anything,
 * since this buffer API is conceived to read data in an ordered way. If
 * data is found, the base offset is modified to point at the end of the
 * returned chunk, which means a new imquic_buffer_peek or imquic_buffer_get
 * call will point at the next chunk in the buffer.
 * @param buf The imquic_buffer instance to get the data from
 * @returns A buffer chunk, if successful, or NULL otherwise */
imquic_buffer_chunk *imquic_buffer_get(imquic_buffer *buf);

/*! \brief Helper method to print the contents of a buffer
 * @param level Log level at which this should be printed
 * @param buf The imquic_buffer instance whose content should be printed */
void imquic_buffer_print(int level, imquic_buffer *buf);

#endif
