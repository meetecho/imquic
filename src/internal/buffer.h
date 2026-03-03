/*! \file   buffer.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Buffer abstraction (headers)
 * \details Abstraction of buffered data.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_BUFFER_H
#define IMQUIC_BUFFER_H

#include <stdint.h>

#include <glib.h>

/*! \brief Internal buffer */
typedef struct imquic_buffer {
	/*! \brief Buffer containing the data */
	uint8_t *bytes;
	/*! \brief Size of the data currently in the buffer */
	uint64_t length;
	/*! \brief Overall size of the buffer */
	uint64_t size;
} imquic_buffer;
/*! \brief Create a new buffer
 * @note Passing empty data will only allocate an empty buffer instance
 * that can be updated/expanded later on.
 * @param bytes The data to initialize the buffer with, if any
 * @param size Size of the data, if any
 * @returns A pointer to a new imquic_buffer instance, if successful, or NULL otherwise */
imquic_buffer *imquic_buffer_create(uint8_t *bytes, uint64_t size);
/*! \brief Resize an existing buffer
 * @note We can only increase the size of the buffer, not reduce it.
 * @param buffer Buffer to resize
 * @param new_size New size of the buffer
 * @returns TRUE if successful, FALSE otherwise */
gboolean imquic_buffer_resize(imquic_buffer *buffer, uint64_t new_size);
/*! \brief Append data at the end of the buffer
 * @note This automatically resizes the buffer with imquic_buffer_resize,
 * if appending the new data would exceeds the buffer size.
 * @param buffer Buffer to append the new data to
 * @param bytes Data to append
 * @param length Size of the data to append
 * returns 0 if successful, a negative integer otherwise */
int imquic_buffer_append(imquic_buffer *buffer, uint8_t *bytes, uint64_t length);
/*! \brief Move the data in the buffer back of a specific number of bytes
 * @note This automatically updates the buffer length accordingly.
 * @param buffer Buffer to update
 * @param length How many bytes back the buffer should be moved */
void imquic_buffer_shift(imquic_buffer *buffer, uint64_t length);
/*! \brief Destroy an existing buffer
 * @param buffer Buffer to destroy */
void imquic_buffer_destroy(imquic_buffer *buffer);

#endif
