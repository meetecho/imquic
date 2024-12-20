/*! \file   utils.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Generic utilities (headers)
 * \details Implementation of a few more generic functionality that is
 * useful in the QUIC stack internals (e.g., varint support).
 *
 * \ingroup Core
 */

#ifndef IMQUIC_UTILS_H
#define IMQUIC_UTILS_H

#include <glib.h>

#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((guint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((guint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

/* https://stackoverflow.com/a/3208376 */
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
	((byte) & 0x80 ? '1' : '0'), \
	((byte) & 0x40 ? '1' : '0'), \
	((byte) & 0x20 ? '1' : '0'), \
	((byte) & 0x10 ? '1' : '0'), \
	((byte) & 0x08 ? '1' : '0'), \
	((byte) & 0x04 ? '1' : '0'), \
	((byte) & 0x02 ? '1' : '0'), \
	((byte) & 0x01 ? '1' : '0')

/** @name String utilities
 */
///@{
/*! \brief Helper method to concatenate strings and log an error if truncation occurred
 * @param[in] dest Destination buffer, already containing one nul-terminated string
 * @param[in] src Source buffer
 * @param[in] dest_size Length of dest buffer in bytes (not length of existing string inside dest)
 * @returns Size of attempted result, if retval >= dest_size, truncation occurred (and an error will be logged). */
size_t imquic_strlcat(char *dest, const char *src, size_t dest_size);
/*! \brief Alternative helper method to concatenate strings and log an error if truncation occurred,
 * which uses memccpy instead of g_strlcat and so is supposed to be faster
 * @note The offset attribute is input/output, and updated any time the method is called
 * @param[in] dest Destination buffer, already containing one nul-terminated string
 * @param[in] src Source buffer
 * @param[in] dest_size Length of dest buffer in bytes (not length of existing string inside dest)
 * @param[in] offset Offset of where to start appending, in the destination buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_strlcat_fast(char *dest, const char *src, size_t dest_size, size_t *offset);
///@}

/** @name 64-bit unsigned integers utilities
 */
///@{
/*! \brief Helper to generate random 64 bit unsigned integers
 * @note This will fall back to a non-cryptographically safe PRNG in case
 * the crypto library RAND_bytes() call fails.
 * @returns A (mostly crypto-safe) random 64-bit unsigned integer */
uint64_t imquic_random_uint64(void);
/*! \brief Helper to generate an allocated copy of a uint64_t number
 * @note While apparently silly, this is needed in order to make sure uint64_t values
 * used as keys in GHashTable operations are not lost: using temporary uint64_t numbers
 * in a g_hash_table_insert, for instance, will cause the key to contain garbage as
 * soon as the temporary variable is lost, and all opererations on the key to fail
 * @param num The uint64_t number to duplicate
 * @returns A pointer to a uint64_t number, if successful, NULL otherwise */
uint64_t *imquic_dup_uint64(uint64_t num);
///@}

/** @name Variable size integers
 */
///@{
/*! \brief Read a variable size integer from a buffer
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to read the next value. In case of issues in the parsing,
 * length will have value 0.
 * @param[in] bytes The buffer to read
 * @param[in] blen The size of the buffer
 * @param[out] length How many bytes the variable size integer used
 * @returns The variable size integer, if length is higher than 0 */
uint64_t imquic_read_varint(uint8_t *bytes, size_t blen, uint8_t *length);
/*! \brief Write a variable size integer to a buffer
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to write the next value. In case of issues in the writing,
 * length will have value 0.
 * @param[in] number The number to write as a variable size integer
 * @param[in] bytes The buffer to write to
 * @param[in] blen The size of the buffer
 * @returns How many bytes the variable size integer used, if successful, 0 otherwise */
uint8_t imquic_write_varint(uint64_t number, uint8_t *bytes, size_t blen);
/*! \brief Read a prefixed integer from a buffer (QPACK only)
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to read the next value. In case of issues in the parsing,
 * length will have value 0.
 * @param[in] n The N prefix
 * @param[in] bytes The buffer to read
 * @param[in] blen The size of the buffer
 * @param[out] length How many bytes the variable size integer used
 * @returns The prefixed integer, if length is higher than 0 */
uint64_t imquic_read_pfxint(uint8_t n, uint8_t *bytes, size_t blen, uint8_t *length);
/*! \brief Write a prefixed integer to a buffer (QPACK only)
 * @note You can use the return value to know how many bytes to skip in
 * the buffer to write the next value. In case of issues in the writing,
 * length will have value 0.
 * @param[in] number The number to write as a variable size integer
 * @param[in] n The N prefix
 * @param[in] bytes The buffer to write to
 * @param[in] blen The size of the buffer
 * @returns How many bytes the variable size integer used, if successful, 0 otherwise */
uint8_t imquic_write_pfxint(uint64_t number, uint8_t n, uint8_t *bytes, size_t blen);
///@}

/*! \brief Helper method to reconstruct a full QUIC packet number
 * @param largest The largest packet number received so far at this encryption level
 * @param pn_pkt The received packet number
 * @param p_len How many bytes the received packet number used as a variable size integer
 * @returns The full reconstructed packet number */
uint64_t imquic_full_packet_number(uint64_t largest, uint64_t pn_pkt, uint8_t p_len);

/*! \brief Helper method mostly used for debugging: prints the content of a hex buffer
 * @param level Log level at which this should be printed
 * @param buf Buffer whose content need to be printed
 * @param buflen How many bytes in the buffer should be printed */
void imquic_print_hex(int level, uint8_t *buf, size_t buflen);

/** @name Generic data buffer
 */
///@{
/*! \brief Generic data buffer */
typedef struct imquic_data {
	/*! \brief Data buffer */
	uint8_t *buffer;
	/*! \brief Data length */
	size_t length;
} imquic_data;
/*! \brief Helper method to create a data buffer out of existing data
 * @param buffer The data to copy in the new buffer
 * @param length How many bytes to copy from the original data
 * @returns A pointer to a new imquic_data instance, if successful, or NULL otherwise */
imquic_data *imquic_data_create(uint8_t *buffer, size_t length);
/*! \brief Helper comparator function, to check if two buffers contain the same data
 * @note Helpful as a callback comparator function
 * @param a Opaque pointer to the first data buffer to compare
 * @param b Opaque pointer to the second data buffer to compare
 * @returns TRUE if the two buffers contain the same data, FALSE otherwise */
gboolean imquic_data_equal(const void *a, const void *b);
/*! \brief Helper method to free an existing data buffer
 * @param data The data buffer to free */
void imquic_data_destroy(imquic_data *data);
/*! \brief Generic fixed size data buffer */
typedef struct imquic_data_fixed {
	/*! \brief Fixed size data buffer */
	uint8_t buffer[1500];	/* FIXME */
	/*! \brief Data length */
	size_t length;
} imquic_data_fixed;
///@}

/** @name Bitstream (currently only used for Huffman in QPACK)
 */
///@{
/*! \brief Bitstream abstraction */
typedef struct imquic_bitstream {
	/*! \brief Buffer containing the data */
	uint8_t *buffer;
	/*! \brief Size of the buffer in bits */
	size_t size;
	/*! \brief Current position in the bitstream, in bits */
	size_t offset;
} imquic_bitstream;
/*! \brief Helper method to peek 8 bit in the bitstream
 * @note This method only peeks at the data, but doesn't advance the offset
 * position in the bitstream. There's no function to "consume" data, as
 * that can be done by simply modifying the offset property, which is
 * what the QPACK stack does when decoding Huffman codes internally.
 * @param[in] bs The bitstream instance to peek
 * @param[out] len How many bits were actually put in the byte
 * @returns A byte containing up to 8 bits from the bitstream, without advancing the offset */
uint8_t imquic_bitstream_peek(imquic_bitstream *bs, uint8_t *len);
/*! \brief Helper method to add bits to a bitstream buffer
 * @param bs The bitstream instance to update
 * @param value Integer containing the data to write
 * @param bits Number of bits from the integer to actually write
 * @returns The number of bits written to the buffer */
size_t imquic_bitstream_write(imquic_bitstream *bs, uint32_t value, uint8_t bits);
///@}

#endif
