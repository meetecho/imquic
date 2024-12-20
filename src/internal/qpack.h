/*! \file   qpack.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QPACK stack (WebTransport only) (headers)
 * \details Naive implementation of QPACK, which implements static and
 * dynamic tables, and Huffman encoding/decoding via static tables. This
 * code is only used for the WebTransport establishment via HTTP/3.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_QPACK_H
#define IMQUIC_QPACK_H

#include <stdint.h>

#include <glib.h>

/*! \brief Name-value entry we can have in the static or dynamic tables */
typedef struct imquic_qpack_entry {
	/*! \brief ID (for static or dynamic table) */
	uint16_t id;
	/*! \brief Name */
	const char *name;
	/*! \brief Value */
	const char *value;
} imquic_qpack_entry;
/*! \brief Create a new entry out of provided name and value
 * @param name Name of the new entry
 * @param value Value of the new entry
 * @returns A pointer to a new imquic_qpack_entry instance, if successful, or NULL otherwise */
imquic_qpack_entry *imquic_qpack_entry_create(const char *name, const char *value);
/*! \brief Helper to calculate the size of this entry
 * @param entry Entry instance to calculate the size for
 * @returns The size of the entry, as needed for the dynamic table size */
size_t imquic_qpack_entry_size(imquic_qpack_entry *entry);
/*! \brief Destroy an existing entry
 * @param entry Entry instance to destroy */
void imquic_qpack_entry_destroy(imquic_qpack_entry *entry);

/*! \brief Static table */
extern imquic_qpack_entry imquic_qpack_static_table[];

/*! \brief Dynamic table */
typedef struct imquic_qpack_dynamic_table {
	/*! \brief Size as advertized, and current size */
	size_t capacity, size;
	/*! \brief Current index */
	uint16_t index;
	/*! \brief Hashtable (indexed by ID) */
	GHashTable *table_byid;
	/*! \brief List of entries, ordered by insertion */
	GList *list;
} imquic_qpack_dynamic_table;
/*! \brief Create a new dynamic table
 * @param capacity The capacity of the dynamic table, as advertized
 * @returns A pointer to a new imquic_qpack_dynamic_table instance, if successful, or NULL otherwise  */
imquic_qpack_dynamic_table *imquic_qpack_dynamic_table_create(size_t capacity);
/*! \brief Destroy an existing dynamic table
 * @param table Dynamic table instance to destroy */
void imquic_qpack_dynamic_table_destroy(imquic_qpack_dynamic_table *table);

/*! \brief QPACK context */
typedef struct imquic_qpack_context {
	/*! \brief Local dynamic table (updated by us via the local encoder stream) */
	imquic_qpack_dynamic_table *ltable;
	/*! \brief Remote dynamic table (updated by the remote encoder stream) */
	imquic_qpack_dynamic_table *rtable;
} imquic_qpack_context;
/*! \brief Create a new QPACK context
 * @param capacity The capacity of the dynamic table, as advertized
 * @returns A pointer to a new imquic_qpack_context instance, if successful, or NULL otherwise  */
imquic_qpack_context *imquic_qpack_context_create(size_t capacity);
/*! \brief Destroy an existing QPACK context
 * @param ctx Context instance to destroy */
void imquic_qpack_context_destroy(imquic_qpack_context *ctx);

/** @name Interacting with QPACK
 */
///@{
/*! \brief Decode incoming QPACK encoder data
 * @note This is data coming from the encoder stream of our peer
 * @param ctx The imquic_qpack_context to update with the new encoder data
 * @param bytes The buffer containing the encoder data
 * @param blen Size of the encoder data
 * @returns The amount of processed encoder data */
size_t imquic_qpack_decode(imquic_qpack_context *ctx, uint8_t *bytes, size_t blen);
/*! \brief Decode an incoming QPACK request
 * @note This is data coming from a request. The GList and its contents
 * are owned by the caller, and so should be freed when not needed anymore.
 * @param[in] ctx The imquic_qpack_context to refer to
 * @param[in] bytes The buffer containing the request data
 * @param[in] blen Size of the request data
 * @param[out] bread The amount of processed request data
 * @returns A list of imquic_qpack_entry entries obtained from the request */
GList *imquic_qpack_process(imquic_qpack_context *ctx, uint8_t *bytes, size_t blen, size_t *bread);
/*! \brief Encode outgoing QPACK encoder data
 * @note This is data we'll send on our encoder stream
 * @param[in] ctx The imquic_qpack_context to use to encode the data
 * @param[in] headers List of headers to encode
 * @param[in] bytes The buffer to put the encoded data in
 * @param[out] blen Size of the encoded data buffer
 * @param[in] qenc The buffer to put the QPACK encoder info in, if any
 * @param[out] qenclen Size of the QPACK encoder info buffer
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_qpack_encode(imquic_qpack_context *ctx, GList *headers, uint8_t *bytes, size_t *blen, uint8_t *qenc, size_t *qenclen);
///@}

#endif
