/*! \file   qpack.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QPACK stack (WebTransport only)
 * \details Naive implementation of QPACK, which implements static and
 * dynamic tables, and Huffman encoding/decoding via static tables. This
 * code is only used for the WebTransport establishment via HTTP/3.
 *
 * \ingroup Core
 */

#include "internal/qpack.h"
#include "internal/huffman.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Static helpers to decode and encode Huffman codes, using the tables in huffman.h */
static char *imquic_qpack_huffman_decode(uint8_t *buffer, size_t size, char *text, size_t tlen) {
	if(buffer == NULL || size == 0 || text == NULL || tlen < 1)
		return NULL;
	imquic_bitstream bs = { 0 };
	bs.offset = 0;
	bs.buffer = buffer;
	bs.size = size * 8;
	/* Read the first byte and start processing */
	uint8_t cur = 0;
	uint8_t len = 0, byte = 0, bits = 0;
	imquic_huffman_table *table = imquic_huffman_transitions[0];
	while(bs.offset < bs.size) {
		byte = imquic_bitstream_peek(&bs, &len);
		if(bits == 0 && len < 5) {
			/* Not enough bits for a symbol */
			break;
		}
		if(table[byte].num_bits < 0) {
			/* Check the next one */
			table = imquic_huffman_transitions[abs(table[byte].num_bits)];
			if(table == NULL) {
				/* EOS, let's stop here */
				break;
			}
			bits += 8;
			bs.offset += 8;
			continue;
		} else if((size_t)table[byte].num_bits > (bs.size - bs.offset)) {
			/* The bits we found are padding, let's stop here */
			break;
		}
		/* We have a symbol */
		if(cur < tlen) {
			text[cur] = table[byte].symbol;
			cur++;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "String output insufficient for Huffman decoding, output will be truncated\n");
		}
		bs.offset += table[byte].num_bits;
		/* Reset and move to the next symbol */
		if(table != imquic_huffman_transitions[0])
			table = imquic_huffman_transitions[0];
		bits = 0;
	}
	text[cur] = '\0';
	return text;
}

static size_t imquic_qpack_huffman_encode(const char *text, uint8_t *buffer, size_t size) {
	if(text == NULL || strlen(text) == 0 || buffer == NULL || size == 0)
		return 0;
	memset(buffer, 0, size);
	imquic_bitstream bs = { 0 };
	bs.offset = 0;
	bs.buffer = buffer;
	bs.size = size * 8;
	size_t written = 0, len = strlen(text), i = 0;
	imquic_huffman_bits bits;
	for(i=0; i<len; i++) {
		bits = table[(uint8_t)text[i]];
		written = imquic_bitstream_write(&bs, bits.value, bits.len);
		if(written == 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Error writing Huffman encoded bits...\n");
			return 0;
		}
	}
	size_t mod = bs.offset % 8, index = bs.offset/8;
	if(mod > 0) {
		/* Add EOS padding */
		for(i=0; i<8-mod; i++) {
			bs.buffer[index] |= (1 << i);
			bs.offset++;
		}
		index++;
	}
	return bs.offset;
}

/* Entries */
imquic_qpack_entry *imquic_qpack_entry_create(const char *name, const char *value) {
	imquic_qpack_entry *entry = g_malloc(sizeof(imquic_qpack_entry));
	entry->id = 0;	/* Something else will fill this */
	entry->name = name ? g_strdup(name) : NULL;
	entry->value = value ? g_strdup(value) : NULL;
	return entry;
}

void imquic_qpack_entry_destroy(imquic_qpack_entry *entry) {
	if(entry) {
		g_free((char *)entry->name);
		g_free((char *)entry->value);
		g_free(entry);
	}
}

size_t imquic_qpack_entry_size(imquic_qpack_entry *entry) {
	size_t size = 0;
	if(entry) {
		entry += (entry->name ? strlen(entry->name) : 0) +
			(entry->value ? strlen(entry->value) : 0) + 32;
	}
	return size;
}

/* Dynamic tables */
imquic_qpack_dynamic_table *imquic_qpack_dynamic_table_create(size_t capacity) {
	imquic_qpack_dynamic_table *table = g_malloc(sizeof(imquic_qpack_dynamic_table));
	table->capacity = capacity;
	table->size = 0;
	table->index = 0;
	table->table_byid = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_qpack_entry_destroy);
	table->list = NULL;
	return table;
}

void imquic_qpack_dynamic_table_destroy(imquic_qpack_dynamic_table *table) {
	if(table == NULL)
		return;
	if(table->table_byid)
		g_hash_table_unref(table->table_byid);
	g_list_free(table->list);
	g_free(table);
}

/* QPACK context */
imquic_qpack_context *imquic_qpack_context_create(size_t capacity) {
	imquic_qpack_context *ctx = g_malloc(sizeof(imquic_qpack_context));
	ctx->ltable = imquic_qpack_dynamic_table_create(capacity);
	ctx->rtable = imquic_qpack_dynamic_table_create(capacity);
	return ctx;
}

void imquic_qpack_context_destroy(imquic_qpack_context *ctx) {
	if(ctx) {
		imquic_qpack_dynamic_table_destroy(ctx->ltable);
		imquic_qpack_dynamic_table_destroy(ctx->rtable);
		g_free(ctx);
	}
}

/* Helper to find a reference for a provided header to encode, which
 * also returns info on which table we found it in, and whether it
 * matches the header completely or just the name and not the value */
static imquic_qpack_entry *imquic_qpack_find_entry(imquic_qpack_dynamic_table *dtable, imquic_qpack_entry *entry, gboolean *dynamic, gboolean *full_match) {
	if(dtable == NULL || entry == NULL || entry->name == NULL)
		return NULL;
	imquic_qpack_entry *ref = NULL, *temp = NULL;
	if(dynamic)
		*dynamic = FALSE;
	if(full_match)
		*full_match = FALSE;
	/* Look in the static table first */
	gboolean is_dynamic = FALSE, is_full_match = FALSE;
	for(int i=0; i<99; i++) {
		temp = &imquic_qpack_static_table[i];
		if(!strcasecmp(temp->name, entry->name)) {
			if(temp->value == NULL && entry->value == NULL) {
				/* Found */
				ref = temp;
				is_full_match = TRUE;
				break;
			} else if(temp->value && entry->value && !strcasecmp(temp->value, entry->value)) {
				/* Found */
				ref = temp;
				is_full_match = TRUE;
				break;
			} else if(ref == NULL) {
				/* Found a partial match we can use as a reference */
				ref = temp;
			}
		}
	}
	if(ref && is_full_match) {
		if(full_match)
			*full_match = TRUE;
		return ref;
	}
	/* Now look in the dynamic table too */
	GList *list = dtable->list;
	while(list) {
		temp = (imquic_qpack_entry *)list->data;
		if(!strcasecmp(temp->name, entry->name)) {
			if(temp->value == NULL && entry->value == NULL) {
				/* Found */
				ref = temp;
				is_dynamic = TRUE;
				is_full_match = TRUE;
				break;
			} else if(temp->value && entry->value && !strcasecmp(temp->value, entry->value)) {
				/* Found */
				ref = temp;
				is_dynamic = TRUE;
				is_full_match = TRUE;
				break;
			} else if(ref == NULL) {
				/* Found a partial match we can use as a reference */
				ref = temp;
				is_dynamic = TRUE;
			}
		}
		list = list->next;
	}
	/* Done */
	if(dynamic)
		*dynamic = is_dynamic;
	if(full_match)
		*full_match = is_full_match;
	return ref;
}

/* Pocessing methods */
size_t imquic_qpack_decode(imquic_qpack_context *ctx, uint8_t *bytes, size_t blen) {
	if(ctx == NULL || bytes == NULL || blen < 1)
		return 0;
	/* Process the encoder data */
	size_t offset = 0;
	uint64_t parsed = 0;
	uint8_t length = 0;
	imquic_qpack_entry *ref = NULL, *entry = NULL;
	while(offset < blen) {
		/* Read the first 3 bits */
		uint8_t b0 = bytes[offset] & 0x80;
		uint8_t b1 = bytes[offset] & 0x40;
		uint8_t b2 = bytes[offset] & 0x20;
		if(!b0 && !b1 && b2) {
			/* Set Dynamic Table Capacity */
			parsed = imquic_read_pfxint(5, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing 'Set Dynamic Table Capacity' value\n");
				break;
			}
			/* TODO Handle the value */
			if(parsed > ctx->rtable->size) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Received a 'Set Dynamic Table Capacity' with a larger size than the current one\n");
				break;
			}
			offset += length;
		} else if(b0) {
			/* Insert with Name Reference */
			parsed = imquic_read_pfxint(6, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name Reference\n");
				break;
			}
			if(b1) {
				/* Reference is to the static table */
				ref = &imquic_qpack_static_table[parsed];
			} else {
				/* Reference is to the dynamic table */
				uint32_t id = parsed;
				ref = g_hash_table_lookup(ctx->rtable->table_byid, GUINT_TO_POINTER(id));
			}
			if(ref == NULL)
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in %s table\n", parsed, b1 ? "static" : "dynamic");
			offset += length;
			uint8_t h = bytes[offset] & 0x80;
			parsed = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Value Length value\n");
				break;
			}
			offset += length;
			char value[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, value, sizeof(value));
			} else {
				/* Regular text */
				g_snprintf(value, sizeof(value), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			if(ref) {
				entry = imquic_qpack_entry_create(ref->name, value);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Insert with Name Reference: %s = %s\n", entry->name, entry->value);
				/* FIXME Add to dynamic table */
				entry->id = ctx->rtable->index;
				g_hash_table_insert(ctx->rtable->table_byid, GUINT_TO_POINTER(entry->id), entry);
				ctx->rtable->list = g_list_prepend(ctx->rtable->list, entry);
				ctx->rtable->size += imquic_qpack_entry_size(entry);
				ctx->rtable->index++;
			}
			/* Move on */
			offset += parsed;
		} else if(!b0 && b1) {
			/* Insert with Literal Name */
			parsed = imquic_read_pfxint(5, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name length\n");
				break;
			}
			offset += length;
			char name[256];
			if(b2) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, name, sizeof(name));
			} else {
				/* Regular text */
				g_snprintf(name, sizeof(name), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			offset += parsed;
			uint8_t h = bytes[offset] & 0x80;
			parsed = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Value Length value\n");
				break;
			}
			offset += length;
			char value[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, value, sizeof(value));
			} else {
				/* Regular text */
				g_snprintf(value, sizeof(value), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			entry = imquic_qpack_entry_create(name, value);
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Insert with Literal Name: %s = %s\n", entry->name, entry->value);
			/* FIXME Add to dynamic table */
			entry->id = ctx->rtable->index;
			g_hash_table_insert(ctx->rtable->table_byid, GUINT_TO_POINTER(entry->id), entry);
			ctx->rtable->list = g_list_prepend(ctx->rtable->list, entry);
			ctx->rtable->size += imquic_qpack_entry_size(entry);
			ctx->rtable->index++;
			/* Move on */
			offset += parsed;
		} else if(!b0 && !b1 && !b2) {
			/* Duplicate */
			parsed = imquic_read_pfxint(6, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name Index\n");
				break;
			}
			/* Reference is to the dynamic table */
			uint32_t id = parsed;
			ref = g_hash_table_lookup(ctx->rtable->table_byid, GUINT_TO_POINTER(id));
			if(ref == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in %s table\n", parsed, b1 ? "static" : "dynamic");
			} else {
				entry = imquic_qpack_entry_create(ref->name, ref->value);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Duplicate: %s = %s\n", entry->name, entry->value);
				/* FIXME Add to dynamic table */
				entry->id = ctx->rtable->index;
				g_hash_table_insert(ctx->rtable->table_byid, GUINT_TO_POINTER(entry->id), entry);
				ctx->rtable->list = g_list_prepend(ctx->rtable->list, entry);
				ctx->rtable->size += imquic_qpack_entry_size(entry);
				ctx->rtable->index++;
				/* Move on */
			}
			offset += length;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Unkwown start code: " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[offset]));
			break;
		}
	}
	return offset;
}

GList *imquic_qpack_process(imquic_qpack_context *ctx, uint8_t *bytes, size_t blen, size_t *bread) {
	if(ctx == NULL || bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	/* Before iterating on the Encoded Field Lines, let's get the first two integers */
	uint8_t length = 0;
	uint64_t ric = imquic_read_pfxint(8, &bytes[offset], blen-offset, &length);
	if(length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Required Insert Count value\n");
		return NULL;
	}
	offset += length;
	uint8_t s = bytes[offset] & 0x80;
	uint64_t delta = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
	if(length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Delta Base value\n");
		return NULL;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Processing QPACK header (Required Insert Count: %"SCNu64", S=%"SCNu8", Delta Base=%"SCNu64")\n",
		ric, (s ? 1:  0), delta);
	offset += length;
	/* Now let's process the encoder data */
	GList *headers = NULL;
	uint64_t parsed = 0;
	imquic_qpack_entry *ref = NULL, *entry = NULL;
	while(offset < blen) {
		/* Read the first 4 bits */
		uint8_t b0 = bytes[offset] & 0x80;
		uint8_t b1 = bytes[offset] & 0x40;
		uint8_t b2 = bytes[offset] & 0x20;
		uint8_t b3 = bytes[offset] & 0x10;
		if(b0) {
			/* Indexed Field Line */
			parsed = imquic_read_pfxint(6, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Index value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			/* Find the entry, clone it and add it to the headers list */
			if(b1) {
				/* Reference is to the static table */
				ref = &imquic_qpack_static_table[parsed];
			} else {
				/* Reference is to the dynamic table */
				uint32_t id = parsed;
				ref = g_hash_table_lookup(ctx->rtable->table_byid, GUINT_TO_POINTER(id));
			}
			if(ref == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in %s table\n", parsed, b1 ? "static" : "dynamic");
			} else {
				entry = imquic_qpack_entry_create(ref->name, ref->value);
				headers = g_list_prepend(headers, entry);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Indexed Field Line: [%"SCNu64"] --> %s = %s\n", parsed, entry->name, entry->value);
			}
		} else if(!b0 && !b1 && !b2 && b3) {
			/* Indexed Field Line with Post-Base Index */
			parsed = imquic_read_pfxint(4, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Index value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			/* TODO Find the entry, clone it and add it to the headers list */
			uint32_t id = parsed;
			ref = g_hash_table_lookup(ctx->rtable->table_byid, GUINT_TO_POINTER(id));
			if(ref == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in dynamic table\n", parsed);
			} else {
				entry = imquic_qpack_entry_create(ref->name, ref->value);
				headers = g_list_prepend(headers, entry);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Indexed Field Line with Post-Base Index: [%"SCNu64"] --> %s = %s\n",
					parsed, entry->name, entry->value);
			}
		} else if(!b0 && b1) {
			/* Literal Field Line with Name Reference */
			uint64_t index = imquic_read_pfxint(4, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name Index value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			uint8_t h = bytes[offset] & 0x80;
			parsed = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Value Length value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			char value[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, value, sizeof(value));
			} else {
				/* Regular text */
				g_snprintf(value, sizeof(value), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			offset += parsed;
			/* Find the entry, clone it with the new value and add it to the headers list */
			ref = &imquic_qpack_static_table[index];
			if(ref == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in %s table\n", parsed, b1 ? "static" : "dynamic");
			} else {
				entry = imquic_qpack_entry_create(ref->name, strlen(value) > 0 ? value : NULL);
				headers = g_list_prepend(headers, entry);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Literal Field Line with Name Reference: [%"SCNu64"] --> %s = %s\n",
					index, entry->name, entry->value);
			}
		} else if(!b0 && !b1 && !b2 && !b3) {
			/* Literal Field Line with Post-Base Name Reference */
			//~ uint8_t n = bytes[offset] & 0x08;
			uint64_t index = imquic_read_pfxint(3, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name Index value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			uint8_t h = bytes[offset] & 0x80;
			parsed = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Value Length value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			char value[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, value, sizeof(value));
			} else {
				/* Regular text */
				g_snprintf(value, sizeof(value), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			offset += parsed;
			/* Find the entry, clone it with the new value and add it to the headers list */
			uint32_t id = index;
			ref = g_hash_table_lookup(ctx->rtable->table_byid, GUINT_TO_POINTER(id));
			if(ref == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't find reference '%"SCNu64"' in dynamic table\n", index);
			} else {
				entry = imquic_qpack_entry_create(ref->name, strlen(value) > 0 ? value : NULL);
				headers = g_list_prepend(headers, entry);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Literal Field Line with Post-Base Name Reference: [%"SCNu64"] --> %s = %s\n",
					index, entry->name, entry->value);
			}
		} else if(!b0 && !b1 && b2) {
			/* Literal Field Line with Literal Name */
			uint8_t h = bytes[offset] & 0x08;
			parsed = imquic_read_pfxint(3, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Name Length value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			char name[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, name, sizeof(name));
			} else {
				/* Regular text */
				g_snprintf(name, sizeof(name), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			offset += parsed;
			h = bytes[offset] & 0x80;
			parsed = imquic_read_pfxint(7, &bytes[offset], blen-offset, &length);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error parsing Value Length value\n");
				g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
				return NULL;
			}
			offset += length;
			char value[256];
			if(h) {
				/* Huffman encoded */
				imquic_qpack_huffman_decode(&bytes[offset], parsed, value, sizeof(value));
			} else {
				/* Regular text */
				g_snprintf(value, sizeof(value), "%.*s\n", (int)parsed, &bytes[offset]);
			}
			offset += parsed;
			/* Create a new entry with the provided name/value and add it to the headers list */
			entry = imquic_qpack_entry_create(strlen(name) > 0 ? name : NULL, strlen(value) > 0 ? value : NULL);
			headers = g_list_prepend(headers, entry);
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "[QPACK] Literal Field Line with Literal Name: %s = %s\n",
				entry->name, entry->value);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Unkwown start code: " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(bytes[offset]));
			g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
			return NULL;
		}
	}
	headers = g_list_reverse(headers);
	if(bread)
		*bread = offset;
	return headers;
}

int imquic_qpack_encode(imquic_qpack_context *ctx, GList *headers, uint8_t *bytes, size_t *blen, uint8_t *qenc, size_t *qenclen) {
	if(ctx == NULL || bytes == NULL || blen == NULL || *blen < 1 || qenc == NULL || qenclen == NULL || *qenclen < 1)
		return -1;
	/* Traverse the list of headers we need to encode: in case we need
	 * to add entries to the dynamic table, prepare the related
	 * encoder instructions to send on our encoder stream as well */
	imquic_qpack_entry *entry = NULL, *ref = NULL;
	gboolean dynamic = FALSE, full_match = FALSE;
	memset(bytes, 0, *blen);
	memset(qenc, 0, *qenclen);
	uint8_t temp[1024], encoded[100];
	size_t tlen = sizeof(temp);
	memset(temp, 0, tlen);
	size_t offset = 0, qoffset = 0, toffset = 0, res = 0;
	uint8_t length = 0;
	while(headers) {
		entry = (imquic_qpack_entry *)headers->data;
		/* Do we have this already? */
		ref = imquic_qpack_find_entry(ctx->ltable, entry, &dynamic, &full_match);
		if(ref == NULL) {
			/* No match at all, send a Literal Field Line with Literal Name */
			res = imquic_qpack_huffman_encode(entry->name, encoded, sizeof(encoded));
			res = res/8;
			temp[toffset] = 0;
			length = imquic_write_pfxint(res, 3, &temp[toffset], *qenclen-toffset);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Name Length for Literal Field Line with Literal Name\n");
				return -1;
			}
			temp[toffset] |= 0x20;	/* 001 */
			temp[toffset] |= 0x10;	/* N=1 */
			temp[toffset] |= 0x08;	/* H=1 */
			toffset += length;
			memcpy(&temp[toffset], encoded, res);
			toffset += res;
			res = 0;
			if(entry->value) {
				res = imquic_qpack_huffman_encode(entry->value, encoded, sizeof(encoded));
				res = res/8;
			}
			temp[toffset] = 0;
			length = imquic_write_pfxint(res, 7, &temp[toffset], *qenclen-toffset);
			if(length == 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Value Length for Literal Field Line with Literal Name\n");
				return -1;
			}
			temp[toffset] |= 0x80;	/* H=1 */
			toffset += length;
			if(res > 0) {
				memcpy(&temp[toffset], encoded, res);
				toffset += res;
			}
		} else {
			/* Do we have a full match, or only an entry with the header name? */
			if(full_match) {
				/* We have a full match, add an Indexed Field Line to the message */
				temp[toffset] = 0;
				length = imquic_write_pfxint(ref->id, 6, &temp[toffset], tlen-toffset);
				if(length == 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Index for Indexed Field Line\n");
					return -1;
				}
				temp[toffset] |= 0x80;	/* 1 */
				if(!dynamic)
					temp[toffset] |= 0x40;	/* T=1 */
				toffset += length;
			} else {
				/* We have a partial match, add a Literal Field Line
				 * with Name Reference instruction to the message */
				temp[toffset] = 0;
				length = imquic_write_pfxint(ref->id, 4, &temp[toffset], tlen-toffset);
				if(length == 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Name Index for Literal Field Line with Name Reference\n");
					return -1;
				}
				temp[toffset] |= 0x40;	/* 01 */
				temp[toffset] |= 0x20;	/* N=1 */
				if(!dynamic)
					temp[toffset] |= 0x10;	/* T=1 */
				toffset += length;
				res = 0;
				if(entry->value) {
					res = imquic_qpack_huffman_encode(entry->value, encoded, sizeof(encoded));
					res = res/8;
				}
				length = imquic_write_pfxint(res, 7, &temp[toffset], tlen-toffset);
				if(length == 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Value Length for Literal Field Line with Name Reference\n");
					return -1;
				}
				temp[toffset] |= 0x80;	/* H=1 */
				toffset += length;
				if(res > 0) {
					memcpy(&temp[toffset], encoded, res);
					toffset += res;
				}
			}
		}
		headers = headers->next;
	}
	/* Now we have all instructions ready: prepend a Encoded Field Section Prefix */
	uint64_t ric = 0;
	if(ctx->ltable->index > 0) {
		size_t max_entries = ctx->ltable->capacity / 32;
		ric = (ctx->ltable->index % (2 * max_entries)) + 1;
	}
	length = imquic_write_pfxint(ric, 8, &bytes[offset], *blen-offset);
	if(length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Required Insert Count\n");
		return -1;
	}
	offset += length;
	bytes[offset] = 0;
	uint64_t delta = ric ? (ric - 1) : 0;	/* FIXME */
	length = imquic_write_pfxint(delta, 7, &bytes[offset], *blen-offset);
	if(length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error writing Delta Base\n");
		return -1;
	}
	if(ric > 0)
		bytes[offset] |= 0x08;	/* S=1 */
	offset += length;
	/* Append the instructions we prepared already */
	memcpy(&bytes[offset], temp, toffset);
	offset += toffset;
	/* Update the size of the buffers */
	*blen = offset;
	*qenclen = qoffset;
	/* Done */
	return 0;
}

/* Static QPACK entries table */
imquic_qpack_entry imquic_qpack_static_table[] = {
	[0] = { 0, ":authority", NULL },
	[1] = { 1, ":path", "/" },
	[2] = { 2, "age", "0" },
	[3] = { 3, "content-disposition", NULL },
	[4] = { 4, "content-length", "0" },
	[5] = { 5, "cookie", NULL },
	[6] = { 6, "date", NULL },
	[7] = { 7, "etag", NULL },
	[8] = { 8, "if-modified-since", NULL },
	[9] = { 9, "if-none-match", NULL },
	[10] = { 10, "last-modified", NULL },
	[11] = { 11, "link", NULL },
	[12] = { 12, "location", NULL },
	[13] = { 13, "referer", NULL },
	[14] = { 14, "set-cookie", NULL },
	[15] = { 15, ":method", "CONNECT" },
	[16] = { 16, ":method", "DELETE" },
	[17] = { 17, ":method", "GET" },
	[18] = { 18, ":method", "HEAD" },
	[19] = { 19, ":method", "OPTIONS" },
	[20] = { 20, ":method", "POST" },
	[21] = { 21, ":method", "PUT" },
	[22] = { 22, ":scheme", "http" },
	[23] = { 23, ":scheme", "https" },
	[24] = { 24, ":status", "103" },
	[25] = { 25, ":status", "200" },
	[26] = { 26, ":status", "304" },
	[27] = { 27, ":status", "404" },
	[28] = { 28, ":status", "503" },
	[29] = { 29, "accept", "*/*" },
	[30] = { 30, "accept", "application/dns-message" },
	[31] = { 31, "accept-encoding", "gzip, deflate, br" },
	[32] = { 32, "accept-ranges", "bytes" },
	[33] = { 33, "access-control-allow-headers", "cache-control" },
	[34] = { 34, "access-control-allow-headers", "content-type" },
	[35] = { 35, "access-control-allow-origin", "*" },
	[36] = { 36, "cache-control", "max-age=0" },
	[37] = { 37, "cache-control", "max-age=2592000" },
	[38] = { 38, "cache-control", "max-age=604800" },
	[39] = { 39, "cache-control", "no-cache" },
	[40] = { 40, "cache-control", "no-store" },
	[41] = { 41, "cache-control", "public, max-age=31536000" },
	[42] = { 42, "content-encoding", "br" },
	[43] = { 43, "content-encoding", "gzip" },
	[44] = { 44, "content-type", "application/dns-message" },
	[45] = { 45, "content-type", "application/javascript" },
	[46] = { 46, "content-type", "application/json" },
	[47] = { 47, "content-type", "application/x-www-form-urlencoded" },
	[48] = { 48, "content-type", "image/gif" },
	[49] = { 49, "content-type", "image/jpeg" },
	[50] = { 50, "content-type", "image/png" },
	[51] = { 51, "content-type", "text/css" },
	[52] = { 52, "content-type", "text/html; charset=utf-8" },
	[53] = { 53, "content-type", "text/plain" },
	[54] = { 54, "content-type", "text/plain;charset=utf-8" },
	[55] = { 55, "range", "bytes=0-" },
	[56] = { 56, "strict-transport-security", "max-age=31536000" },
	[57] = { 57, "strict-transport-security", "max-age=31536000; includesubdomains" },
	[58] = { 58, "strict-transport-security", "max-age=31536000; includesubdomains; preload" },
	[59] = { 59, "vary", "accept-encoding" },
	[60] = { 60, "vary", "origin" },
	[61] = { 61, "x-content-type-options", "nosniff" },
	[62] = { 62, "x-xss-protection", "1; mode=block" },
	[63] = { 63, ":status", "100" },
	[64] = { 64, ":status", "204" },
	[65] = { 65, ":status", "206" },
	[66] = { 66, ":status", "302" },
	[67] = { 67, ":status", "400" },
	[68] = { 68, ":status", "403" },
	[69] = { 69, ":status", "421" },
	[70] = { 70, ":status", "425" },
	[71] = { 71, ":status", "500" },
	[72] = { 72, "accept-language", NULL },
	[73] = { 73, "access-control-allow-credentials", "FALSE" },
	[74] = { 74, "access-control-allow-credentials", "TRUE" },
	[75] = { 75, "access-control-allow-headers", "*" },
	[76] = { 76, "access-control-allow-methods", "get" },
	[77] = { 77, "access-control-allow-methods", "get, post, options" },
	[78] = { 78, "access-control-allow-methods", "options" },
	[79] = { 79, "access-control-expose-headers", "content-length" },
	[80] = { 80, "access-control-request-headers", "content-type" },
	[81] = { 81, "access-control-request-method", "get" },
	[82] = { 82, "access-control-request-method", "post" },
	[83] = { 83, "alt-svc", "clear" },
	[84] = { 84, "authorization", NULL },
	[85] = { 85, "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'" },
	[86] = { 86, "early-data", "1" },
	[87] = { 87, "expect-ct", NULL },
	[88] = { 88, "forwarded", NULL },
	[89] = { 89, "if-range", NULL },
	[90] = { 90, "origin", NULL },
	[91] = { 91, "purpose", "prefetch" },
	[92] = { 92, "server", NULL },
	[93] = { 93, "timing-allow-origin", "*" },
	[94] = { 94, "upgrade-insecure-requests", "1" },
	[95] = { 95, "user-agent", NULL },
	[96] = { 96, "x-forwarded-for", NULL },
	[97] = { 97, "x-frame-options", "deny" },
	[98] = { 98, "x-frame-options", "sameorigin" },
};
