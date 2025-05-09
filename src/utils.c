/*! \file   utils.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Generic utilities
 * \details Implementation of a few more generic functionality that is
 * useful in the QUIC stack internals (e.g., varint support).
 *
 * \ingroup Core
 */

#include <arpa/inet.h>

#include "internal/utils.h"
#include "imquic/debug.h"

#include <openssl/rand.h>

/* String concatenation utilities */
size_t imquic_strlcat(char *dest, const char *src, size_t dest_size) {
	size_t ret = g_strlcat(dest, src, dest_size);
	if(ret >= dest_size)
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Truncation occurred, %lu >= %lu\n", ret, dest_size);
	return ret;
}

int imquic_strlcat_fast(char *dest, const char *src, size_t dest_size, size_t *offset) {
	if(dest == NULL || src == NULL || offset == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid arguments\n");
		return -1;
	}
	if(*offset >= dest_size) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Offset is beyond the buffer size\n");
		return -2;
	}
	char *p = memccpy(dest + *offset, src, 0, dest_size - *offset);
	if(p == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Truncation occurred, %lu >= %lu\n",
			*offset + strlen(src), dest_size);
		*offset = dest_size;
		*(dest + dest_size -1) = '\0';
		return -3;
	}
	*offset = (p - dest - 1);
	return 0;
}

/* Utilities to use 64-bit integers as parts of lists and hashtables */
uint64_t imquic_random_uint64(void) {
	guint64 ret = 0;
	if(RAND_bytes((void *)&ret, sizeof(ret)) != 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Safe RAND_bytes() failed, falling back to unsafe PRNG\n");
		return ((guint64)g_random_int() << 32) | g_random_int();
	}
	return ret;
}

uint64_t *imquic_dup_uint64(uint64_t num) {
	uint64_t *numdup = g_malloc(sizeof(uint64_t));
	*numdup = num;
	return numdup;
}

/* Reading and writing variable size integers */
uint64_t imquic_read_varint(uint8_t *bytes, size_t blen, uint8_t *length) {
	if(length)
		*length = 0;
	if(bytes == NULL || blen == 0)
		return 0;
	uint8_t len = 1 << (bytes[0] >> 6);
	if(len > blen) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid varint (%"SCNu8" > %zu)\n", len, blen);
		return 0;
	}
	uint64_t res = bytes[0] & 0x3F;
	for(uint8_t i=1; i<len; i++)
		res = (res << 8) + bytes[i];
	if(length)
		*length = len;
	return res;
}

uint8_t imquic_write_varint(uint64_t number, uint8_t *bytes, size_t blen) {
	if(blen < 1 || number > IMQUIC_MAX_VARINT)
		return 0;
	if(number <= 63) {
		/* Let's use one byte */
		*bytes = number;
		return 1;
	} else if(number <= 16383) {
		/* Let's use two bytes */
		if(blen < 2) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write varint '%"SCNu64"' (need at least 2 bytes)\n", number);
			return 0;
		}
		uint16_t num = number;
		num = g_htons(num);
		memcpy(bytes, &num, sizeof(num));
		*bytes += 1 << 6;
		return 2;
	} else if(number <= 1073741823) {
		/* Let's use four bytes */
		if(blen < 4) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write varint '%"SCNu64"' (need at least 4 bytes)\n", number);
			return 0;
		}
		uint32_t num = number;
		num = g_htonl(num);
		memcpy(bytes, &num, sizeof(num));
		*bytes += 1 << 7;
		return 4;
	} else {
		/* We need 8 bytes */
		if(blen < 8) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write varint '%"SCNu64"' (need at least 8 bytes)\n", number);
			return 0;
		}
		number = htonll(number);
		memcpy(bytes, &number, sizeof(number));
		*bytes += 1 << 6;
		*bytes += 1 << 7;
		return 8;
	}
	IMQUIC_LOG(IMQUIC_LOG_WARN, "Didn't write varint '%"SCNu64"'\n", number);
	return 0;
}

/* Reading and writing prefixed integers (for QPACK) */
uint64_t imquic_read_pfxint(uint8_t n, uint8_t *bytes, size_t blen, uint8_t *length) {
	if(length)
		*length = 0;
	if(n > 8 || bytes == NULL || blen == 0)
		return 0;
	uint8_t cap = (1 << n) - 1;
	uint8_t first = bytes[0] & cap;
	if(first < cap) {
		/* Easy enough */
		if(length)
			*length = 1;
		return first;
	}
	/* We need to traverse more bits */
	uint8_t m = 0, b = 0x80, i = 0;
	uint64_t number = cap;
	while(b & 0x80) {
		i++;
		if(blen == i) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough bytes to read the number (we're at %"SCNu8" but need more than that)\n", i);
			return 0;
		}
		b = bytes[i];
		number += (b & 0x7f) * ((uint64_t)1 << m);
		m += 7;
	};
	if(length)
		*length = i + 1;
	/* Done */
	return number;
}

uint8_t imquic_write_pfxint(uint64_t number, uint8_t n, uint8_t *bytes, size_t blen) {
	if(n > 8 || bytes == NULL || blen == 0)
		return 0;
	uint8_t cap = (1 << n) - 1;
	if(number < cap) {
		/* Easy enough */
		bytes[0] |= number;
		return 1;
	}
	/* We need more, fill the prefix */
	bytes[0] |= cap;
	uint64_t left = number - cap;
	uint8_t res = 1;
	while(left >= 128) {
		if(blen == res) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to prefixed integer '%"SCNu64"' (need more than %zu bytes)\n", number, blen);
			return 0;
		}
		bytes[res] = (left % 128) + 128;
		left = left / 128;
		res++;
	}
	if(blen == res) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to prefixed integer '%"SCNu64"' (need more than %zu bytes)\n", number, blen);
		return 0;
	}
	bytes[res] = left;
	res++;
	/* Done */
	return res;
}

/* FIXME Reconstructing a full packet number */
uint64_t imquic_full_packet_number(uint64_t largest, uint64_t pn_pkt, uint8_t p_len) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%"SCNu64", %"SCNu64", %"SCNu8"\n", largest, pn_pkt, p_len);
	/* https://datatracker.ietf.org/doc/html/rfc9000#section-a.3 */
	//~ uint64_t expected = largest + 1;
	//~ uint64_t pn_win = (uint64_t)1 << p_len;
	//~ uint64_t pn_hwin = pn_win / 2;
	//~ uint64_t pn_mask = pn_win - 1;
	//~ IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- l=%"SCNu64", w=%"SCNu64", hw=%"SCNu64", m=%"SCNu64"\n", expected, pn_win, pn_hwin, pn_mask);
	//~ uint64_t candidate_pn = (expected & ~pn_mask) | pn_pkt;
	//~ IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- candidate=%"SCNu64"\n", candidate_pn);
	//~ if((candidate_pn <= (expected - pn_hwin)) && (candidate_pn < (((uint64_t)1 << 62) - pn_win)))
		//~ return candidate_pn + pn_win;
	//~ if((candidate_pn > (expected + pn_hwin)) && candidate_pn >= pn_win)
		//~ return candidate_pn - pn_win;
	//~ return candidate_pn;
	uint64_t k = largest + 1;
	uint64_t u = k & ~((G_GUINT64_CONSTANT(1) << p_len) - 1);
	uint64_t a = u | pn_pkt;
	uint64_t b = (u + (G_GUINT64_CONSTANT(1) << p_len)) | pn_pkt;
	uint64_t a1 = k < a ? a - k : k - a;
	uint64_t b1 = k < b ? b - k : k - b;
	if(a1 < b1)
		return a;
	return b;
}

/* Debugging: printing the content of a hex buffer */
void imquic_print_hex(int level, uint8_t *buf, size_t buflen) {
	IMQUIC_LOG(level, "\t");
	for(size_t i=0; i<buflen; ++i)
		IMQUIC_LOG(level, "%02x", buf[i]);
	IMQUIC_LOG(level, "\n");
}

const char *imquic_hex_str(uint8_t *buf, size_t buflen, char *buffer, size_t blen) {
	if(buf == NULL || buflen == 0 || buffer == NULL || blen == 0)
		return NULL;
	if(buflen*2 >= blen) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render data as a string (truncation would occur)\n");
		return NULL;
	}
	*buffer = '\0';
	char hex[3];
	size_t offset = 0;
	for(size_t i=0; i<buflen; i++) {
		g_snprintf(hex, sizeof(hex), "%02x", buf[i]);
		imquic_strlcat_fast(buffer, hex, blen, &offset);
	}
	return buffer;
}

/* Generic data buffer */
imquic_data *imquic_data_create(uint8_t *buffer, size_t length) {
	if(length > 0 && buffer == NULL)
		return NULL;
	imquic_data *data = g_malloc(sizeof(imquic_data));
	if(length == 0) {
		data->buffer = NULL;
	} else {
		data->buffer = g_malloc(length);
		memcpy(data->buffer, buffer, length);
	}
	data->length = length;
	return data;
}

gboolean imquic_data_equal(const void *a, const void *b) {
	const imquic_data *d1 = (imquic_data *)a;
	const imquic_data *d2 = (imquic_data *)b;
	if(!a || !b || d1->length != d2->length)
		return FALSE;
	for(size_t i=0; i<d1->length; i++) {
		if(d1->buffer[i] != d2->buffer[i])
			return FALSE;
	}
	return TRUE;
}


void imquic_data_destroy(imquic_data *data) {
	if(data) {
		g_free(data->buffer);
		g_free(data);
	}
}

/* Bitstreams */
uint8_t imquic_bitstream_peek(imquic_bitstream *bs, uint8_t *len) {
	if(bs == NULL || bs->buffer == NULL || bs->size == 0 || bs->offset == bs->size) {
		/* We're done */
		if(len)
			*len = 0;
		return 0;
	}
	uint8_t byte = 0;
	uint8_t index = bs->offset / 8;
	uint8_t mod = bs->offset % 8;
	size_t left = bs->size - bs->offset;
	if(mod == 0) {
		/* Easy enough */
		byte = bs->buffer[index];
	} else {
		/* We need some shifting */
		byte = bs->buffer[index] << mod;
		if(left > 8)
			byte += bs->buffer[index+1] >> (8 - mod);
	}
	if(len)
		*len = left < 8 ? left : 8;
	return byte;
}

size_t imquic_bitstream_write(imquic_bitstream *bs, uint32_t value, uint8_t bits) {
	if(bs == NULL || bs->buffer == NULL || bs->size == 0 || bits == 0) {
		/* We're done */
		return 0;
	}
	value = htonl(value);
	uint8_t *bytes = (uint8_t *)&value;
	size_t initial_offset = bs->offset;
	uint8_t byte = 0, index = 0, mod = 0, avail = 0;
	uint8_t step = 3 - bits/8;
	if(bits % 8 == 0)
		step++;
	size_t left = bs->size - bs->offset;
	if(left < bits) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough bits left to write this value\n");
		return 0;
	}
	uint8_t missing = bits, writing = 0;
	while(missing > 0) {
		index = bs->offset / 8;
		mod = bs->offset % 8;
		byte = bytes[step];
		writing = missing;
		if(writing > 8) {
			writing = missing % 8;
			if(writing == 0)
				writing = 8;
		}
		if(mod == 0) {
			/* Easy enough */
			bs->buffer[index] = byte << (8 - writing);
			missing -= writing;
			bs->offset += writing;
		} else {
			/* We need some shifting */
			avail = 8 - mod;
			if(writing <= avail) {
				bs->buffer[index] |= byte << (avail - writing);
				missing -= writing;
				bs->offset += writing;
			} else {
				writing -= avail;
				bs->buffer[index] |= byte >> writing;
				missing -= avail;
				bs->offset += avail;
				index++;
				if(writing > 0) {
					bs->buffer[index] |= byte << (8 - writing);
					missing -= writing;
					bs->offset += writing;
				}
			}
		}
		step++;
	}
	return bs->offset - initial_offset;
}
