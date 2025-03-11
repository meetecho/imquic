/*! \file   http3.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  HTTP/3 stack (WebTransport only)
 * \details Implementation of the required set of features need to
 * establish a WebTransport connection, when needed. It explicitly only
 * deals with WebTransport, meaning it will fail with anything else that
 * is not a \c CONNECT request.
 *
 * \ingroup Core
 */

#include <stddef.h>
#include <stdint.h>

#include "internal/http3.h"
#include "internal/quic.h"
#include "internal/utils.h"
#include "internal/version.h"
#include "imquic/debug.h"

/* HTTP/3 stringifires */
const char *imquic_http3_stream_type_str(imquic_http3_stream_type type) {
	switch(type) {
		case IMQUIC_HTTP3_CONTROL_STREAM:
			return "Control Stream";
		case IMQUIC_HTTP3_PUSH_STREAM:
			return "Push Stream";
		case IMQUIC_HTTP3_QPACK_ENCODER_STREAM:
			return "QPACK Encoder Stream";
		case IMQUIC_HTTP3_QPACK_DECODER_STREAM:
			return "QPACK Decoder Stream";
		default: break;
	}
	return NULL;
}

const char *imquic_http3_frame_type_str(imquic_http3_frame_type type) {
	switch(type) {
		case IMQUIC_HTTP3_DATA:
			return "DATA";
		case IMQUIC_HTTP3_HEADERS:
			return "HEADERS";
		case IMQUIC_HTTP3_CANCEL_PUSH:
			return "CANCEL_PUSH";
		case IMQUIC_HTTP3_SETTINGS:
			return "SETTINGS";
		case IMQUIC_HTTP3_PUSH_PROMISE:
			return "PUSH_PROMISE";
		case IMQUIC_HTTP3_GOAWAY:
			return "GOAWAY";
		case IMQUIC_HTTP3_MAX_PUSH_ID:
			return "MAX_PUSH_ID";
		case IMQUIC_HTTP3_WEBTRANSPORT_UNI_STREAM:
			return "WEBTRANSPORT_UNI_STREAM";
		case IMQUIC_HTTP3_WEBTRANSPORT_STREAM:
			return "WEBTRANSPORT_STREAM";
		default: break;
	}
	return NULL;
}

const char *imquic_http3_settings_type_str(imquic_http3_settings_type type) {
	switch(type) {
		case IMQUIC_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			return "SETTINGS_QPACK_MAX_TABLE_CAPACITY";
		case IMQUIC_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			return "SETTINGS_MAX_FIELD_SECTION_SIZE";
		case IMQUIC_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS:
			return "SETTINGS_QPACK_BLOCKED_STREAMS";
		case IMQUIC_HTTP3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
			return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
		case IMQUIC_HTTP3_SETTINGS_H3_DATAGRAM:
			return "SETTINGS_H3_DATAGRAM";
		case IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT:
			return "SETTINGS_ENABLE_WEBTRANSPORT";
		case IMQUIC_HTTP3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS:
			return "SETTINGS_WEBTRANSPORT_MAX_SESSIONS";
		default: break;
	}
	return NULL;
}

/* HTTP/3 connections  */
static void imquic_http3_connection_free(const imquic_refcount *h3c_ref) {
	imquic_http3_connection *h3c = imquic_refcount_containerof(h3c_ref, imquic_http3_connection, ref);
	imquic_qpack_context_destroy(h3c->qpack);
	g_free(h3c->subprotocol);
	g_free(h3c);
}

imquic_http3_connection *imquic_http3_connection_create(imquic_connection *conn, char *subprotocol) {
	imquic_http3_connection *h3c = g_malloc0(sizeof(imquic_http3_connection));
	h3c->conn = conn;
	h3c->is_server = conn->is_server;
	h3c->subprotocol = subprotocol ? g_strdup(subprotocol) : NULL;
	imquic_refcount_init(&h3c->ref, imquic_http3_connection_free);
	return h3c;
}

void imquic_http3_connection_destroy(imquic_http3_connection *h3c) {
	if(h3c && g_atomic_int_compare_and_exchange(&h3c->destroyed, 0, 1))
		imquic_refcount_decrease(&h3c->ref);
}

/* Helper to parse settings */
int imquic_http3_parse_settings(imquic_http3_connection *h3c, uint8_t *bytes, size_t blen) {
	if(blen < 2)
		return -1;
	/* TODO Store those settings somewhere */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing SETTINGS (%zu bytes)\n",
		imquic_get_connection_name(h3c->conn), blen);
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = 0, s_len = 0, value = 0;
	if(bytes[0] != IMQUIC_HTTP3_SETTINGS) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Not a SETTINGS payload\n",
			imquic_get_connection_name(h3c->conn));
		return -1;
	}
	offset++;
	s_len = imquic_read_varint(bytes + offset, blen - offset, &length);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- SETTINGS has length %zu\n", s_len);
	offset += length;
	if(s_len > blen - offset) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Not enough bytes for SETTINGS\n",
			imquic_get_connection_name(h3c->conn));
		return -1;
	}
	while(s_len > 0) {
		type = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		s_len -= length;
		value = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		s_len -= length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- [%"SCNu64"][%s] %"SCNu64"\n",
			type, imquic_http3_settings_type_str(type), value);
		/* FIXME */
		if(type == IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT && value != 0)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Establishing WebTransport\n", imquic_get_connection_name(h3c->conn));
	}
	h3c->settings_received = TRUE;
	if(h3c->is_server) {
		/* FIXME As an HTTP/3 server, reply with our own SETTINGS */
		imquic_http3_prepare_settings(h3c);
	} else {
		imquic_http3_check_send_connect(h3c);
	}
	return 0;
}

/* Helpers to add setting to a buffer */
size_t imquic_http3_settings_add_int(uint8_t *bytes, size_t blen, imquic_http3_settings_type type, uint64_t number) {
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = imquic_write_varint(type, &bytes[0], blen);
	offset += imquic_write_varint(number, &bytes[offset], blen-offset);
	return offset;

}

const char *imquic_http3_error_code_str(imquic_http3_error_code type) {
	switch(type) {
		case IMQUIC_HTTP3_H3_DATAGRAM_ERROR:
			return "H3_DATAGRAM_ERROR";
		case IMQUIC_HTTP3_H3_NO_ERROR:
			return "H3_NO_ERROR";
		case IMQUIC_HTTP3_H3_GENERAL_PROTOCOL_ERROR:
			return "H3_GENERAL_PROTOCOL_ERROR";
		case IMQUIC_HTTP3_H3_INTERNAL_ERROR:
			return "H3_INTERNAL_ERROR";
		case IMQUIC_HTTP3_H3_STREAM_CREATION_ERROR:
			return "H3_STREAM_CREATION_ERROR";
		case IMQUIC_HTTP3_H3_CLOSED_CRITICAL_STREAM:
			return "H3_CLOSED_CRITICAL_STREAM";
		case IMQUIC_HTTP3_H3_FRAME_UNEXPECTED:
			return "H3_FRAME_UNEXPECTED";
		case IMQUIC_HTTP3_H3_FRAME_ERROR:
			return "H3_FRAME_ERROR";
		case IMQUIC_HTTP3_H3_EXCESSIVE_LOAD:
			return "H3_EXCESSIVE_LOAD";
		case IMQUIC_HTTP3_H3_ID_ERROR:
			return "H3_ID_ERROR";
		case IMQUIC_HTTP3_H3_SETTINGS_ERROR:
			return "H3_SETTINGS_ERROR";
		case IMQUIC_HTTP3_H3_MISSING_SETTINGS:
			return "H3_MISSING_SETTINGS";
		case IMQUIC_HTTP3_H3_REQUEST_REJECTED:
			return "H3_REQUEST_REJECTED";
		case IMQUIC_HTTP3_H3_REQUEST_CANCELLED:
			return "H3_REQUEST_CANCELLED";
		case IMQUIC_HTTP3_H3_REQUEST_INCOMPLETE:
			return "H3_REQUEST_INCOMPLETE";
		case IMQUIC_HTTP3_H3_MESSAGE_ERROR:
			return "H3_MESSAGE_ERROR";
		case IMQUIC_HTTP3_H3_CONNECT_ERROR:
			return "H3_CONNECT_ERROR";
		case IMQUIC_HTTP3_H3_VERSION_FALLBACK:
			return "H3_VERSION_FALLBACK";
		case IMQUIC_HTTP3_QPACK_DECOMPRESSION_FAILED:
			return "QPACK_DECOMPRESSION_FAILED";
		case IMQUIC_HTTP3_QPACK_ENCODER_STREAM_ERROR:
			return "QPACK_ENCODER_STREAM_ERROR";
		case IMQUIC_HTTP3_QPACK_DECODER_STREAM_ERROR:
			return "QPACK_DECODER_STREAM_ERROR";
		default: break;
	}
	return NULL;
}

/* Processing incoming data */
void imquic_http3_process_stream_data(imquic_connection *conn, imquic_stream *stream, imquic_buffer_chunk *chunk, gboolean new_stream) {
	if(conn == NULL || conn->http3 == NULL || stream == NULL || chunk == NULL)
		return;
	imquic_http3_connection *h3c = conn->http3;
	if(new_stream) {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Parsing HTTP/3 STREAM (stream ID %"SCNu64") chunk\n",
			imquic_get_connection_name(conn), stream->stream_id);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Stream '%"SCNu64"' is %s initiated and %s\n", stream->actual_id,
			stream->client_initiated ? "client" : "server", stream->bidirectional ? "bidirectional" : "unidirectional");
	}
	uint8_t *payload = chunk->data;
	size_t p_offset = 0;
	uint8_t length = 0;
	if(new_stream && !h3c->webtransport && !stream->bidirectional &&
			stream->stream_id != h3c->remote_control_stream &&
			stream->stream_id != h3c->remote_qpack_encoder_stream &&
			stream->stream_id != h3c->remote_qpack_decoder_stream) {
		/* We don't know what this unidirectional stream is yet, check the type */
		uint64_t stream_type = imquic_read_varint(&payload[p_offset], chunk->length-p_offset, &length);
		p_offset += length;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- %s '%"SCNu64"'\n", imquic_http3_stream_type_str(stream_type), stream->stream_id);
		if(stream_type == IMQUIC_HTTP3_CONTROL_STREAM) {
			h3c->remote_control_stream = stream->stream_id;
		} else if(stream_type == IMQUIC_HTTP3_QPACK_ENCODER_STREAM) {
			h3c->remote_qpack_encoder_stream = stream->stream_id;
			/* FIXME */
			if(h3c->qpack == NULL)
				h3c->qpack = imquic_qpack_context_create(4096);
		} else if(stream_type == IMQUIC_HTTP3_QPACK_DECODER_STREAM) {
			h3c->remote_qpack_decoder_stream = stream->stream_id;
			/* FIXME */
			if(h3c->qpack == NULL)
				h3c->qpack = imquic_qpack_context_create(4096);
		}
	} else if(new_stream && h3c->webtransport) {
		uint64_t frame_type = imquic_read_varint(&payload[p_offset], chunk->length-p_offset, &length);
		p_offset += length;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- %s '%"SCNu64"'\n", imquic_http3_frame_type_str(frame_type), stream->stream_id);
		uint64_t session_id = imquic_read_varint(&payload[p_offset], chunk->length-p_offset, &length);
		p_offset += length;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Session ID: %"SCNu64"\n", session_id);
		/* We'll need to skip these initial bytes when handling the data */
		stream->skip_in = p_offset;
	}
	/* Now we should know what it is */
	if(!stream->bidirectional && stream->stream_id == h3c->remote_control_stream) {
		/* Control stream */
		imquic_http3_parse_settings(h3c, chunk->data + p_offset, chunk->length - p_offset);
	} else if(!stream->bidirectional && stream->stream_id == h3c->remote_qpack_encoder_stream) {
		/* QPACK encoder */
		if(chunk->length - p_offset > 0) {
			ssize_t bread = imquic_qpack_decode(h3c->qpack, chunk->data + p_offset, chunk->length - p_offset);
			IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] QPACK decoded %zd/%zd bytes\n",
				imquic_get_connection_name(conn), bread, chunk->length - p_offset);
		}
	} else if(!stream->bidirectional && stream->stream_id == h3c->remote_qpack_decoder_stream) {
		/* TODO Handle QPACK decoder messages */
	} else if(!stream->bidirectional && h3c->webtransport) {
		/* Got WebTransport data on a unidirectional stream */
		imquic_connection_notify_stream_incoming(conn, stream, chunk->data, chunk->offset, chunk->length);
	} else if(stream->bidirectional) {
		if(!h3c->webtransport || stream->stream_id == h3c->request_stream) {
			/* Request */
			if(h3c->request_stream == 0)
				h3c->request_stream = stream->stream_id;
			imquic_http3_parse_request(h3c, stream, chunk->data + p_offset, chunk->length - p_offset);
		} else {
			/* Got WebTransport data on a bidirectional stream */
			imquic_connection_notify_stream_incoming(conn, stream, chunk->data, chunk->offset, chunk->length);
		}
	}
}

/* HTTP/3 request/response parsing */
int imquic_http3_parse_request(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 1)
		return -1;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing HTTP/3 request\n",
		imquic_get_connection_name(h3c->conn));
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	size_t offset = 0, f_offset = 0;
	uint8_t length = 0;
	uint64_t f_len = 0;
	while(blen - offset > 0) {
		f_offset = offset;
		imquic_http3_frame_type type = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		f_len = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s (%02x, %zu bytes)\n", imquic_http3_frame_type_str(type), bytes[0], f_len);
		if(f_len > blen - offset) {
			/* TODO Not really an error, this probably means we just have to wait... */
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Invalid HTTP/3 frame, length too long (%"SCNu64" > %zu)\n",
				imquic_get_connection_name(h3c->conn), f_len, blen - offset);
			imquic_print_hex(IMQUIC_LOG_HUGE, bytes + f_offset, blen - f_offset);
			return -1;
		}
		if(type == IMQUIC_HTTP3_DATA) {
			offset += imquic_http3_parse_request_data(h3c, stream, (bytes + offset), f_len);
		} else if(type == IMQUIC_HTTP3_HEADERS) {
			offset += imquic_http3_parse_request_headers(h3c, stream, (bytes + offset), f_len);
		} else {
			/* TODO */
			offset += f_len;
		}
	}
	/* Done */
	return 0;
}

size_t imquic_http3_parse_request_headers(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen) {
	/* TODO Actually take note of what we parse here */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Parsing HTTP/3 HEADERS\n",
		imquic_get_connection_name(h3c->conn));
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	if(h3c->qpack == NULL)
		h3c->qpack = imquic_qpack_context_create(4096);
	size_t bread = 0;
	GList *headers = imquic_qpack_process(h3c->qpack, bytes, blen, &bread);
	GList *temp = headers;
	imquic_qpack_entry *header = NULL;
	while(temp) {
		header = (imquic_qpack_entry *)temp->data;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- -- %s = %s\n", header->name, header->value);
		temp = temp->next;
	}
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
	if(!h3c->is_server) {
		/* Done */
		h3c->webtransport = TRUE;
		if(h3c->conn->socket->new_connection)
			h3c->conn->socket->new_connection(h3c->conn, h3c->conn->socket->user_data);
	} else {
		/* FIXME Let's assume it was a CONNECT and let's send a 200 OK */
		uint8_t es[100], rs[100];
		size_t es_len = 0, rs_len = 0;
		if(imquic_http3_prepare_headers_response(h3c, es, &es_len, rs, &rs_len) == 0) {
			/* FIXME Prepare the necessary STREAM payload(s) */
			if(es_len > 0) {
				imquic_stream *enc_stream = g_hash_table_lookup(h3c->conn->streams, &h3c->local_qpack_encoder_stream);
				if(enc_stream)
					imquic_buffer_append(enc_stream->out_data, es, es_len);
				g_queue_push_tail(h3c->conn->outgoing_data, imquic_dup_uint64(h3c->local_qpack_encoder_stream));
			}
			if(rs_len > 0)
				imquic_buffer_append(stream->out_data, rs, rs_len);
			g_queue_push_tail(h3c->conn->outgoing_data, imquic_dup_uint64(stream->stream_id));
			h3c->conn->wakeup = TRUE;
			imquic_loop_wakeup();
		}
	}
	return blen;
}

size_t imquic_http3_parse_request_data(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen) {
	/* TODO */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Parsing HTTP/3 DATA\n",
		imquic_get_connection_name(h3c->conn));
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	return blen;
}

/* FIXME HTTP/3 request */
int imquic_http3_prepare_headers_request(imquic_http3_connection *h3c, uint8_t *es, size_t *es_len, uint8_t *rs, size_t *rs_len) {
	if(h3c->qpack == NULL)
		h3c->qpack = imquic_qpack_context_create(4096);
	/* FIXME BADLY This is all hardcoded */
	GList *headers = NULL;
	headers = g_list_append(headers, imquic_qpack_entry_create(":method", "CONNECT"));
	headers = g_list_append(headers, imquic_qpack_entry_create(":scheme", "https"));
	char address[256];
	headers = g_list_append(headers, imquic_qpack_entry_create(":authority",
		imquic_network_address_str(&h3c->conn->socket->remote_address, address, sizeof(address), TRUE)));	/* FIXME */
	const char *path = "/";
	if(h3c->conn && h3c->conn->socket && h3c->conn->socket->h3_path)
		path = (const char *)h3c->conn->socket->h3_path;
	headers = g_list_append(headers, imquic_qpack_entry_create(":path", path));
	headers = g_list_append(headers, imquic_qpack_entry_create(":protocol", "webtransport"));
	headers = g_list_append(headers, imquic_qpack_entry_create("user-agent", "imquic/0.0.1alpha"));
	headers = g_list_append(headers, imquic_qpack_entry_create("sec-fetch-dest", "webtransport"));
	headers = g_list_append(headers, imquic_qpack_entry_create("sec-webtransport-http3-draft", "draft02"));
	/* FIXME Is the stream supposed to be the right bidirectional stream? */
	uint8_t rbuf[1024], ebuf[1024];
	size_t r_len = sizeof(rbuf), e_len = sizeof(ebuf);
	int res = imquic_qpack_encode(h3c->qpack, headers, rbuf, &r_len, ebuf, &e_len);
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
	if(res < 0) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Failed to QPACK encode the headers\n",
			imquic_get_connection_name(h3c->conn));
		return -1;
	}
	/* Check if we have an encoder strean */
	*es_len = e_len;
	if(e_len > 0) {
		/* We do */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Encoder stream (%zu)\n", e_len);
		imquic_print_hex(IMQUIC_LOG_HUGE, ebuf, e_len);
		memcpy(es, ebuf, e_len);
	}
	/* Now copy the request stream */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Request stream (%zu)\n", r_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, rbuf, r_len);
	*rs = IMQUIC_HTTP3_HEADERS;
	uint8_t h_len = imquic_write_varint(r_len, rs + 1, 8);
	memcpy(rs + 1 + h_len, rbuf, r_len);
	*rs_len = 1 + h_len + r_len;
	imquic_print_hex(IMQUIC_LOG_HUGE, rs, *rs_len);
	return 0;
}

/* FIXME HTTP/3 response */
int imquic_http3_prepare_headers_response(imquic_http3_connection *h3c, uint8_t *es, size_t *es_len, uint8_t *rs, size_t *rs_len) {
	if(h3c->qpack == NULL)
		h3c->qpack = imquic_qpack_context_create(4096);
	/* FIXME BADLY This is all hardcoded */
	GList *headers = NULL;
	headers = g_list_append(headers, imquic_qpack_entry_create(":status", "200"));
	char server[100];
	g_snprintf(server, sizeof(server), "%s %s", imquic_name, imquic_version_string_full);
	headers = g_list_append(headers, imquic_qpack_entry_create("server", server));
	headers = g_list_append(headers, imquic_qpack_entry_create("sec-webtransport-http3-draft", "draft02"));
	/* FIXME Is the stream supposed to be the right bidirectional stream? */
	uint8_t rbuf[1024], ebuf[1024];
	size_t r_len = sizeof(rbuf), e_len = sizeof(ebuf);
	int res = imquic_qpack_encode(h3c->qpack, headers, rbuf, &r_len, ebuf, &e_len);
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
	if(res < 0) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Failed to QPACK encode the headers\n",
			imquic_get_connection_name(h3c->conn));
		return -1;
	}
	/* Check if we have an encoder strean */
	*es_len = e_len;
	if(e_len > 0) {
		/* We do */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Encoder stream (%zu)\n", e_len);
		imquic_print_hex(IMQUIC_LOG_HUGE, ebuf, e_len);
		memcpy(es, ebuf, e_len);
	}
	/* Now copy the request stream */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Request stream (%zu)\n", r_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, rbuf, r_len);
	*rs = IMQUIC_HTTP3_HEADERS;
	uint8_t h_len = imquic_write_varint(r_len, rs + 1, 8);
	memcpy(rs + 1 + h_len, rbuf, r_len);
	*rs_len = 1 + h_len + r_len;
	imquic_print_hex(IMQUIC_LOG_HUGE, rs, *rs_len);
	/* Done */
	h3c->webtransport = TRUE;
	if(h3c->conn->socket->new_connection)
		h3c->conn->socket->new_connection(h3c->conn, h3c->conn->socket->user_data);
	return 0;
}

/* FIXME Sending messages */
void imquic_http3_check_send_connect(imquic_http3_connection *h3c) {
	if(!h3c->is_server && h3c->settings_sent && h3c->settings_received) {
		/* FIXME Let's prepare a CONNECT */
		uint8_t buffer[1024];
		uint8_t es[200], rs[200];
		size_t es_len = 0, rs_len = 0, offset = 0;
		if(imquic_http3_prepare_headers_request(h3c, es, &es_len, rs, &rs_len) == 0) {
			/* FIXME Prepare the necessary STREAM payload(s) */
			if(es_len > 0) {
				imquic_stream *enc_stream = g_hash_table_lookup(h3c->conn->streams, &h3c->local_qpack_encoder_stream);
				if(enc_stream)
					imquic_buffer_append(enc_stream->out_data, es, es_len);
				g_queue_push_tail(h3c->conn->outgoing_data, imquic_dup_uint64(h3c->local_qpack_encoder_stream));
				//~ memcpy(&buffer[offset], es, es_len);
				//~ offset += es_len;
			}
			if(rs_len > 0) {
				memcpy(&buffer[offset], rs, rs_len);
				offset += rs_len;
			}
			uint64_t stream_id = 0;
			imquic_connection_new_stream_id(h3c->conn, TRUE, &stream_id);
			h3c->request_stream = stream_id;
			imquic_connection_send_on_stream(h3c->conn, stream_id, buffer, 0, offset, FALSE);
			imquic_connection_flush_stream(h3c->conn, stream_id);
			h3c->conn->wakeup = TRUE;
			imquic_loop_wakeup();
		}
	}
}

int imquic_http3_prepare_settings(imquic_http3_connection *h3c) {
	/* FIXME Generate SETTINGS */
	uint8_t settings[100];
	size_t s_offset = 0, s_len = sizeof(settings);
	settings[0] = IMQUIC_HTTP3_CONTROL_STREAM;
	settings[1] = IMQUIC_HTTP3_SETTINGS;
	s_offset = 3;
	s_offset += imquic_http3_settings_add_int(&settings[s_offset], s_len - s_offset, IMQUIC_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096);
	s_offset += imquic_http3_settings_add_int(&settings[s_offset], s_len - s_offset, IMQUIC_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS, 16);
	s_offset += imquic_http3_settings_add_int(&settings[s_offset], s_len - s_offset, IMQUIC_HTTP3_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
	s_offset += imquic_http3_settings_add_int(&settings[s_offset], s_len - s_offset, IMQUIC_HTTP3_SETTINGS_H3_DATAGRAM, 1);
	s_offset += imquic_http3_settings_add_int(&settings[s_offset], s_len - s_offset, IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT, 1);
	settings[2] = s_offset - 3;
	/* FIXME Add STREAMs */
	imquic_connection_new_stream_id(h3c->conn, FALSE, &h3c->local_control_stream);
	imquic_connection_send_on_stream(h3c->conn, h3c->local_control_stream, settings, 0, s_offset, FALSE);
	imquic_connection_new_stream_id(h3c->conn, FALSE, &h3c->local_qpack_encoder_stream);
	settings[0] = IMQUIC_HTTP3_QPACK_ENCODER_STREAM;
	imquic_connection_send_on_stream(h3c->conn, h3c->local_qpack_encoder_stream, settings, 0, 1, FALSE);
	imquic_connection_new_stream_id(h3c->conn, FALSE, &h3c->local_qpack_decoder_stream);
	settings[0] = IMQUIC_HTTP3_QPACK_DECODER_STREAM;
	imquic_connection_send_on_stream(h3c->conn, h3c->local_qpack_decoder_stream, settings, 0, 1, FALSE);
	imquic_connection_flush_stream(h3c->conn, h3c->local_control_stream);
	imquic_connection_flush_stream(h3c->conn, h3c->local_qpack_encoder_stream);
	imquic_connection_flush_stream(h3c->conn, h3c->local_qpack_decoder_stream);
	/* Done */
	h3c->settings_sent = TRUE;
	if(!h3c->is_server)
		imquic_http3_check_send_connect(h3c);
	return 0;
}
