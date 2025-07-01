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
	g_hash_table_unref(h3c->buffers);
	g_free(h3c);
}

imquic_http3_connection *imquic_http3_connection_create(imquic_connection *conn, char *subprotocol) {
	imquic_http3_connection *h3c = g_malloc0(sizeof(imquic_http3_connection));
	h3c->conn = conn;
	h3c->is_server = conn->is_server;
	h3c->subprotocol = subprotocol ? g_strdup(subprotocol) : NULL;
	h3c->buffers = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_buffer_chunk_free);
	imquic_refcount_init(&h3c->ref, imquic_http3_connection_free);
	return h3c;
}

void imquic_http3_connection_destroy(imquic_http3_connection *h3c) {
	if(h3c && g_atomic_int_compare_and_exchange(&h3c->destroyed, 0, 1))
		imquic_refcount_decrease(&h3c->ref);
}

/* Helper to parse settings */
int imquic_http3_parse_settings(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 1)
		return -1;
	/* We'll need a temporary chunk that we'll index by stream, to be used as a
	 * buffer in case, e.g., a request is spread across multiple STREAM frames*/
	imquic_buffer_chunk *h3c_chunk = g_hash_table_lookup(h3c->buffers, &stream->stream_id);
	if(h3c_chunk == NULL) {
		/* New buffer */
		h3c_chunk = imquic_buffer_chunk_create(bytes, 0, blen);
		g_hash_table_insert(h3c->buffers, imquic_uint64_dup(stream->stream_id), h3c_chunk);
	} else {
		/* Append data to existing buffer */
		h3c_chunk->data = g_realloc(h3c_chunk->data, h3c_chunk->length + blen);
		memcpy(h3c_chunk->data + h3c_chunk->length, bytes, blen);
		h3c_chunk->length += blen;
	}
	bytes = h3c_chunk->data;
	blen = h3c_chunk->length;
	/* TODO Store those settings somewhere */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing SETTINGS (%zu bytes)\n",
		imquic_get_connection_name(h3c->conn), blen);
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = 0, settings_len = 0, value = 0;
	if(bytes[0] != IMQUIC_HTTP3_SETTINGS) {
		/* FIXME Give up */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Not a SETTINGS payload\n",
			imquic_get_connection_name(h3c->conn));
		g_hash_table_remove(h3c->buffers, &stream->stream_id);
		return -1;
	}
	offset++;
	settings_len = imquic_read_varint(bytes + offset, blen - offset, &length);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- SETTINGS has length %zu\n", settings_len);
	offset += length;
	if(settings_len > blen - offset) {
		/* We may need to wait for more STREAM data, try again later */
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Not enough bytes for SETTINGS, waiting for more data\n",
			imquic_get_connection_name(h3c->conn));
		return -1;
	}
#ifdef HAVE_QLOG
	json_t *frame = NULL, *settings = NULL;
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		frame = imquic_qlog_http3_prepare_content(NULL, "settings", FALSE);
		settings = imquic_qlog_http3_prepare_content(frame, "settings", FALSE);
		imquic_qlog_event_add_raw(frame, "raw", NULL, settings_len);
	}
#endif
	uint64_t s_len = settings_len;
	while(s_len > 0) {
		type = imquic_read_varint(bytes + offset, blen - offset, &length);
		if(length == 0)
			goto error;
		offset += length;
		s_len -= length;
		value = imquic_read_varint(bytes + offset, blen - offset, &length);
		if(length == 0)
			goto error;
		offset += length;
		s_len -= length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- [%"SCNu64"][%s] %"SCNu64"\n",
			type, imquic_http3_settings_type_str(type), value);
#ifdef HAVE_QLOG
		if(settings != NULL) {
			switch(type) {
				case IMQUIC_HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
					json_object_set_new(settings, "settings_qpack_max_table_capacity", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE:
					json_object_set_new(settings, "settings_max_field_section_size", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS:
					json_object_set_new(settings, "settings_qpack_blocked_streams", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
					json_object_set_new(settings, "settings_enable_connect_protocol", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_H3_DATAGRAM:
					json_object_set_new(settings, "settings_h3_datagram", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT:
					json_object_set_new(settings, "settings_enable_webtransport", json_integer(value));
					break;
				case IMQUIC_HTTP3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS:
					json_object_set_new(settings, "settings_webtransport_max_sessions", json_integer(value));
					break;
				default:
					break;
			}
		}
#endif
		/* FIXME */
		if(type == IMQUIC_HTTP3_SETTINGS_ENABLE_WEBTRANSPORT && value != 0)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Establishing WebTransport\n", imquic_get_connection_name(h3c->conn));
	}
	g_hash_table_remove(h3c->buffers, &stream->stream_id);
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
		imquic_http3_qlog_frame_parsed(h3c->conn->qlog, h3c->remote_control_stream, settings_len, frame);
#endif
	h3c->settings_received = TRUE;
	if(h3c->is_server) {
		/* FIXME As an HTTP/3 server, reply with our own SETTINGS */
		imquic_http3_prepare_settings(h3c);
	} else {
		imquic_http3_check_send_connect(h3c);
	}
	return 0;

/* We get here if something went wrong */
error:
	g_hash_table_remove(h3c->buffers, &stream->stream_id);
#ifdef HAVE_QLOG
	if(frame != NULL)
		json_decref(frame);
#endif
	return -1;
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
#ifdef HAVE_QLOG
			if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
				imquic_http3_qlog_stream_type_set(h3c->conn->qlog, FALSE, h3c->remote_control_stream, "control");
#endif
		} else if(stream_type == IMQUIC_HTTP3_QPACK_ENCODER_STREAM) {
			h3c->remote_qpack_encoder_stream = stream->stream_id;
#ifdef HAVE_QLOG
			if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
				imquic_http3_qlog_stream_type_set(h3c->conn->qlog, FALSE, h3c->remote_qpack_encoder_stream, "qpack_encode");
#endif
			/* FIXME */
			if(h3c->qpack == NULL)
				h3c->qpack = imquic_qpack_context_create(4096);
		} else if(stream_type == IMQUIC_HTTP3_QPACK_DECODER_STREAM) {
			h3c->remote_qpack_decoder_stream = stream->stream_id;
#ifdef HAVE_QLOG
			if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
				imquic_http3_qlog_stream_type_set(h3c->conn->qlog, FALSE, h3c->remote_qpack_decoder_stream, "qpack_decode");
#endif
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
		imquic_http3_parse_settings(h3c, stream, chunk->data + p_offset, chunk->length - p_offset);
	} else if(!stream->bidirectional && stream->stream_id == h3c->remote_qpack_encoder_stream) {
		/* QPACK encoder */
		if(chunk->length > p_offset) {
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
			if(!h3c->request_stream_set) {
				h3c->request_stream_set = TRUE;
				h3c->request_stream = stream->stream_id;
#ifdef HAVE_QLOG
				if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
					imquic_http3_qlog_stream_type_set(h3c->conn->qlog, FALSE, h3c->request_stream, "request");
#endif
			}
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
	/* We'll need a temporary chunk that we'll index by stream, to be used as a
	 * buffer in case, e.g., a request is spread across multiple STREAM frames*/
	imquic_buffer_chunk *h3c_chunk = g_hash_table_lookup(h3c->buffers, &stream->stream_id);
	if(h3c_chunk == NULL) {
		/* New buffer */
		h3c_chunk = imquic_buffer_chunk_create(bytes, 0, blen);
		g_hash_table_insert(h3c->buffers, imquic_uint64_dup(stream->stream_id), h3c_chunk);
	} else {
		/* Append data to existing buffer */
		h3c_chunk->data = g_realloc(h3c_chunk->data, h3c_chunk->length + blen);
		memcpy(h3c_chunk->data + h3c_chunk->length, bytes, blen);
		h3c_chunk->length += blen;
	}
	bytes = h3c_chunk->data;
	blen = h3c_chunk->length;
	/* This could be a request or a response */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing HTTP/3 request\n",
		imquic_get_connection_name(h3c->conn));
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	size_t offset = 0, res = 0;
	uint8_t length = 0;
	uint64_t f_len = 0;
	while(blen > offset) {
		imquic_http3_frame_type type = imquic_read_varint(bytes + offset, blen - offset, &length);
		if(length == 0)
			goto retry_later;
		offset += length;
		f_len = imquic_read_varint(bytes + offset, blen - offset, &length);
		if(length == 0)
			goto retry_later;
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s (%02x, %zu bytes)\n", imquic_http3_frame_type_str(type), bytes[0], f_len);
		if(f_len > blen - offset)
			goto retry_later;
		if(type == IMQUIC_HTTP3_DATA) {
			res = imquic_http3_parse_request_data(h3c, stream, (bytes + offset), f_len);
			if(res == 0)
				goto retry_later;
		} else if(type == IMQUIC_HTTP3_HEADERS) {
			res = imquic_http3_parse_request_headers(h3c, stream, (bytes + offset), f_len);
			if(res == 0)
				goto retry_later;
		} else {
			/* TODO */
			res = f_len;
		}
		offset += res;
		/* Frame parsed, update the buffer */
		blen -= offset;
		if(blen > 0) {
			memmove(h3c_chunk->data, h3c_chunk->data + offset, blen);
			h3c_chunk->length = blen;
			bytes = h3c_chunk->data;
		}
		offset = 0;
	}
	/* Done */
	g_hash_table_remove(h3c->buffers, &stream->stream_id);
	return 0;

/* If we got here, we need to wait for more data and try again later */
retry_later:
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Not enough bytes to parse HTTP/3 request, waiting for more data\n",
		imquic_get_connection_name(h3c->conn));
	return -1;
}

size_t imquic_http3_parse_request_headers(imquic_http3_connection *h3c, imquic_stream *stream, uint8_t *bytes, size_t blen) {
	/* TODO Actually take note of what we parse here */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Parsing HTTP/3 HEADERS\n",
		imquic_get_connection_name(h3c->conn));
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	if(h3c->qpack == NULL)
		h3c->qpack = imquic_qpack_context_create(4096);
#ifdef HAVE_QLOG
	json_t *frame = NULL, *frame_headers = NULL;
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		frame = imquic_qlog_http3_prepare_content(NULL, "headers", FALSE);
		frame_headers = imquic_qlog_http3_prepare_content(frame, "headers", TRUE);
		imquic_qlog_event_add_raw(frame, "raw", NULL, blen);
	}
#endif
	size_t bread = 0;
	GList *headers = imquic_qpack_process(h3c->qpack, bytes, blen, &bread);
	GList *temp = headers;
	imquic_qpack_entry *header = NULL;
	while(temp) {
		header = (imquic_qpack_entry *)temp->data;
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- -- %s = %s\n", header->name, header->value);
#ifdef HAVE_QLOG
		if(frame_headers != NULL)
			imquic_qlog_http3_append_object(frame_headers, header->name, header->value);
#endif
		temp = temp->next;
	}
	g_list_free_full(headers, (GDestroyNotify)imquic_qpack_entry_destroy);
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
		imquic_http3_qlog_frame_parsed(h3c->conn->qlog, h3c->request_stream, blen, frame);
#endif
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
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		json_t *frame = imquic_qlog_http3_prepare_content(NULL, "data", FALSE);
		imquic_qlog_event_add_raw(frame, "raw", NULL, blen);
		imquic_http3_qlog_frame_parsed(h3c->conn->qlog, h3c->request_stream, blen, frame);
	}
#endif
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
	if(h3c->conn->socket && h3c->conn->socket->h3_path)
		path = (const char *)h3c->conn->socket->h3_path;
	headers = g_list_append(headers, imquic_qpack_entry_create(":path", path));
	headers = g_list_append(headers, imquic_qpack_entry_create(":protocol", "webtransport"));
	headers = g_list_append(headers, imquic_qpack_entry_create("user-agent", "imquic/0.0.1alpha"));
	headers = g_list_append(headers, imquic_qpack_entry_create("sec-fetch-dest", "webtransport"));
	headers = g_list_append(headers, imquic_qpack_entry_create("sec-webtransport-http3-draft02", "1"));
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
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		json_t *frame = imquic_qlog_http3_prepare_content(NULL, "headers", FALSE);
		json_t *headers = imquic_qlog_http3_prepare_content(frame, "headers", TRUE);
		imquic_qlog_http3_append_object(headers, ":method", "CONNECT");
		imquic_qlog_http3_append_object(headers, ":scheme", "https");
		imquic_qlog_http3_append_object(headers, ":authority",
			imquic_network_address_str(&h3c->conn->socket->remote_address, address, sizeof(address), TRUE));
		imquic_qlog_http3_append_object(headers, ":path", "path");
		imquic_qlog_http3_append_object(headers, ":protocol", "webtransport");
		imquic_qlog_http3_append_object(headers, "user-agent", "imquic/0.0.1alpha");
		imquic_qlog_http3_append_object(headers, "sec-fetch-dest", "webtransport");
		imquic_qlog_http3_append_object(headers, "sec-webtransport-http3-draft02", "1");
		imquic_qlog_event_add_raw(frame, "raw", NULL, r_len);
		imquic_http3_qlog_frame_created(h3c->conn->qlog, h3c->request_stream, r_len, frame);
	}
#endif
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
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		json_t *frame = imquic_qlog_http3_prepare_content(NULL, "headers", FALSE);
		json_t *headers = imquic_qlog_http3_prepare_content(frame, "headers", TRUE);
		imquic_qlog_http3_append_object(headers, ":status", "200");
		imquic_qlog_http3_append_object(headers, "server", server);
		imquic_qlog_http3_append_object(headers, "sec-webtransport-http3-draft", "draft02");
		imquic_qlog_event_add_raw(frame, "raw", NULL, r_len);
		imquic_http3_qlog_frame_created(h3c->conn->qlog, h3c->request_stream, r_len, frame);
	}
#endif
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
			h3c->request_stream_set = TRUE;
			h3c->request_stream = stream_id;
#ifdef HAVE_QLOG
			if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
				imquic_http3_qlog_stream_type_set(h3c->conn->qlog, TRUE, stream_id, "request");
#endif
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
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3) {
		imquic_http3_qlog_stream_type_set(h3c->conn->qlog, TRUE, h3c->local_control_stream, "control");
		json_t *frame = imquic_qlog_http3_prepare_content(NULL, "settings", FALSE);
		json_t *settings = imquic_qlog_http3_prepare_content(frame, "settings", FALSE);
		json_object_set_new(settings, "settings_qpack_max_table_capacity", json_integer(4096));
		json_object_set_new(settings, "settings_qpack_blocked_streams", json_integer(16));
		json_object_set_new(settings, "settings_enable_connect_protocol", json_integer(1));
		json_object_set_new(settings, "settings_h3_datagram", json_integer(1));
		json_object_set_new(settings, "settings_enable_webtransport", json_integer(1));
		imquic_qlog_event_add_raw(frame, "raw", NULL, s_offset - 3);
		imquic_http3_qlog_frame_created(h3c->conn->qlog, h3c->local_control_stream, s_offset - 3, frame);
	}
#endif
	imquic_connection_send_on_stream(h3c->conn, h3c->local_control_stream, settings, 0, s_offset, FALSE);
	imquic_connection_new_stream_id(h3c->conn, FALSE, &h3c->local_qpack_encoder_stream);
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
		imquic_http3_qlog_stream_type_set(h3c->conn->qlog, TRUE, h3c->local_qpack_encoder_stream, "qpack_encode");
#endif
	settings[0] = IMQUIC_HTTP3_QPACK_ENCODER_STREAM;
	imquic_connection_send_on_stream(h3c->conn, h3c->local_qpack_encoder_stream, settings, 0, 1, FALSE);
	imquic_connection_new_stream_id(h3c->conn, FALSE, &h3c->local_qpack_decoder_stream);
#ifdef HAVE_QLOG
	if(h3c->conn->qlog != NULL && h3c->conn->qlog->http3)
		imquic_http3_qlog_stream_type_set(h3c->conn->qlog, TRUE, h3c->local_qpack_decoder_stream, "qpack_decode");
#endif
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

#ifdef HAVE_QLOG
void imquic_http3_qlog_parameters_set(imquic_qlog *qlog, gboolean local, gboolean extended_connect, gboolean h3_datagram) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("http3:parameters_set");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "extended_connect", json_integer(extended_connect));
	json_object_set_new(data, "h3_datagram", json_integer(h3_datagram));
	if(local)
		json_object_set_new(data, "wait_for_settings", json_true());
	imquic_qlog_append_event(qlog, event);
}

json_t *imquic_qlog_http3_prepare_content(json_t *parent, const char *name, gboolean array) {
	if(parent != NULL && !json_is_object(parent) && !json_is_array(parent))
		return NULL;
	if((parent == NULL || array) && name == NULL)
		return NULL;
	json_t *content = (!array || parent == NULL) ? json_object() : json_array();
	if(parent == NULL) {
		json_object_set_new(content, "frame_type", json_string(name));
	} else {
		if(json_is_array(parent))
			json_array_append_new(parent, content);
		else
			json_object_set_new(parent, name, content);
	}
	return content;
}

void imquic_qlog_http3_append_object(json_t *parent, const char *name, const char *value) {
	if(parent == NULL || !json_is_array(parent) || name == NULL || value == NULL)
		return;
	json_t *object = json_object();
	json_object_set_new(object, name, json_string(value));
	json_array_append_new(parent, object);
}

void imquic_http3_qlog_stream_type_set(imquic_qlog *qlog, gboolean local, uint64_t stream_id, const char *type) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("http3:stream_type_set");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "owner", json_string(local ? "local" : "remote"));
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "stream_type", json_string(type));
	imquic_qlog_append_event(qlog, event);
}

void imquic_http3_qlog_frame_created(imquic_qlog *qlog, uint64_t stream_id, uint64_t length, json_t *frame) {
	if(qlog == NULL) {
		if(frame != NULL)
			json_decref(frame);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("http3:frame_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "length", json_integer(length));
	if(frame != NULL)
		json_object_set_new(data, "frame", frame);
	imquic_qlog_append_event(qlog, event);
}

void imquic_http3_qlog_frame_parsed(imquic_qlog *qlog, uint64_t stream_id, uint64_t length, json_t *frame) {
	if(qlog == NULL) {
		if(frame != NULL)
			json_decref(frame);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("http3:frame_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "length", json_integer(length));
	if(frame != NULL)
		json_object_set_new(data, "frame", frame);
	imquic_qlog_append_event(qlog, event);
}
#endif
