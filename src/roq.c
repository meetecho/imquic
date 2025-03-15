/*! \file   roq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  RTP Over QUIC (RoQ) stack
 * \details Implementation of the RTP Over QUIC (RoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) version -10 of the protocol.
 *
 * \note This is the internal implementation of RoQ in the library. You're
 * still free to only use imquic as the underlying QUIC/WebTransport library,
 * and take care of the RoQ implementation on your own instead: in order
 * to do that, use the generic imquic client/server creation utilities,
 * rather than the RoQ specific ones.
 *
 * \ingroup RoQ Core
 */

#include "imquic/roq.h"
#include "internal/roq.h"
#include "internal/connection.h"

/* Collection of sessions */
static GHashTable *roq_sessions = NULL;
static imquic_mutex roq_mutex = IMQUIC_MUTEX_INITIALIZER;

/* Cleanup helpers */
static void imquic_roq_endpoint_destroy(imquic_roq_endpoint *endpoint) {
	if(endpoint) {
		if(endpoint->stream_flows_in != NULL)
			g_hash_table_unref(endpoint->stream_flows_in);
		if(endpoint->stream_flows_out != NULL)
			g_hash_table_unref(endpoint->stream_flows_out);
		if(endpoint->packets != NULL)
			g_hash_table_unref(endpoint->packets);
		g_free(endpoint);
	}
}

static void imquic_roq_stream_destroy(imquic_roq_stream *roq_stream) {
	if(roq_stream && g_atomic_int_compare_and_exchange(&roq_stream->destroyed, 0, 1))
		imquic_refcount_decrease(&roq_stream->ref);
}

static void imquic_roq_stream_free(const imquic_refcount *rs_ref) {
	imquic_roq_stream *roq_stream = imquic_refcount_containerof(rs_ref, imquic_roq_stream, ref);
	g_free(roq_stream);
}

/* Initialization */
void imquic_roq_init(void) {
	roq_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_roq_endpoint_destroy);
}

void imquic_roq_deinit(void) {
	imquic_mutex_lock(&roq_mutex);
	if(roq_sessions != NULL)
		g_hash_table_unref(roq_sessions);
	roq_sessions = NULL;
	imquic_mutex_unlock(&roq_mutex);
}

/* Buffered packet, in case it's needed */
typedef struct imquic_roq_packet {
	uint8_t *buffer;
	size_t offset;
	size_t length;
	size_t size;
	uint64_t rtp_len;
} imquic_roq_packet;
static void imquic_roq_packet_free(imquic_roq_packet *pkt) {
	if(pkt) {
		g_free(pkt->buffer);
		g_free(pkt);
	}
}

/* Helper method to add incoming data to a buffer */
static int imquic_roq_buffer_data(imquic_roq_endpoint *endpoint, uint64_t flow_id, uint64_t stream_id, uint8_t *bytes, size_t blen) {
	imquic_roq_packet *pkt = g_hash_table_lookup(endpoint->packets, &stream_id);
	if(pkt == NULL) {
		/* Add a new buffered packet from the data we received */
		pkt = g_malloc(sizeof(*pkt));
		pkt->buffer = g_malloc(blen);
		pkt->offset = 0;
		pkt->length = blen;
		pkt->size = blen;
		pkt->rtp_len = 0;
		memcpy(pkt->buffer, bytes, blen);
		g_hash_table_insert(endpoint->packets, imquic_uint64_dup(stream_id), pkt);
#ifdef HAVE_QLOG
		if(endpoint->conn != NULL && endpoint->conn->qlog != NULL && endpoint->conn->qlog->roq)
			imquic_roq_qlog_stream_opened(endpoint->conn->qlog, stream_id, flow_id);
#endif
	} else if(blen > 0) {
		/* Append the data */
		if(blen > (pkt->size - pkt->length)) {
			pkt->size += blen - (pkt->size - pkt->length);
			pkt->buffer = g_realloc(pkt->buffer, pkt->size);
		}
		memcpy(pkt->buffer + pkt->length, bytes, blen);
		pkt->length += blen;
	}
	uint8_t parsed = 0;
	if(pkt->rtp_len == 0) {
		pkt->rtp_len = imquic_varint_read(pkt->buffer + pkt->offset, pkt->length - pkt->offset, &parsed);
		pkt->offset += parsed;
	}
	if(pkt->rtp_len <= (pkt->length - pkt->offset)) {
		/* We have enough data for an RTP packet, notify the application */
#ifdef HAVE_QLOG
		if(endpoint->conn && endpoint->conn->qlog != NULL && endpoint->conn->qlog->roq)
			imquic_roq_qlog_stream_packet_parsed(endpoint->conn->qlog, stream_id, flow_id, pkt->rtp_len);
#endif
		if(pkt->rtp_len > 0 && endpoint->conn && endpoint->conn->socket && endpoint->conn->socket->callbacks.roq.rtp_incoming)
			endpoint->conn->socket->callbacks.roq.rtp_incoming(endpoint->conn, flow_id, pkt->buffer + pkt->offset, pkt->rtp_len);
		/* Move on */
		pkt->offset += pkt->rtp_len;
		pkt->rtp_len = 0;
		if((pkt->length - pkt->offset) <= 8) {
			/* We're done for now (there may not be enough room for the RTP packet length) */
			pkt->length -= pkt->offset;
			pkt->offset = 0;
		} else {
			/* There's more data to process, shift the buffer */
			pkt->length -= pkt->offset;
			memmove(pkt->buffer, pkt->buffer + pkt->offset, pkt->length);
			pkt->offset = 0;
			return imquic_roq_buffer_data(endpoint, flow_id, stream_id, NULL, 0);
		}
	} else {
		/* We'll need more data before we can process this packet */
	}
	return 0;
}

/* Callbacks */
void imquic_roq_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_refcount_increase(&conn->ref);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][RoQ] New connection %p\n", imquic_get_connection_name(conn), conn);
	imquic_roq_endpoint *endpoint = g_malloc(sizeof(imquic_roq_endpoint));
	endpoint->conn = conn;
	endpoint->stream_flows_in = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)g_free);
	endpoint->stream_flows_out = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_roq_stream_destroy);
	endpoint->packets = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_roq_packet_free);
	imquic_mutex_init(&endpoint->mutex);
	imquic_mutex_lock(&roq_mutex);
	g_hash_table_insert(roq_sessions, conn, endpoint);
	imquic_mutex_unlock(&roq_mutex);
	if(conn->socket && conn->socket->callbacks.roq.new_connection)
		conn->socket->callbacks.roq.new_connection(conn, user_data);
}

void imquic_roq_stream_incoming(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	/* Got incoming data via STREAM */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][RoQ] [STREAM-%"SCNu64"] Got data: %"SCNu64"--%"SCNu64" (%s)\n",
		imquic_get_connection_name(conn),
		stream_id, offset, offset+length, (complete ? "complete" : "not complete"));
	imquic_mutex_lock(&roq_mutex);
	imquic_roq_endpoint *endpoint = g_hash_table_lookup(roq_sessions, conn);
	imquic_mutex_unlock(&roq_mutex);
	if(endpoint == NULL)
		return;
	/* Do we know the flow ID already? */
	uint8_t parsed = 0;
	size_t p_offset = 0;
	imquic_mutex_lock(&endpoint->mutex);
	uint64_t s_flow_id = 0, *flow_id = g_hash_table_lookup(endpoint->stream_flows_in, &stream_id);
	imquic_mutex_unlock(&endpoint->mutex);
	if(flow_id == NULL) {
		/* We don't, get it from the data */
		s_flow_id = imquic_varint_read(bytes, length, &parsed);
		p_offset += parsed;
		if(!complete) {
			imquic_mutex_lock(&endpoint->mutex);
			g_hash_table_insert(endpoint->stream_flows_in, imquic_uint64_dup(stream_id), imquic_uint64_dup(s_flow_id));
			imquic_mutex_unlock(&endpoint->mutex);
		}
	} else {
		s_flow_id = *flow_id;
	}
	/* Handle the STREAM data */
	if(imquic_roq_buffer_data(endpoint, s_flow_id, stream_id, bytes + p_offset, length - p_offset)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error buffering STREAM data\n", imquic_get_connection_name(conn));
	}
	if(complete) {
		imquic_mutex_lock(&endpoint->mutex);
		g_hash_table_remove(endpoint->stream_flows_in, &stream_id);
		g_hash_table_remove(endpoint->packets, &stream_id);
		imquic_mutex_unlock(&endpoint->mutex);
	}
}

void imquic_roq_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	/* Got incoming data via DATAGRAM */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][RoQ] [DATAGRAM] Got data: %"SCNu64"\n", imquic_get_connection_name(conn), length);
	/* Get the flow ID */
	uint8_t parsed = 0;
	uint64_t flow_id = imquic_varint_read(bytes, length, &parsed);
	/* Notify the application */
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->roq)
		imquic_roq_qlog_datagram_packet_parsed(conn->qlog, flow_id, length - parsed);
#endif
	if(length > 0 && conn->socket && conn->socket->callbacks.roq.rtp_incoming)
		conn->socket->callbacks.roq.rtp_incoming(conn, flow_id, bytes + parsed, length - parsed);
}

void imquic_roq_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	imquic_mutex_lock(&roq_mutex);
	gboolean removed = g_hash_table_remove(roq_sessions, conn);
	imquic_mutex_unlock(&roq_mutex);
	if(conn->socket && conn->socket->callbacks.roq.connection_gone)
		conn->socket->callbacks.roq.connection_gone(conn);
	if(removed) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][RoQ] Connection gone\n", imquic_get_connection_name(conn));
		imquic_refcount_decrease(&conn->ref);
	}
}

/* Sending RTP packets */
static imquic_roq_stream *imquic_roq_stream_create(imquic_connection *conn, imquic_roq_endpoint *endpoint, uint64_t flow_id) {
	imquic_roq_stream *roq_stream = g_malloc0(sizeof(imquic_roq_stream));
	imquic_connection_new_stream_id(conn, FALSE, &roq_stream->stream_id);
	roq_stream->flow_id = flow_id;
	imquic_refcount_init(&roq_stream->ref, imquic_roq_stream_free);
	g_hash_table_insert(endpoint->stream_flows_out, imquic_uint64_dup(flow_id), roq_stream);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->roq)
		imquic_roq_qlog_stream_opened(conn->qlog, roq_stream->stream_id, flow_id);
#endif
	return roq_stream;
}

size_t imquic_roq_send_rtp(imquic_connection *conn, imquic_roq_multiplexing multiplexing,
		uint64_t flow_id, uint8_t *bytes, size_t blen, gboolean close_stream) {
	if(conn == NULL || bytes == NULL || blen < 12)
		return 0;
	imquic_mutex_lock(&roq_mutex);
	imquic_roq_endpoint *endpoint = g_hash_table_lookup(roq_sessions, conn);
	imquic_mutex_unlock(&roq_mutex);
	if(endpoint == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][RoQ] No RoQ session associated with this QUIC connection\n",
			imquic_get_connection_name(conn));
		return 0;
	}
	/* Check how we should send this packet */
	uint8_t outgoing[2048];
	size_t offset = 0, outlen = sizeof(outgoing);
	if(multiplexing == IMQUIC_ROQ_DATAGRAM) {
		/* Send the RTP packet as a QUIC DATAGRAM */
		offset = imquic_varint_write(flow_id, outgoing, outlen);
		memcpy(outgoing + offset, bytes, blen);
		offset += blen;
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->roq)
			imquic_roq_qlog_datagram_packet_created(conn->qlog, flow_id, blen);
#endif
		imquic_send_on_datagram(conn, outgoing, offset);
	} else if(multiplexing == IMQUIC_ROQ_STREAM) {
		/* Send the RTP packet on its flow STREAM */
		imquic_mutex_lock(&endpoint->mutex);
		imquic_roq_stream *roq_stream = g_hash_table_lookup(endpoint->stream_flows_out, &flow_id);
		if(roq_stream == NULL)
			roq_stream = imquic_roq_stream_create(conn, endpoint, flow_id);
		if(roq_stream == NULL) {
			imquic_mutex_unlock(&endpoint->mutex);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][RoQ] No such outgoing stream with flow ID %"SCNu64"\n",
				imquic_get_connection_name(conn), flow_id);
			return 0;
		}
		imquic_refcount_increase(&roq_stream->ref);
		imquic_mutex_unlock(&endpoint->mutex);
		if(roq_stream->offset == 0) {
			/* Write the flow ID first */
			offset = imquic_varint_write(flow_id, outgoing, outlen);
		}
		offset += imquic_varint_write(blen, outgoing + offset, outlen-offset);
		memcpy(outgoing + offset, bytes, blen);
		offset += blen;
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->roq)
			imquic_roq_qlog_stream_packet_created(conn->qlog, roq_stream->stream_id, flow_id, blen);
#endif
		imquic_send_on_stream(conn, roq_stream->stream_id, outgoing, roq_stream->offset, offset, close_stream);
		roq_stream->offset += offset;
		imquic_mutex_lock(&endpoint->mutex);
		if(close_stream)
			g_hash_table_remove(endpoint->stream_flows_out, &flow_id);
		imquic_mutex_unlock(&endpoint->mutex);
		imquic_refcount_decrease(&roq_stream->ref);
	}
	/* Done, return the number of sent bytes */
	return offset;
}

#ifdef HAVE_QLOG
/* QLOG support */
void imquic_roq_qlog_add_rtp_packet(json_t *data, uint64_t flow_id, uint64_t length) {
	if(data != NULL) {
		json_object_set_new(data, "flow_id", json_integer(flow_id));
		json_object_set_new(data, "length", json_integer(length));
	}
}

void imquic_roq_qlog_stream_opened(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("roq:stream_opened");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "flow_id", json_integer(flow_id));
	imquic_qlog_append_event(qlog, event);
}

void imquic_roq_qlog_stream_packet_created(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id, uint64_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("roq:stream_packet_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	imquic_roq_qlog_add_rtp_packet(data, flow_id, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_roq_qlog_stream_packet_parsed(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id, uint64_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("roq:stream_packet_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	imquic_roq_qlog_add_rtp_packet(data, flow_id, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_roq_qlog_datagram_packet_created(imquic_qlog *qlog, uint64_t flow_id, uint64_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("roq:datagram_packet_created");
	json_t *data = imquic_qlog_event_add_data(event);
	imquic_roq_qlog_add_rtp_packet(data, flow_id, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_roq_qlog_datagram_packet_parsed(imquic_qlog *qlog, uint64_t flow_id, uint64_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("roq:datagram_packet_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	imquic_roq_qlog_add_rtp_packet(data, flow_id, length);
	imquic_qlog_append_event(qlog, event);
}
#endif
