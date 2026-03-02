/*! \file   connection.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC connection abstraction
 * \details Abstraction of QUIC connections, during or after establishment.
 * This is where helper functions are exposed to the QUIC stack internals
 * for the purpose of creating STREAM ids, send data, and notify upper
 * layers about incoming data or shutdowns.
 *
 * \ingroup Core
 */

#include "internal/connection.h"
#include "internal/stream.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Connection ID utilities */
const char *imquic_connection_id_str(picoquic_connection_id_t *cid, char *buffer, size_t blen) {
	if(cid == NULL || cid->id_len == 0 || blen == 0)
		return NULL;
	if(cid->id_len*2 >= blen) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render connection ID as a string (truncation would occur)\n");
		return NULL;
	}
	*buffer = '\0';
	char hex[3];
	size_t offset = 0;
	for(size_t i=0; i<cid->id_len; i++) {
		g_snprintf(hex, sizeof(hex), "%02x", cid->id[i]);
		imquic_strlcat_fast(buffer, hex, blen, &offset);
	}
	return buffer;
}

/* Connection events */
static void imquic_connection_events_empty(imquic_connection *conn);

/* Connection management */
static void imquic_connection_free(const imquic_refcount *conn_ref) {
	imquic_connection *conn = imquic_refcount_containerof(conn_ref, imquic_connection, ref);
	g_free(conn->name);
	g_free(conn->chosen_alpn);
	g_free(conn->chosen_wt_protocol);
	g_hash_table_unref(conn->streams);
	imquic_connection_events_empty(conn);
	g_async_queue_unref(conn->queued_events);
	imquic_http3_connection_destroy(conn->http3);
	if(conn->socket != NULL)
		imquic_refcount_decrease(&conn->socket->ref);
	free(conn);
}

imquic_connection *imquic_connection_create(imquic_network_endpoint *socket, picoquic_cnx_t *piconn) {
	if(socket == NULL)
		return NULL;
	/* FIXME */
	imquic_connection *conn = g_malloc0(sizeof(imquic_connection));
	if(!socket->is_server) {
		/* This is a client, create a picoquic client connection */
		conn->piconn = picoquic_create_cnx(
			socket->qc,
			picoquic_null_connection_id,	/* initial connection ID */
			picoquic_null_connection_id,	/* remote connection ID */
			(struct sockaddr *)&socket->remote_address.addr,
			picoquic_current_time(),
			0,
			socket->sni,
			NULL,	/* We'll negotiate the ALPN via callack */
			1);		/* client mode */
		if(conn->piconn == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error creating client connection\n", socket->name);
			g_free(conn);
			return NULL;
		}
		picoquic_cnx_set_pmtud_policy(conn->piconn, picoquic_pmtud_delayed);
		picoquic_set_default_pmtud_policy(socket->qc, picoquic_pmtud_delayed);
	} else {
		/* This is a server, track the picoquic connection we received */
		conn->piconn = piconn;
	}
	/* FIXME We're assuming an idle timeout of 30s, which is the default */
	picoquic_enable_keep_alive(conn->piconn, 15 * G_USEC_PER_SEC);
	imquic_mutex_lock(&socket->mutex);
	uint64_t id = ++socket->conns_num;
	imquic_mutex_unlock(&socket->mutex);
	char name[200];
	g_snprintf(name, sizeof(name), "%s/%"SCNu64, socket->name, id);
	conn->name = g_strdup(name);
	conn->just_started = TRUE;
	conn->is_server = socket->is_server;
	conn->socket = socket;
	imquic_refcount_increase(&socket->ref);
	/* Streams map */
	conn->streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_stream_destroy);
	conn->queued_events = g_async_queue_new();
	imquic_refcount_init(&conn->ref, imquic_connection_free);
	imquic_network_endpoint_add_connection(conn->socket, conn, TRUE);
	conn->loop_source = imquic_loop_poll_connection(conn);
	return conn;
}

void imquic_connection_destroy(imquic_connection *conn) {
	if(conn && g_atomic_int_compare_and_exchange(&conn->destroyed, 0, 1)) {
#ifdef HAVE_QLOG
		if(conn->qlog != NULL) {
			imquic_qlog_destroy(conn->qlog);
			conn->qlog = NULL;
		}
#endif
		imquic_refcount_decrease(&conn->ref);
	}
}

/* Helper to generate a new stream ID for this connection */
int imquic_connection_new_stream_id(imquic_connection *conn, gboolean bidirectional, uint64_t *stream_id) {
	if(conn == NULL || conn->piconn == NULL)
		return -1;
	/* Get a new stream ID
	 * FIXME this should be done on the loop thread */
	imquic_mutex_lock(&conn->mutex);
	uint64_t new_stream_id = imquic_build_stream_id(bidirectional ? conn->stream_next_bidi : conn->stream_next_uni,
		!conn->is_server, bidirectional);
	if(bidirectional)
		conn->stream_next_bidi++;
	else
		conn->stream_next_uni++;
	/* Create a new stream instance */
	imquic_stream *stream = imquic_stream_create(new_stream_id, conn->is_server);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Created new %s initiated %s stream '%"SCNu64"'\n",
		imquic_get_connection_name(conn), stream->client_initiated ? "client" : "server",
		stream->bidirectional ? "bidirectional" : "unidirectional", new_stream_id);
	g_hash_table_insert(conn->streams, imquic_dup_uint64(new_stream_id), stream);
	imquic_mutex_unlock(&conn->mutex);
	if(stream_id)
		*stream_id = new_stream_id;
	if(conn->http3 != NULL && conn->http3->webtransport) {
		/* We need to write the info on the new WebTransport stream */
		uint8_t prefix[10];
		size_t plen = sizeof(prefix);
		size_t offset = imquic_write_varint(stream->bidirectional ? IMQUIC_HTTP3_WEBTRANSPORT_STREAM : IMQUIC_HTTP3_WEBTRANSPORT_UNI_STREAM, prefix, plen);
		offset += imquic_write_varint(0, &prefix[offset], plen-offset);	/* FIXME Should we expose session ID? */
		imquic_connection_send_on_stream(conn, stream->stream_id, prefix, offset, FALSE);
	}
	return 0;
}

/* Helper to send data on a DATAGRAM */
int imquic_connection_send_on_datagram(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	if(conn == NULL)
		return -1;
	if(bytes == NULL || length == 0)
		return 0;
	/* Queue the data to send */
	imquic_connection_event *event = imquic_connection_event_create(IMQUIC_CONNECTION_EVENT_DATAGRAM);
	if(conn->http3 != NULL) {
		/* FIXME For HTTP/3 and WebTransport DATAGRAM, we need to prefix
		 * the payload with the Quarter Stream ID: we don't currently
		 * support it, so we simply hardcode its value to 0x00 */
		 uint8_t zero = 0;
		event->data = imquic_buffer_create(&zero, 1);
		imquic_buffer_append(event->data, bytes, length);
	} else {
		event->data = imquic_buffer_create(bytes, length);
	}
	g_async_queue_push(conn->queued_events, event);
	imquic_loop_wakeup();
	return 0;
}

/* Helper to send data on a STREAM */
int imquic_connection_send_on_stream(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t length, gboolean complete) {
	if(conn == NULL)
		return -1;
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream == NULL || stream->out_state == IMQUIC_STREAM_BLOCKED ||
			stream->out_state == IMQUIC_STREAM_RESET || stream->out_state == IMQUIC_STREAM_COMPLETE) {
		imquic_mutex_unlock(&conn->mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't send data, no such stream %"SCNu64"\n",
			imquic_get_connection_name(conn), stream_id);
		return -1;
	}
	imquic_refcount_increase(&stream->ref);
	imquic_mutex_unlock(&conn->mutex);
	/* Queue the data to send */
	imquic_connection_event *event = imquic_connection_event_create(IMQUIC_CONNECTION_EVENT_STREAM);
	event->stream_id = stream_id;
	event->fin = complete;
	event->data = imquic_buffer_create(bytes, length);
	g_async_queue_push(conn->queued_events, event);
	/* Update the stream status, if needed */
	imquic_mutex_lock(&stream->mutex);
	if(complete)
		imquic_stream_mark_complete(stream, FALSE);
	imquic_mutex_unlock(&stream->mutex);
	imquic_refcount_decrease(&stream->ref);
	/* Done */
	imquic_loop_wakeup();
	return 0;
}

/* Helper to notify incoming DATAGRAM data to the application */
void imquic_connection_notify_datagram_incoming(imquic_connection *conn, uint8_t *data, uint64_t length) {
	if(conn == NULL || conn->socket == NULL || data == NULL || length == 0)
		return;
	if(conn->socket->datagram_incoming == NULL)
		return;
	/* Notify the data */
	conn->socket->datagram_incoming(conn, data, length);
}

/* Helper to notify incoming STREAM data to the application */
void imquic_connection_notify_stream_incoming(imquic_connection *conn, imquic_stream *stream, uint8_t *data, uint64_t length) {
	if(conn == NULL || conn->socket == NULL || conn->socket->stream_incoming == NULL ||
			stream == NULL || ((data == NULL || length == 0) && stream->in_state != IMQUIC_STREAM_COMPLETE))
		return;
	/* Notify the data */
	conn->socket->stream_incoming(conn, stream->stream_id,
		data, length, (stream->in_state == IMQUIC_STREAM_COMPLETE));
}

/* Helper to notify about the connection being gone */
void imquic_connection_notify_gone(imquic_connection *conn) {
	if(conn == NULL || conn->socket == NULL || !g_atomic_int_compare_and_exchange(&conn->notified_close, 0, 1))
		return;
	/* Notify the event */
	if(conn->established && conn->socket->connection_gone)
		conn->socket->connection_gone(conn);
	else if(!conn->is_server && !conn->established && conn->socket->connection_failed)
		conn->socket->connection_failed(conn->socket->user_data);
}

/* Helper to reset a STREAM */
void imquic_connection_reset_stream(imquic_connection *conn, uint64_t stream_id, uint64_t error_code) {
	if(conn == NULL)
		return;
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream == NULL || !stream->can_send) {
		imquic_mutex_unlock(&conn->mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't close stream, no such stream %"SCNu64"\n",
			imquic_get_connection_name(conn), stream_id);
		return;
	}
	imquic_refcount_increase(&stream->ref);
	imquic_mutex_unlock(&conn->mutex);
	imquic_mutex_lock(&stream->mutex);
	if(stream->out_state >= IMQUIC_STREAM_RESET) {
		imquic_mutex_unlock(&stream->mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't prepare RESET_STREAM for %"SCNu64" (alreayd sent?)\n",
			imquic_get_connection_name(conn), stream_id);
	} else {
		imquic_stream_mark_complete(stream, FALSE);
		stream->out_state = IMQUIC_STREAM_RESET;
		imquic_mutex_unlock(&stream->mutex);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Closing stream %"SCNu64" (RESET_STREAM)\n",
			imquic_get_connection_name(conn), stream_id);
		imquic_connection_event *event = imquic_connection_event_create(IMQUIC_CONNECTION_EVENT_RESET_STREAM);
		event->stream_id = stream_id;
		event->error_code = error_code;
		g_async_queue_push(conn->queued_events, event);
		imquic_loop_wakeup();
	}
	imquic_refcount_decrease(&stream->ref);
}

/* Helpers to close connections */
void imquic_connection_close(imquic_connection *conn, uint64_t error_code, const char *reason) {
	/* Send a CONNECTION CLOSE */
	if(conn == NULL || conn->socket == NULL || g_atomic_int_get(&conn->closed) ||
			!g_atomic_int_compare_and_exchange(&conn->closing, 0, 1))
		return;
	/* FIXME picoquic doesn't allow us to provide a reason? */
	imquic_connection_event *event = imquic_connection_event_create(IMQUIC_CONNECTION_EVENT_CLOSE_CONN);
	event->error_code = error_code;
	if(reason != NULL)
		event->reason = g_strdup(reason);
	g_async_queue_push(conn->queued_events, event);
	imquic_loop_wakeup();
	int64_t started = g_get_monotonic_time();
	while(!g_atomic_int_get(&conn->closed) && ((g_get_monotonic_time()-started) < 100000))
		g_usleep(10000);
}

/* Create an event */
imquic_connection_event *imquic_connection_event_create(imquic_connection_event_type type) {
	imquic_connection_event *event = g_malloc0(sizeof(imquic_connection_event));
	event->type = type;
	return event;
}

/* Destroy an event */
void imquic_connection_event_destroy(imquic_connection_event *event) {
	if(event != NULL) {
		imquic_buffer_destroy(event->data);
		g_free(event->reason);
		g_free(event);
	}
}

/* Clean the list of queued events for a connection */
static void imquic_connection_events_empty(imquic_connection *conn) {
	if(conn == NULL || conn->queued_events == NULL)
		return;
	imquic_connection_event *event = NULL;
	while(g_async_queue_length(conn->queued_events) > 0) {
		event = g_async_queue_try_pop(conn->queued_events);
		imquic_connection_event_destroy(event);
	}
}
