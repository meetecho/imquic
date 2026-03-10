/*! \file   moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Media Over QUIC (MoQ) stack
 * \details Implementation of the Media Over QUIC (MoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) versions from -16 to to -17 of the protocol.
 *
 * \note This is the internal implementation of MoQ in the library. You're
 * still free to only use imquic as the underlying QUIC/WebTransport library,
 * and take care of the MoQ implementation on your own instead: in order
 * to do that, use the generic imquic client/server creation utilities,
 * rather than the MoQ specific ones.
 *
 * \ingroup MoQ Core
 */

#include <arpa/inet.h>

#include "internal/moq.h"
#include "internal/connection.h"
#include "internal/version.h"
#include "imquic/debug.h"

/* Logging */
#define IMQUIC_MOQ_LOG_VERB	IMQUIC_LOG_HUGE
#define IMQUIC_MOQ_LOG_HUGE	IMQUIC_LOG_VERB
//~ #define IMQUIC_MOQ_LOG_VERB	IMQUIC_LOG_INFO
//~ #define IMQUIC_MOQ_LOG_HUGE	IMQUIC_LOG_INFO

/* Request IDs management */
#define IMQUIC_MOQ_REQUEST_ID_INCREMENT	2

/* Collection of sessions */
static GHashTable *moq_sessions = NULL;
static imquic_mutex moq_mutex = IMQUIC_MUTEX_INITIALIZER;

/* Buffering of streams/requests, where needed */
typedef struct imquic_moq_pending_stream {
	uint64_t stream_id;
	imquic_buffer *buffer;
	gboolean complete;
} imquic_moq_pending_stream;
static void imquic_moq_pending_stream_destroy(imquic_moq_pending_stream *stream) {
	if(stream != NULL) {
		imquic_buffer_destroy(stream->buffer);
		g_free(stream);
	}
}
static GHashTable *moq_pending_streams = NULL;

/* MoQ's flavour of varint (introduced in v17) */
static uint64_t imquic_read_moqint(imquic_moq_version version, uint8_t *bytes, size_t blen, uint8_t *length);
static uint8_t imquic_write_moqint(imquic_moq_version version, uint64_t number, uint8_t *bytes, size_t blen);

/* Helpers to check and generate GREASE values */
#define IMQUIC_MOQ_GREASE_BASE	0x7f
#define IMQUIC_MOQ_GREASE_SUM	0x9D
static gboolean imquic_moq_is_grease(uint64_t value);
static uint64_t imquic_moq_random_grease(void);

/* Initialization */
static void imquic_moq_context_destroy(imquic_moq_context *moq);
static void imquic_moq_context_free(const imquic_refcount *moq_ref);
void imquic_moq_init(void) {
	moq_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_moq_context_destroy);
	moq_pending_streams = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)g_hash_table_unref);
}

void imquic_moq_deinit(void) {
	imquic_mutex_lock(&moq_mutex);
	if(moq_sessions != NULL)
		g_hash_table_unref(moq_sessions);
	moq_sessions = NULL;
	if(moq_pending_streams != NULL)
		g_hash_table_unref(moq_pending_streams);
	moq_pending_streams = NULL;
	imquic_mutex_unlock(&moq_mutex);
}

/* Helper to dynamically return the MoQ version associated with the negotiated ALPN */
static imquic_moq_version imquic_moq_version_from_alpn(const char *alpn, imquic_moq_version fallback) {
	if(alpn == NULL)
		return fallback;
	if(!strcasecmp(alpn, "moq-17"))
		return IMQUIC_MOQ_VERSION_17;
	else if(!strcasecmp(alpn, "moq-16"))
		return IMQUIC_MOQ_VERSION_16;
	/* If we got here, there was no specific ALPN negotiation */
	return fallback;
}

/* Helper to check if a request ID is valid or not */
static gboolean moq_is_request_id_valid(imquic_moq_context *moq, uint64_t request_id, gboolean outgoing) {
	if(outgoing) {
		/* Check if the request ID we're trying to send is valid */
		if((moq->is_server && request_id % 2 == 0) || (!moq->is_server && request_id % 2 != 0)) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request IDs must be %s when sent by a %s\n",
				imquic_get_connection_name(moq->conn),
				moq->is_server ? "odd" : "even", moq->is_server ? "server" : "client");
			return FALSE;
		}
		/* We only need stricter checks on older versions */
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			return TRUE;
		if(request_id < moq->next_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), request_id, moq->next_request_id);
			return FALSE;
		}
		if(request_id >= moq->max_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Reached the Maximum Request ID (%"SCNu64")\n",
				imquic_get_connection_name(moq->conn), moq->max_request_id);
			return FALSE;
		}
	} else {
		/* Check if the request ID we just received is valid */
		if((moq->is_server && request_id % 2 != 0) || (!moq->is_server && request_id % 2 == 0)) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request IDs must be %s when sent by a %s\n",
				imquic_get_connection_name(moq->conn),
				!moq->is_server ? "odd" : "even", !moq->is_server ? "server" : "client");
			return FALSE;
		}
		/* We only need stricter checks on older versions */
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			return TRUE;
		if(request_id != moq->expected_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID not the one next we expected (%"SCNu64" != %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), request_id, moq->expected_request_id);
			return FALSE;
		}
		if(request_id >= moq->local_max_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Peer reached the Maximum Request ID (%"SCNu64")\n",
				imquic_get_connection_name(moq->conn), moq->local_max_request_id);
			return FALSE;
		}
	}
	/* If we got here, it's all good */
	return TRUE;
}

/* Helpers to manage pending streams */
static void imquic_moq_track_pending_stream(imquic_connection *conn, uint64_t stream_id, uint8_t *bytes, size_t length, gboolean complete) {
	imquic_mutex_lock(&moq_mutex);
	GHashTable *streams = g_hash_table_lookup(moq_pending_streams, conn);
	if(streams == NULL) {
		/* No map for this connection yet, create it now */
		streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_pending_stream_destroy);
		g_hash_table_insert(moq_pending_streams, conn, streams);
	}
	/* Keep track of the stream data */
	imquic_moq_pending_stream *stream = g_hash_table_lookup(streams, &stream_id);
	if(stream == NULL) {
		stream = g_malloc0(sizeof(imquic_moq_pending_stream));
		stream->stream_id = stream_id;
		stream->buffer = imquic_buffer_create(NULL, 0);
		g_hash_table_insert(streams, imquic_uint64_dup(stream_id), stream);
	}
	imquic_buffer_append(stream->buffer, bytes, length);
	stream->complete = complete;
	imquic_mutex_unlock(&moq_mutex);
}

static void imquic_moq_handle_pending_streams(imquic_connection *conn) {
	GHashTable *streams = NULL;
	imquic_mutex_lock(&moq_mutex);
	g_hash_table_steal_extended(moq_pending_streams, conn,
		NULL, (gpointer *)&streams);
	imquic_mutex_unlock(&moq_mutex);
	/* Iterate on the streams list and cleanup */
	if(streams != NULL) {
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, streams);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			imquic_moq_pending_stream *stream = value;
			imquic_moq_stream_incoming(conn, stream->stream_id,
				stream->buffer->bytes, stream->buffer->length, stream->complete);
		}
		g_hash_table_unref(streams);
	}
}

/* Callbacks */
void imquic_moq_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_refcount_increase(&conn->ref);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s][MoQ] New connection %p\n", imquic_get_connection_name(conn), conn);
	imquic_moq_context *moq = g_malloc0(sizeof(imquic_moq_context));
	moq->conn = conn;
	moq->is_server = conn->is_server;
	moq->next_request_id = moq->is_server ? 1 : 0;
	moq->expected_request_id = moq->is_server ? 0 : 1;
	const char *alpn = imquic_is_connection_webtransport(conn) ?
		imquic_get_connection_wt_protocol(conn) : imquic_get_connection_alpn(conn);
	moq->version = imquic_moq_version_from_alpn(alpn, conn->socket->moq_version);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s][MoQ] MoQ version: %s (%s)\n", imquic_get_connection_name(conn),
		imquic_moq_version_str(moq->version), alpn);
	moq->streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	moq->streams_by_reqid = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_subscription_destroy);
	moq->requests = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->update_requests = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)g_free);
	moq->buffer = imquic_buffer_create(NULL, 0);
	imquic_mutex_init(&moq->mutex);
	imquic_refcount_init(&moq->ref, imquic_moq_context_free);
	imquic_mutex_lock(&moq_mutex);
	g_hash_table_insert(moq_sessions, conn, moq);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		g_hash_table_remove(moq_pending_streams, conn);
	imquic_mutex_unlock(&moq_mutex);
	/* Let's check if we need to create a control stream */
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		/* For older versions, we only open a bidirectional STREAM ourselves
		 * if we're a client, as we'll need to send a CLIENT_SETUP */
		if(!moq->is_server) {
			uint64_t stream_id = 0;
			imquic_connection_new_stream_id(conn, TRUE, &stream_id);
			moq->control_stream_id = stream_id;
			moq->has_control_stream = TRUE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq->control_stream_id, "control");
#endif
		}
	} else {
		/* For newer versions, the role doesn't matter, as we always create
		 * a unidirectional STREAM to send a SETUP message right away */
		uint64_t stream_id = 0;
		imquic_connection_new_stream_id(conn, FALSE, &stream_id);
		moq->control_stream_id = stream_id;
		moq->sent_setup = TRUE;
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->moq)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq->control_stream_id, "control");
#endif
	}
	/* Notify the application: we may get some info back to use next */
	if(conn->socket && conn->socket->callbacks.moq.new_connection)
		conn->socket->callbacks.moq.new_connection(conn, user_data);
	/* After the function returns, check if we can do something */
	if(moq->version <= IMQUIC_MOQ_VERSION_16 && !moq->is_server) {
		/* Legacy version, generate a CLIENT_SETUP */
		imquic_moq_setup_options parameters = { 0 };
		if(moq->local_max_request_id > 0) {
			parameters.max_request_id_set = TRUE;
			parameters.max_request_id = moq->local_max_request_id;
		}
		if(moq->local_max_auth_token_cache_size > 0) {
			parameters.max_auth_token_cache_size_set = TRUE;
			parameters.max_auth_token_cache_size = moq->local_max_auth_token_cache_size;
		}
		if(moq->auth != NULL && moq->authlen > 0) {
			parameters.auth_token_set = TRUE;
			if(moq->authlen > sizeof(parameters.auth_token)) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
					imquic_get_connection_name(moq->conn), moq->authlen, sizeof(parameters.auth_token));
				moq->authlen = sizeof(parameters.auth_token);
			}
			memcpy(parameters.auth_token, moq->auth, moq->authlen);
			parameters.auth_token_len = moq->authlen;
		}
		/* Add the implementation */
		parameters.moqt_implementation_set = TRUE;
		g_snprintf(parameters.moqt_implementation, sizeof(parameters.moqt_implementation), "imquic %s", imquic_version_string_full);
		/* TODO For raw quic connections, we should expose ways to
		 * fill in and use the PATH and ATTRIBUTE parameters as well */
		uint8_t buffer[200];
		size_t blen = sizeof(buffer);
		size_t cs_len = imquic_moq_add_client_setup(moq, buffer, blen, &parameters);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			buffer, cs_len, FALSE);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		/* New version, generate a SETUP no matter the role */
		imquic_moq_setup_options parameters = { 0 };
		if(moq->local_max_auth_token_cache_size > 0) {
			parameters.max_auth_token_cache_size_set = TRUE;
			parameters.max_auth_token_cache_size = moq->local_max_auth_token_cache_size;
		}
		if(moq->auth != NULL && moq->authlen > 0) {
			parameters.auth_token_set = TRUE;
			if(moq->authlen > sizeof(parameters.auth_token)) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
					imquic_get_connection_name(moq->conn), moq->authlen, sizeof(parameters.auth_token));
				moq->authlen = sizeof(parameters.auth_token);
			}
			memcpy(parameters.auth_token, moq->auth, moq->authlen);
			parameters.auth_token_len = moq->authlen;
		}
		/* Add the implementation */
		parameters.moqt_implementation_set = TRUE;
		g_snprintf(parameters.moqt_implementation, sizeof(parameters.moqt_implementation), "imquic %s", imquic_version_string_full);
		/* TODO For raw quic connections, we should expose ways to
		 * fill in and use the PATH and ATTRIBUTE parameters as well */
		uint8_t buffer[200];
		size_t blen = sizeof(buffer);
		size_t cs_len = imquic_moq_add_setup(moq, buffer, blen, &parameters);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			buffer, cs_len, FALSE);
	}
	/* Check if there are streams we kept on hold because we didn't have a context */
	imquic_moq_handle_pending_streams(conn);
}

void imquic_moq_stream_incoming(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t length, gboolean complete) {
	/* Got incoming data via STREAM */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] [STREAM-%"SCNu64"] Got data: %"SCNu64" bytes (%s)\n",
		imquic_get_connection_name(conn),
		stream_id, length, (complete ? "complete" : "not complete"));
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(moq == NULL) {
		/* FIXME For newer versions, we may get bidirectional stream data
		 * from requests before we get the SETUP on the unidirectional
		 * control stream, which means we need to buffer data for later */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][MoQ] Buffering incoming STREAM data on unknown context\n",
			imquic_get_connection_name(conn));
		imquic_moq_track_pending_stream(conn, stream_id, bytes, length, complete);
		return;
	}
	if(!moq->has_control_stream) {
		uint64_t actual_id = 0;
		gboolean client_initiated = FALSE, bidirectional = FALSE;
		imquic_parse_stream_id(stream_id, &actual_id, &client_initiated, &bidirectional);
		/* FIXME Depending on the version, we'll be waiting for the remote
		 * control stream on either a bidirectional or unidirectional stream */
		if(moq->version <= IMQUIC_MOQ_VERSION_16 && !bidirectional) {
			/* Legacy version, we need a bidirectional control stream as a first thing */
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Not a bidirectional MoQ control stream\n",
				imquic_get_connection_name(conn));
			return;
		} else if(moq->version >= IMQUIC_MOQ_VERSION_17 && bidirectional) {
			/* New version, the remote control stream will be unidirectional,
			 * but we may get some bidirectional streams for requests too
			 * in the meanwhile: if that happens, queue that data, and we
			 * will handle it later, once the control stream has been setup */
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][MoQ] Not a unidirectional MoQ control stream, buffering stream %"SCNu64" data\n",
				imquic_get_connection_name(conn), stream_id);
			imquic_moq_track_pending_stream(conn, stream_id, bytes, length, complete);
			return;
		}
		moq->has_control_stream = TRUE;
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			moq->control_stream_id = stream_id;
		else
			moq->remote_control_stream_id = stream_id;
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->moq)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, stream_id, "control");
#endif
	}
	imquic_moq_parse_message(moq, stream_id, bytes, length, complete, FALSE);
	/* After we've handled this stream, check if there is pending stream
	 * data we should process now: this can happen in newer MoQ versions
	 * if we received data from a bidirectional stream (e.g., a request)
	 * before we received the SETUP on the unidirectional control stream */
	if(g_atomic_int_compare_and_exchange(&moq->check_pending, 1, 0)) {
		/* We do, check if there are streams to process */
		imquic_moq_handle_pending_streams(conn);
	}
}

void imquic_moq_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	/* Got incoming data via DATAGRAM */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%p] [DATAGRAM] Got data: %"SCNu64"\n",
		imquic_get_connection_name(conn), conn, length);
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(moq == NULL)
		return;
	imquic_moq_parse_message(moq, 0, bytes, length, FALSE, TRUE);
}

static void imquic_moq_request_stream_closed(imquic_moq_context *moq, imquic_moq_stream *moq_stream) {
	if(moq == NULL || moq_stream == NULL || moq_stream->request_type == 0)
		return;
	imquic_moq_message_type request_type = moq_stream->request_type;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][MoQ]   -- Getting rid of %s '%"SCNu64"'\n",
		imquic_get_connection_name(moq->conn),
		imquic_moq_message_type_str(request_type, IMQUIC_MOQ_VERSION_17),
		moq_stream->request_id);
	gboolean request_sender = moq_stream->request_sender;
	uint64_t request_id = moq_stream->request_id;
	gboolean notify = !request_sender;
	g_hash_table_remove(moq->streams_by_reqid, &moq_stream->request_id);
	g_hash_table_remove(moq->streams, &moq_stream->stream_id);	/* */
	imquic_mutex_unlock(&moq->mutex);
	/* FIXME Trigger the application callbacks, if needed */
	if(request_type == IMQUIC_MOQ_PUBLISH_NAMESPACE) {
		if(notify && moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_done)
			moq->conn->socket->callbacks.moq.publish_namespace_done(moq->conn, request_id);
	} else if(request_type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE) {
		if(notify && moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe_namespace)
			moq->conn->socket->callbacks.moq.incoming_unsubscribe_namespace(moq->conn, request_id);
	} else if(request_type == IMQUIC_MOQ_PUBLISH) {
		/* FIXME */
		if(notify && moq->conn->socket && moq->conn->socket->callbacks.moq.publish_done)
			moq->conn->socket->callbacks.moq.publish_done(moq->conn, request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, 0, "Stream closed");
	} else if(request_type == IMQUIC_MOQ_SUBSCRIBE) {
		if(notify && moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe)
			moq->conn->socket->callbacks.moq.incoming_unsubscribe(moq->conn, request_id);
	} else if(request_type == IMQUIC_MOQ_FETCH) {
		if(notify && moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_fetch_cancel)
			moq->conn->socket->callbacks.moq.incoming_fetch_cancel(moq->conn, request_id);
	}
}

void imquic_moq_reset_stream_incoming(imquic_connection *conn, uint64_t stream_id, uint64_t error_code) {
	/* We got a RESET_STREAM */
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(moq == NULL)
		return;
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams, &stream_id);
	if(moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Got RESET_STREAM for unknown STREAM %"SCNu64": %"SCNu64" (%s)\n",
			imquic_get_connection_name(conn), stream_id, error_code, imquic_moq_reset_stream_code_str(error_code));
		imquic_mutex_unlock(&moq->mutex);
		return;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][MoQ] Got RESET_STREAM for STREAM %"SCNu64": %"SCNu64" (%s)\n",
		imquic_get_connection_name(conn), stream_id, error_code, imquic_moq_reset_stream_code_str(error_code));
	if(moq_stream->request_type == 0) {
		/* FIXME Not a request stream, we ignore it for now */
		imquic_mutex_unlock(&moq->mutex);
		return;
	}
	/* If we got here, a request bidirectional STREAM was closed */
	imquic_moq_request_stream_closed(moq, moq_stream);
}

void imquic_moq_stop_sending_incoming(imquic_connection *conn, uint64_t stream_id, uint64_t error_code) {
	/* We got a STOP_SENDING */
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(moq == NULL)
		return;
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams, &stream_id);
	if(moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Got STOP_SENDING for unknown STREAM %"SCNu64": %"SCNu64" (%s)\n",
			imquic_get_connection_name(conn), stream_id, error_code, imquic_moq_reset_stream_code_str(error_code));
		imquic_mutex_unlock(&moq->mutex);
		return;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s][MoQ] Got STOP_SENDING for STREAM %"SCNu64": %"SCNu64" (%s)\n",
		imquic_get_connection_name(conn), stream_id, error_code, imquic_moq_reset_stream_code_str(error_code));
	imquic_mutex_unlock(&moq->mutex);
	if(moq_stream->request_type == 0) {
		/* FIXME Not a request stream, we ignore it for now */
		imquic_mutex_unlock(&moq->mutex);
		return;
	}
	/* If we got here, a request bidirectional STREAM was closed */
	imquic_moq_request_stream_closed(moq, moq_stream);
}

void imquic_moq_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	imquic_mutex_lock(&moq_mutex);
	gboolean removed = g_hash_table_remove(moq_sessions, conn);
	g_hash_table_remove(moq_pending_streams, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(conn->socket && conn->socket->callbacks.moq.connection_gone)
		conn->socket->callbacks.moq.connection_gone(conn);
	if(removed) {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s][MoQ] Connection gone\n",
			imquic_get_connection_name(conn));
		imquic_refcount_decrease(&conn->ref);
	}
}

/* Cleanup */
static void imquic_moq_context_destroy(imquic_moq_context *moq) {
	if(moq && g_atomic_int_compare_and_exchange(&moq->destroyed, 0, 1))
		imquic_refcount_decrease(&moq->ref);
}

static void imquic_moq_context_free(const imquic_refcount *moq_ref) {
	imquic_moq_context *moq = imquic_refcount_containerof(moq_ref, imquic_moq_context, ref);
	g_free(moq->peer_implementation);
	g_list_free(moq->supported_versions);
	if(moq->streams)
		g_hash_table_unref(moq->streams);
	if(moq->subscriptions)
		g_hash_table_unref(moq->subscriptions);
	if(moq->subscriptions_by_id)
		g_hash_table_unref(moq->subscriptions_by_id);
	if(moq->streams_by_reqid)
		g_hash_table_unref(moq->streams_by_reqid);
	if(moq->requests)
		g_hash_table_unref(moq->requests);
	if(moq->update_requests)
		g_hash_table_unref(moq->update_requests);
	imquic_buffer_destroy(moq->buffer);
	g_free(moq);
}

static void imquic_moq_property_free(imquic_moq_property *property) {
	if(property != NULL) {
		if(property->value.data.buffer != NULL)
			g_free(property->value.data.buffer);
		g_free(property);
	}
}

/* MoQ stringifiers */
const char *imquic_moq_error_code_str(imquic_moq_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_NO_ERROR:
			return "No Error";
		case IMQUIC_MOQ_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_PROTOCOL_VIOLATION:
			return "Protocol Violation";
		case IMQUIC_MOQ_INVALID_REQUEST_ID:
			return "Invalid Request ID";
		case IMQUIC_MOQ_DUPLICATE_TRACK_ALIAS:
			return "Duplicate Track Alias";
		case IMQUIC_MOQ_KEYVALUE_FORMATTING_ERROR:
			return "Key-Value Formatting Error";
		case IMQUIC_MOQ_INVALID_REQUIRED_REQUEST_ID:
			return "Invalid Required Request ID";
		case IMQUIC_MOQ_INVALID_PATH:
			return "Invalid Path";
		case IMQUIC_MOQ_MALFORMED_PATH:
			return "Malformed Path";
		case IMQUIC_MOQ_GOAWAY_TIMEOUT:
			return "GOAWAY Timeout";
		case IMQUIC_MOQ_CONTROL_MESSAGE_TIMEOUT:
			return "Control Message Timeout";
		case IMQUIC_MOQ_DATA_STREAM_TIMEOUT:
			return "Data Stream Timeout";
		case IMQUIC_MOQ_AUTH_TOKEN_CACHE_OVERFLOW:
			return "Auth Token Cache Overflow";
		case IMQUIC_MOQ_DUPLICATE_AUTH_TOKEN_ALIAS:
			return "Duplicate Auth Token Alias";
		case IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED:
			return "Version Negotiation Failed";
		case IMQUIC_MOQ_MALFORMED_AUTH_TOKEN:
			return "Malformed Auth Token";
		case IMQUIC_MOQ_UNKNOWN_AUTH_TOKEN_ALIAS:
			return "Unknown Auth Token Alias";
		case IMQUIC_MOQ_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		case IMQUIC_MOQ_INVALID_AUTHORITY:
			return "Invalid Authority";
		case IMQUIC_MOQ_MALFORMED_AUTHORITY:
			return "Malformed Authority";
		case IMQUIC_MOQ_UNKNOWN_ERROR:
			return "Unknown Error";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_request_error_code_str(imquic_moq_request_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_REQERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_REQERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_REQERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_REQERR_NOT_SUPPORTED:
			return "Not Suppoered";
		case IMQUIC_MOQ_REQERR_MALFORMED_AUTH_TOKEN:
			return "Malformed Auth Token";
		case IMQUIC_MOQ_REQERR_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		case IMQUIC_MOQ_REQERR_GOING_AWAY:
			return "Going Away";
		case IMQUIC_MOQ_REQERR_EXCESSIVE_LOAD:
			return "Excessive Load";
		case IMQUIC_MOQ_REQERR_DOES_NOT_EXIST:
			return "Does Not Exist";
		case IMQUIC_MOQ_REQERR_INVALID_RANGE:
			return "Invalid Range";
		case IMQUIC_MOQ_REQERR_MALFORMED_TRACK:
			return "Malformed Track";
		case IMQUIC_MOQ_REQERR_DUPLICATE_SUBSCRIPTION:
			return "Duplicate Subscription";
		case IMQUIC_MOQ_REQERR_UNINTERESTED:
			return "Uninterested";
		case IMQUIC_MOQ_REQERR_PREFIX_OVERLAP:
			return "Prefix Overlap";
		case IMQUIC_MOQ_REQERR_NAMESPACE_TOO_LARGE:
			return "Namespace Too Large";
		case IMQUIC_MOQ_REQERR_INVALID_JOINING_REQUEST_ID:
			return "Invalid Joining Request ID";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_pub_done_code_str(imquic_moq_pub_done_code code) {
	switch(code) {
		case IMQUIC_MOQ_PUBDONE_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_PUBDONE_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_PUBDONE_TRACK_ENDED:
			return "Track Ended";
		case IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED:
			return "Subscription Ended";
		case IMQUIC_MOQ_PUBDONE_GOING_AWAY:
			return "Going Away";
		case IMQUIC_MOQ_PUBDONE_EXPIRED:
			return "Expired";
		case IMQUIC_MOQ_PUBDONE_TOO_FAR_BEHIND:
			return "Too Far Behind";
		case IMQUIC_MOQ_PUBDONE_UPDATE_FAILED:
			return "Update Failed";
		case IMQUIC_MOQ_PUBDONE_EXCESSIVE_LOAD:
			return "Excessive Load";
		case IMQUIC_MOQ_PUBDONE_MALFORMED_TRACK:
			return "Malformed Track";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_reset_stream_code_str(imquic_moq_reset_stream_code code) {
	switch(code) {
		case IMQUIC_MOQ_RESET_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_RESET_CANCELLED:
			return "Cancelled";
		case IMQUIC_MOQ_RESET_DELIVERY_TIMEOUT:
			return "Delivery Timeout";
		case IMQUIC_MOQ_RESET_SESSION_CLOSED:
			return "Session Closed";
		case IMQUIC_MOQ_RESET_UNKNOWN_OBJECT_STATUS:
			return "Unknown Object Status";
		case IMQUIC_MOQ_RESET_TOO_FAR_BEHIND:
			return "Too Far Behind";
		case IMQUIC_MOQ_RESET_EXCESSIVE_LOAD:
			return "Excessive Load";
		case IMQUIC_MOQ_RESET_MALFORMED_TRACK:
			return "Malformed Track";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_message_type_str(imquic_moq_message_type type, imquic_moq_version version) {
	switch(type) {
		case IMQUIC_MOQ_REQUEST_OK:
			return "REQUEST_OK";
		case IMQUIC_MOQ_REQUEST_ERROR:
			return "REQUEST_ERROR";
		case IMQUIC_MOQ_SUBSCRIBE:
			return "SUBSCRIBE";
		case IMQUIC_MOQ_SUBSCRIBE_OK:
			return "SUBSCRIBE_OK";
		case IMQUIC_MOQ_REQUEST_UPDATE:
			return "REQUEST_UPDATE";
		case IMQUIC_MOQ_PUBLISH_NAMESPACE:
			return "PUBLISH_NAMESPACE";
		case IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE:
			return "PUBLISH_NAMESPACE_DONE";
		case IMQUIC_MOQ_UNSUBSCRIBE:
			return "UNSUBSCRIBE";
		case IMQUIC_MOQ_PUBLISH_DONE:
			return "PUBLISH_DONE";
		case IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL:
			return "PUBLISH_NAMESPACE_CANCEL";
		case IMQUIC_MOQ_TRACK_STATUS:
			return "TRACK_STATUS";
		case IMQUIC_MOQ_GOAWAY:
			return "GOAWAY";
		case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE:
			return "SUBSCRIBE_NAMESPACE";
		case IMQUIC_MOQ_NAMESPACE:
			return "NAMESPACE";
		case IMQUIC_MOQ_NAMESPACE_DONE:
			return "NAMESPACE_DONE";
		case IMQUIC_MOQ_PUBLISH_BLOCKED:
			return "PUBLISH_BLOCKED";
		case IMQUIC_MOQ_MAX_REQUEST_ID:
			return "MAX_REQUEST_ID";
		case IMQUIC_MOQ_REQUESTS_BLOCKED:
			return "REQUESTS_BLOCKED";
		case IMQUIC_MOQ_FETCH:
			return "FETCH";
		case IMQUIC_MOQ_FETCH_CANCEL:
			return "FETCH_CANCEL";
		case IMQUIC_MOQ_FETCH_OK:
			return "FETCH_OK";
		case IMQUIC_MOQ_CLIENT_SETUP:
			return "CLIENT_SETUP";
		case IMQUIC_MOQ_SERVER_SETUP:
			return "SERVER_SETUP";
		case IMQUIC_MOQ_SETUP:
			return "SETUP";
		case IMQUIC_MOQ_PUBLISH:
			return "PUBLISH";
		case IMQUIC_MOQ_PUBLISH_OK:
			return "PUBLISH_OK";
		default: break;
	}
	return NULL;
}

const char *imquic_media_stream_request_state_str(imquic_media_stream_request_state state) {
	switch(state) {
		case IMQUIC_MOQ_REQUEST_STATE_NEW:
			return "New";
		case IMQUIC_MOQ_REQUEST_STATE_SENT:
			return "Sent";
		case IMQUIC_MOQ_REQUEST_STATE_OK:
			return "OK";
		case IMQUIC_MOQ_REQUEST_STATE_ERROR:
			return "Error";
		case IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT:
			return "Update Sent";
		case IMQUIC_MOQ_REQUEST_STATE_DONE:
			return "Done";
		default: break;
	}
	return NULL;
}

gboolean imquic_moq_is_datagram_message_type_valid(imquic_moq_version version, uint8_t type) {
	return (type <= 0x0F || (type >= 0x20 && type <= 0x2D));
}

uint8_t imquic_moq_datagram_message_type_return(imquic_moq_version version,
		gboolean payload, gboolean prop, gboolean eog, gboolean oid, gboolean priority) {
	uint8_t type = payload ? 0x00 : 0x20;
	if(!payload)
		eog = FALSE;
	if(eog)
		type |= 0x02;
	if(prop)
		type |= 0x01;
	if(!oid)
		type |= 0x04;
	if(!priority)
		type |= 0x08;
	return type;
}

void imquic_moq_datagram_message_type_parse(imquic_moq_version version, uint8_t type,
		gboolean *payload, gboolean *prop, gboolean *eog, gboolean *oid, gboolean *priority, gboolean *violation) {
	if(oid)
		*oid = TRUE;
	if(priority)
		*priority = TRUE;
	/* v15 and later */
	if(payload)
		*payload = !(type & 0x20);
	if(prop)
		*prop = (type & 0x01);
	if(eog)
		*eog = (type & 0x02);
	if(oid)
		*oid = !(type & 0x04);
	if(priority)
		*priority = !(type & 0x08);
	if(violation)
		*violation = ((type > 0x0F && type < 0x20) || type > 0x2D || (type >= 0x20 && (type & 0x02)));
}

const char *imquic_moq_datagram_message_type_str(uint8_t type, imquic_moq_version version) {
	if(type <= 0x0F)
		return "OBJECT_DATAGRAM";
	else if(type >= 0x20 && type <= 0x2D)
		return "OBJECT_DATAGRAM_STATUS";
	return NULL;
}

gboolean imquic_moq_is_data_message_type_valid(imquic_moq_version version, uint8_t type) {
	if(type == IMQUIC_MOQ_FETCH_HEADER)
		return TRUE;
	if((type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) ||
			(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX))
		return TRUE;
	return FALSE;
}

uint8_t imquic_moq_data_message_type_from_subgroup_header(imquic_moq_version version,
		gboolean subgroup, gboolean sgid0, gboolean prop, gboolean eog, gboolean priority) {
	uint8_t type = 0;
	if(subgroup) {
		sgid0 = FALSE;
		type |= 0x04;
	}
	if(sgid0)
		type |= 0x02;
	if(prop)
		type |= 0x01;
	if(eog)
		type |= 0x08;
	type |= (priority ? 0x10 : 0x30);
	return type;
}

void imquic_moq_data_message_type_to_subgroup_header(imquic_moq_version version, uint8_t type,
		gboolean *subgroup, gboolean *sgid0, gboolean *prop, gboolean *eog, gboolean *priority, gboolean *violation) {
	uint8_t base = 0x10;
	if(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) {
		base = 0x10;
	} else if(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX) {
		base = 0x30;
	}
	uint8_t bitmask = type - base;
	if(bitmask == 0x06 || bitmask == 0x07) {
		/* If these bits are set, it's a protocol violation */
		if(violation)
			*violation = TRUE;
		return;
	}
	if(priority)
		*priority = (base == 0x10);
	if(subgroup)
		*subgroup = (bitmask & 0x04);
	if(sgid0)
		*sgid0 = (bitmask & 0x02);
	if(prop)
		*prop = (bitmask & 0x01);
	if(eog)
		*eog = (bitmask & 0x08);
}

const char *imquic_moq_data_message_type_str(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(type == IMQUIC_MOQ_FETCH_HEADER)
		return "FETCH_HEADER";
	else if(imquic_moq_is_data_message_type_valid(version, type))
		return "SUBGROUP_HEADER";
	return NULL;
}

imquic_moq_delivery imquic_moq_data_message_type_to_delivery(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(type == IMQUIC_MOQ_FETCH_HEADER)
		return IMQUIC_MOQ_USE_FETCH;
	else if((type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) ||
			(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX))
		return IMQUIC_MOQ_USE_SUBGROUP;
	return -1;
}

gboolean imquic_moq_is_fetch_serialization_flags_valid(imquic_moq_version version, uint64_t flags) {
	if(flags > 128 && flags != (uint64_t)0x8C && flags != (uint64_t)0x10C)
		return FALSE;
	return TRUE;
}

uint64_t imquic_moq_generate_fetch_serialization_flags(imquic_moq_version version,
		imquic_moq_fetch_subgroup_type subgroup, gboolean oid, gboolean group, gboolean priority, gboolean prop,
		gboolean datagram, gboolean end_ne_range, gboolean end_uk_range) {
	if(end_ne_range) {
		/* Ignore everything else */
		return (uint64_t)0x8C;
	} else if(end_uk_range) {
		/* Ignore everything else */
		return (uint64_t)0x10C;
	}
	/* If we're here, we're writing a bitmask of a single byte */
	uint8_t flags = subgroup;
	if(oid)
		flags |= 0x04;
	if(group)
		flags |= 0x08;
	if(priority)
		flags |= 0x10;
	if(prop)
		flags |= 0x20;
	if(datagram)
		flags |= 0x40;
	return (uint64_t)flags;
}

void imquic_moq_parse_fetch_serialization_flags(imquic_moq_version version, uint64_t flags,
		imquic_moq_fetch_subgroup_type *subgroup, gboolean *oid, gboolean *group, gboolean *priority, gboolean *prop,
		gboolean *datagram, gboolean *end_ne_range, gboolean *end_uk_range, gboolean *violation) {
	/* Make sure the provided flags are valid, or return a protocol violation */
	if(!imquic_moq_is_fetch_serialization_flags_valid(version, flags)) {
		if(*violation)
			*violation = TRUE;
		return;
	}
	if(flags == (uint64_t)0x8C || flags == (uint64_t)0x10C) {
		if(end_ne_range)
			*end_ne_range = (flags == (uint64_t)0x8C);
		if(end_uk_range)
			*end_uk_range = (flags == (uint64_t)0x10C);
		return;
	}
	/* If we're here, we're parsing a bitmask of a single byte */
	uint8_t flags8 = (uint8_t)flags;
	uint8_t lsb = flags8 & 0x03;
	if(*subgroup) {
		if(lsb == 0x00)
			*subgroup = IMQUIC_MOQ_FETCH_SUBGROUP_ZERO;
		if(lsb == 0x01)
			*subgroup = IMQUIC_MOQ_FETCH_SUBGROUP_PREVIOUS;
		if(lsb == 0x02)
			*subgroup = IMQUIC_MOQ_FETCH_SUBGROUP_PLUS_ONE;
		else
			*subgroup = IMQUIC_MOQ_FETCH_SUBGROUP_ID;
	}
	if(oid)
		*oid = (flags8 & 0x04);
	if(group)
		*group = (flags8 & 0x08);
	if(priority)
		*priority = (flags8 & 0x10);
	if(prop)
		*prop = (flags8 & 0x20);
	if(datagram)
		*datagram = (flags8 & 0x40);
}


const char *imquic_moq_setup_option_type_str(imquic_moq_setup_option_type type) {
	switch(type) {
		case IMQUIC_MOQ_SETUP_OPTION_PATH:
			return "PATH";
		case IMQUIC_MOQ_SETUP_OPTION_MAX_REQUEST_ID:
			return "MAX_REQUEST_ID";
		case IMQUIC_MOQ_SETUP_OPTION_AUTHORIZATION_TOKEN:
			return "AUTHORIZATION_TOKEN";
		case IMQUIC_MOQ_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE:
			return "MAX_AUTH_TOKEN_CACHE_SIZE";
		case IMQUIC_MOQ_SETUP_OPTION_AUTHORITY:
			return "AUTHORITY";
		case IMQUIC_MOQ_SETUP_OPTION_MOQT_IMPLEMENTATION:
			return "MOQT_IMPLEMENTATION";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_request_parameter_type_str(imquic_moq_request_parameter_type type, imquic_moq_version version) {
	switch(type) {
		case IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT:
			return "DELIVERY_TIMEOUT";
		case IMQUIC_MOQ_REQUEST_PARAM_RENDEZVOUS_TIMEOUT:
			return "RENDEZVOUS_TIMEOUT";
		case IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN:
			return "AUTHORIZATION_TOKEN";
		case IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY:
			return "SUBSCRIBER_PRIORITY";
		case IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER:
			return "GROUP_ORDER";
		case IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER:
			return "SUBSCRIPTION_FILTER";
		case IMQUIC_MOQ_REQUEST_PARAM_EXPIRES:
			return "EXPIRES";
		case IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT:
			return "LARGEST_OBJECT";
		case IMQUIC_MOQ_REQUEST_PARAM_FORWARD:
			return "FORWARD";
		case IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST:
			return "NEW_GROUP_REQUEST";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_filter_type_str(imquic_moq_filter_type type) {
	switch(type) {
		case IMQUIC_MOQ_FILTER_NEXT_GROUP_START:
			return "Next Group Start";
		case IMQUIC_MOQ_FILTER_LARGEST_OBJECT:
			return "Largest Object";
		case IMQUIC_MOQ_FILTER_ABSOLUTE_START:
			return "AbsoluteStart";
		case IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE:
			return "AbsoluteRange";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_group_order_str(imquic_moq_group_order type) {
	switch(type) {
		case IMQUIC_MOQ_ORDERING_ORIGINAL:
			return "Original";
		case IMQUIC_MOQ_ORDERING_ASCENDING:
			return "Ascending";
		case IMQUIC_MOQ_ORDERING_DESCENDING:
			return "Descending";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_subscribe_namespace_options_str(imquic_moq_subscribe_namespace_options type) {
	switch(type) {
		case IMQUIC_MOQ_WANT_PUBLISH:
			return "PUBLISH";
		case IMQUIC_MOQ_WANT_NAMESPACE:
			return "NAMESPACE";
		case IMQUIC_MOQ_WANT_PUBLISH_AND_NAMESPACE:
			return "PUBLISH and NAMESPACE";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_fetch_type_str(imquic_moq_fetch_type type) {
	switch(type) {
		case IMQUIC_MOQ_FETCH_STANDALONE:
			return "Standalone Fetch";
		case IMQUIC_MOQ_FETCH_JOINING_RELATIVE:
			return "Relative Joining Fetch";
		case IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE:
			return "Absolute Joining Fetch";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_auth_token_alias_type_str(imquic_moq_auth_token_alias_type type) {
	switch(type) {
		case IMQUIC_MOQ_AUTH_TOKEN_DELETE:
			return "DELETE";
		case IMQUIC_MOQ_AUTH_TOKEN_REGISTER:
			return "REGISTER";
		case IMQUIC_MOQ_AUTH_TOKEN_USE_ALIAS:
			return "USE_ALIAS";
		case IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE:
			return "USE_VALUE";
		default: break;
	}
	return NULL;
}

/* MoQ options and parameters */
static int imquic_moq_compare_types(const void *a, const void *b) {
	return GPOINTER_TO_INT(a) - GPOINTER_TO_INT(b);
}
size_t imquic_moq_setup_options_serialize(imquic_moq_context *moq,
		imquic_moq_setup_options *options,
		uint8_t *bytes, size_t blen, uint8_t *params_num) {
	*params_num = 0;
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	if(options == NULL) {
		/* No options */
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			offset += imquic_write_moqint(moq->version, 0, &bytes[offset], blen-offset);
	} else {
		uint64_t new_id = 0, last_id = 0;
		GList *list = NULL;
		if(options->path_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_PATH));
		if(options->max_request_id_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_MAX_REQUEST_ID));
		if(options->max_auth_token_cache_size_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE));
		if(options->auth_token_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_AUTHORIZATION_TOKEN));
		if(options->authority_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_AUTHORITY));
		if(options->moqt_implementation_set)
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_SETUP_OPTION_MOQT_IMPLEMENTATION));
		/* For newer versions, we always add a GREASE option */
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			list = g_list_append(list, GUINT_TO_POINTER(imquic_moq_random_grease()));
		*params_num = g_list_length(list);
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			offset += imquic_write_moqint(moq->version, *params_num, &bytes[offset], blen-offset);
		if(list != NULL) {
			list = g_list_sort(list, imquic_moq_compare_types);
			GList *temp = list;
			while(temp) {
				new_id = GPOINTER_TO_UINT(temp->data);
				if(new_id == IMQUIC_MOQ_SETUP_OPTION_PATH) {
					offset += imquic_moq_setup_option_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint8_t *)options->path, strlen(options->path));
				} else if(new_id == IMQUIC_MOQ_SETUP_OPTION_MAX_REQUEST_ID) {
					offset += imquic_moq_setup_option_add_int(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						options->max_request_id);
				} else if(new_id == IMQUIC_MOQ_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE) {
					offset += imquic_moq_setup_option_add_int(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						options->max_auth_token_cache_size);
				} else if(new_id == IMQUIC_MOQ_SETUP_OPTION_AUTHORIZATION_TOKEN) {
					offset += imquic_moq_setup_option_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						options->auth_token, options->auth_token_len);
				} else if(new_id == IMQUIC_MOQ_SETUP_OPTION_AUTHORITY) {
					offset += imquic_moq_setup_option_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint8_t *)options->authority, strlen(options->authority));
				} else if(new_id == IMQUIC_MOQ_SETUP_OPTION_MOQT_IMPLEMENTATION) {
					offset += imquic_moq_setup_option_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint8_t *)options->moqt_implementation, strlen(options->moqt_implementation));
				} else if(moq->version >= IMQUIC_MOQ_VERSION_17 && imquic_moq_is_grease(new_id)) {
					/* Add a GREASE setup option */
					if(new_id % 2 == 0) {
						uint64_t value = g_random_int_range(1, 1000);
						offset += imquic_moq_setup_option_add_int(moq, &bytes[offset], blen-offset,
							new_id, last_id, value);
					} else {
						uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
						offset += imquic_moq_setup_option_add_data(moq, &bytes[offset], blen-offset,
							new_id, last_id, data, sizeof(data));
					}
				}
				last_id = new_id;
				temp = temp->next;
			}
			g_list_free(list);
		}
	}
	return offset;
}

void imquic_moq_request_parameters_init_defaults(imquic_moq_request_parameters *parameters) {
	if(parameters == NULL)
		return;
	memset(parameters, 0, sizeof(imquic_moq_request_parameters));
	parameters->subscriber_priority = 128;
	parameters->group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	parameters->forward = TRUE;
}

size_t imquic_moq_request_parameters_serialize(imquic_moq_context *moq,
		imquic_moq_message_type request, imquic_moq_request_parameters *parameters,
		uint8_t *bytes, size_t blen, uint8_t *params_num) {
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	if(parameters == NULL) {
		/* No parameters */
		offset += imquic_write_moqint(moq->version, 0, &bytes[offset], blen-offset);
	} else {
		uint64_t new_id = 0, last_id = 0;
		GList *list = NULL;
		if(parameters->auth_token_set && request != IMQUIC_MOQ_REQUEST_OK && request != IMQUIC_MOQ_REQUEST_ERROR) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN));
		}
		if(parameters->delivery_timeout_set && parameters->delivery_timeout > 0 &&
				(request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE || request == IMQUIC_MOQ_REQUEST_UPDATE)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT));
		}
		if(parameters->rendezvous_timeout_set && parameters->rendezvous_timeout > 0 &&
				moq->version >= IMQUIC_MOQ_VERSION_17 && request == IMQUIC_MOQ_SUBSCRIBE) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_RENDEZVOUS_TIMEOUT));
		}
		if(parameters->subscriber_priority_set &&
				(request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE || request == IMQUIC_MOQ_FETCH || request == IMQUIC_MOQ_REQUEST_UPDATE)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY));
		}
		if(parameters->group_order_set &&
				(request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE || request == IMQUIC_MOQ_FETCH)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER));
		}
		if(parameters->subscription_filter_set &&
				(request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE || request == IMQUIC_MOQ_REQUEST_UPDATE)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER));
		}
		if(parameters->expires_set &&
				(request == IMQUIC_MOQ_PUBLISH || request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_REQUEST_OK)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_EXPIRES));
		}
		if(parameters->largest_object_set &&
				(request == IMQUIC_MOQ_PUBLISH || request == IMQUIC_MOQ_SUBSCRIBE_OK || request == IMQUIC_MOQ_REQUEST_OK)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT));
		}
		if(parameters->forward_set &&
				(request == IMQUIC_MOQ_PUBLISH || request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE ||
					request == IMQUIC_MOQ_REQUEST_UPDATE || request == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_FORWARD));
		}
		if(parameters->new_group_request_set &&
				(request == IMQUIC_MOQ_PUBLISH_OK || request == IMQUIC_MOQ_SUBSCRIBE || request == IMQUIC_MOQ_REQUEST_UPDATE)) {
			list = g_list_append(list, GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST));
		}
		*params_num = g_list_length(list);
		offset += imquic_write_moqint(moq->version, *params_num, &bytes[offset], blen-offset);
		if(list != NULL) {
			list = g_list_sort(list, imquic_moq_compare_types);
			GList *temp = list;
			while(temp) {
				new_id = GPOINTER_TO_UINT(temp->data);
				if(new_id == IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN) {
					offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						parameters->auth_token, parameters->auth_token_len);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT) {
					offset += imquic_moq_parameter_add_varint(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						parameters->delivery_timeout);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_RENDEZVOUS_TIMEOUT) {
					offset += imquic_moq_parameter_add_varint(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						parameters->rendezvous_timeout);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY) {
					offset += imquic_moq_parameter_add_uint8(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint64_t)parameters->subscriber_priority);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER) {
					offset += imquic_moq_parameter_add_uint8(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						parameters->group_order);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER) {
					uint8_t temp[40];
					size_t tlen = sizeof(temp);
					size_t toffset = imquic_write_moqint(moq->version, parameters->subscription_filter.type, temp, tlen);
					if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
							parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
						toffset += imquic_write_moqint(moq->version, parameters->subscription_filter.start_location.group, &temp[toffset], tlen-toffset);
						toffset += imquic_write_moqint(moq->version, parameters->subscription_filter.start_location.object, &temp[toffset], tlen-toffset);
					}
					if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
						/* End group is a delta, starting from v17 */
						uint64_t end_group = parameters->subscription_filter.end_group;
						if(moq->version >= IMQUIC_MOQ_VERSION_16)
							end_group -= parameters->subscription_filter.start_location.group;
						toffset += imquic_write_moqint(moq->version, end_group, &temp[toffset], tlen-toffset);
					}
					offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						temp, toffset);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_EXPIRES) {
					offset += imquic_moq_parameter_add_varint(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						parameters->expires);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT) {
					offset += imquic_moq_parameter_add_location(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						&parameters->largest_object);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_FORWARD) {
					offset += imquic_moq_parameter_add_uint8(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint64_t)parameters->forward);
				} else if(new_id == IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST) {
					offset += imquic_moq_parameter_add_varint(moq, &bytes[offset], blen-offset,
						new_id, last_id,
						(uint64_t)parameters->new_group_request);
				}
				last_id = new_id;
				temp = temp->next;
			}
			g_list_free(list);
		}
	}
	return offset;
}

imquic_moq_subscription *imquic_moq_subscription_create(uint64_t request_id, uint64_t track_alias) {
	imquic_moq_subscription *moq_sub = g_malloc0(sizeof(imquic_moq_subscription));
	moq_sub->request_id = request_id;
	moq_sub->track_alias = track_alias;
	moq_sub->stream = NULL;
	moq_sub->streams_by_subgroup = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	return moq_sub;
}

void imquic_moq_subscription_destroy(imquic_moq_subscription *moq_sub) {
	if(moq_sub != NULL) {
		if(moq_sub->stream != NULL)
			imquic_moq_stream_destroy(moq_sub->stream);
		g_hash_table_unref(moq_sub->streams_by_subgroup);
		g_free(moq_sub);
	}
}

void imquic_moq_stream_destroy(imquic_moq_stream *moq_stream) {
	if(moq_stream != NULL) {
		imquic_moq_namespace_free(moq_stream->namespace_prefix);
		imquic_buffer_destroy(moq_stream->buffer);
		g_free(moq_stream);
	}
}

/* Parsing and building macros */
#define IMQUIC_MOQ_CHECK_ERR(cond, error, code, res, reason) \
	if(cond) { \
		IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", reason); \
		if(error) \
			*(uint8_t *)error = code; \
		return res; \
	}

#define IMQUIC_MOQ_PARSE_NAMESPACES(request, tns_num, i, error_message, last) \
	do { \
		tns_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length); \
		IMQUIC_MOQ_CHECK_ERR(length == 0 || (tns_num > 0 && length >= blen-offset), NULL, 0, 0, error_message); \
		IMQUIC_MOQ_CHECK_ERR((tns_num == 0 && request != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE && request != IMQUIC_MOQ_NAMESPACE && request != IMQUIC_MOQ_NAMESPACE_DONE) || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces"); \
		offset += length; \
		uint64_t total_len = 0; \
		i = 0; \
		for(i = 0; i < tns_num; i++) { \
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, error_message); \
			uint64_t tns_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length); \
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, error_message); \
			IMQUIC_MOQ_CHECK_ERR(tns_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track namespace field length"); \
			offset += length; \
			if(last && (i == tns_num - 1)) { \
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, NULL, 0, 0, error_message); \
			} else { \
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, error_message); \
			} \
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n", \
				imquic_get_connection_name(moq->conn), tns_len); \
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n", \
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]); \
			tns[i].length = tns_len; \
			tns[i].buffer = tns_len ? &bytes[offset] : NULL; \
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL); \
			offset += tns_len; \
			total_len += tns_len; \
		} \
		IMQUIC_MOQ_CHECK_ERR(total_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track namespace length"); \
	} while(0)

#define IMQUIC_MOQ_PARSE_TRACKNAME(error_message, last) \
	do { \
		uint64_t tn_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length); \
		if(last) { \
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, error_message); \
		} else { \
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, error_message); \
		} \
		IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length"); \
		offset += length; \
		IMQUIC_MOQ_CHECK_ERR(tn_len > blen-offset, NULL, 0, 0, error_message); \
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n", \
			imquic_get_connection_name(moq->conn), tn_len); \
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n", \
			imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]); \
		tn.length = tn_len; \
		tn.buffer = tn_len ? &bytes[offset] : NULL; \
		offset += tn_len; \
	} while(0)

#define IMQUIC_MOQ_ADD_NAMESPACES(request) \
	do { \
		uint64_t tns_num = 0; \
		imquic_moq_namespace *temp = track_namespace; \
		while(temp) { \
			if(temp->length > 0 && temp->buffer == NULL) { \
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n", \
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(request, moq->version)); \
				return 0; \
			} \
			tns_num++; \
			temp = temp->next; \
		} \
		if((tns_num == 0 && request != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE && request != IMQUIC_MOQ_NAMESPACE && request != IMQUIC_MOQ_NAMESPACE_DONE) || tns_num > 32) { \
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n", \
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(request, moq->version)); \
			return 0; \
		} \
		offset += imquic_write_moqint(moq->version, tns_num, &bytes[offset], blen-offset); \
		temp = track_namespace; \
		while(temp) { \
			offset += imquic_write_moqint(moq->version, temp->length, &bytes[offset], blen-offset); \
			if(temp->length > 0) { \
				memcpy(&bytes[offset], temp->buffer, temp->length); \
				offset += temp->length; \
			} \
			temp = temp->next; \
		} \
	} while(0)

#define IMQUIC_MOQ_ADD_TRACKNAME(request) \
	do { \
		if(track_name->length > 4096) { \
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n", \
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(request, moq->version)); \
			return 0; \
		} \
		offset += imquic_write_moqint(moq->version, track_name->length, &bytes[offset], blen-offset); \
		if(track_name->length > 0) { \
			memcpy(&bytes[offset], track_name->buffer, track_name->length); \
			offset += track_name->length; \
		} \
	} while(0)

#define IMQUIC_MOQ_ADD_MESSAGE_TYPE(type) \
	do { \
		offset = imquic_write_moqint(moq->version, type, bytes, blen); \
		len_offset = offset; \
		offset += 2; \
	} while(0)

#define IMQUIC_MOQ_ADD_MESSAGE_LENGTH() \
	do { \
		uint16_t clen = offset - len_offset - 2; \
		clen = htons(clen); \
		memcpy(&bytes[len_offset], &clen, 2); \
	} while(0)

/* Parse MoQ messages */
static uint64_t imquic_moq_get_control_stream(imquic_moq_context *moq) {
	return (moq->version <= IMQUIC_MOQ_VERSION_16) ?  moq->control_stream_id : moq->remote_control_stream_id;
}
static gboolean imquic_moq_is_control_stream(imquic_moq_context *moq, uint64_t stream_id) {
	if((moq->version <= IMQUIC_MOQ_VERSION_16 && stream_id == moq->control_stream_id) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && stream_id == moq->remote_control_stream_id))
		return TRUE;
	return FALSE;
}
int imquic_moq_parse_message(imquic_moq_context *moq, uint64_t stream_id, uint8_t *bytes, size_t blen, gboolean complete, gboolean datagram) {
	size_t offset = 0, parsed = 0, parsed_prev = 0;
	uint8_t tlen = 0, error = 0;
	/* If this is a datagram, it can only be OBJECT_DATAGRAM or OBJECT_DATAGRAM_STATUS */
	if(datagram) {
		imquic_moq_datagram_message_type dtype = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &tlen);
		offset += tlen;
		gboolean valid = FALSE, payload = FALSE, violation = FALSE;
		valid = imquic_moq_is_datagram_message_type_valid(moq->version, dtype);
		if(valid)
			imquic_moq_datagram_message_type_parse(moq->version, dtype, &payload, NULL, NULL, NULL, NULL, &violation);
		if(valid && payload) {
			/* Parse this OBJECT_DATAGRAM message */
			parsed = imquic_moq_parse_object_datagram(moq, &bytes[offset], blen-offset, dtype, &error);
			IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
		} else if(valid && !payload) {
			/* Parse this OBJECT_DATAGRAM_STATUS message */
			parsed = imquic_moq_parse_object_datagram_status(moq, &bytes[offset], blen-offset, dtype, &error);
			IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
		} else {
			/* TODO Handle failure */
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] MoQ message '%02x' is not allowed on datagrams\n",
				imquic_get_connection_name(moq->conn), dtype);
			return -1;
		}
		/* Done */
		return 0;
	}
	/* Check if this is a media stream */
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams, &stream_id);
	if(imquic_moq_is_control_stream(moq, stream_id)) {
		imquic_buffer_append(moq->buffer, bytes, blen);
		bytes = moq->buffer->bytes;
		blen = moq->buffer->length;
	} else if(moq_stream != NULL && moq_stream->request_type > 0) {
		if(moq_stream->buffer == NULL)
			moq_stream->buffer = imquic_buffer_create(NULL, 0);
		imquic_buffer_append(moq_stream->buffer, bytes, blen);
		bytes = moq_stream->buffer->bytes;
		blen = moq_stream->buffer->length;
	}
	/* Iterate on all frames */
	while((moq_stream == NULL || moq_stream->request_type != 0) && blen-offset > 0) {
		/* If we're here, we're either on the control stream, on a request
		 * stream, or on a media stream waiting to know what it will be like */
		imquic_moq_message_type type = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &tlen);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ][%zu] >> %s (%02x, %u)\n",
			imquic_get_connection_name(moq->conn), offset, imquic_moq_message_type_str(type, moq->version), type, tlen);
		if(!imquic_moq_is_control_stream(moq, stream_id) && moq_stream == NULL) {
			/* Not the control stream, check what it's for (request
			 * or objects) and then make sure it's a supported message */
			gboolean bidirectional = FALSE;
			imquic_parse_stream_id(stream_id, NULL, NULL, &bidirectional);
			imquic_moq_data_message_type dtype = (imquic_moq_data_message_type)type;
			if(bidirectional && (type == IMQUIC_MOQ_PUBLISH_NAMESPACE || type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE ||
					type == IMQUIC_MOQ_PUBLISH || type == IMQUIC_MOQ_SUBSCRIBE ||
					type == IMQUIC_MOQ_FETCH || type == IMQUIC_MOQ_TRACK_STATUS)) {
				/* Create a new MoQ stream for the request and track it */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Stream %"SCNu64" will be used for %s\n",
					imquic_get_connection_name(moq->conn), stream_id, imquic_moq_message_type_str(type, moq->version));
				moq_stream = g_malloc0(sizeof(imquic_moq_stream));
				moq_stream->stream_id = stream_id;
				moq_stream->request_type = type;
				g_hash_table_insert(moq->streams, imquic_dup_uint64(stream_id), moq_stream);
				moq_stream->buffer = imquic_buffer_create(bytes, blen);
				bytes = moq_stream->buffer->bytes;
				blen = moq_stream->buffer->length;
			} else if(!bidirectional && imquic_moq_is_data_message_type_valid(moq->version, dtype)) {
				/* Create a new MoQ stream for data and track it */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Stream %"SCNu64" will be used for %s\n",
					imquic_get_connection_name(moq->conn), stream_id, imquic_moq_data_message_type_str(dtype, moq->version));
				moq_stream = g_malloc0(sizeof(imquic_moq_stream));
				moq_stream->stream_id = stream_id;
				moq_stream->type = dtype;
				moq_stream->priority = 128;	/* FIXME */
				g_hash_table_insert(moq->streams, imquic_dup_uint64(stream_id), moq_stream);
			} else {
				/* TODO Handle failure */
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] MoQ message '%s' (%02x) is not allowed on media streams\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(type, moq->version), type);
				return -1;
			}
		}
		parsed_prev = parsed;
		offset += tlen;
		if(imquic_moq_is_control_stream(moq, stream_id)) {
			/* Control message */
			size_t plen = blen-offset;
			tlen = 2;
			if(blen - offset < tlen) {
				/* Try again later */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to get the length of the control message (%"SCNu8" > %zu), waiting for more data\n",
					imquic_get_connection_name(moq->conn), tlen, blen-offset);
				goto done;
			}
			uint16_t clen = 0;
			memcpy(&clen, &bytes[offset], tlen);
			plen = ntohs(clen);
			offset += tlen;
			if(plen > blen-offset) {
				/* Try again later */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to parse this message (%zu > %zu), waiting for more data\n",
					imquic_get_connection_name(moq->conn), plen, blen-offset);
				goto done;
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_17) {
				/* On newer versions of the protocol, the unidirectional
				 * control streams can only carry a limited set of messages */
				if(type == IMQUIC_MOQ_SETUP) {
					/* Parse this SETUP message */
					parsed = imquic_moq_parse_setup(moq, &bytes[offset], plen, &error);
				} else if(type == IMQUIC_MOQ_GOAWAY) {
					/* Parse this GOAWAY message */
					parsed = imquic_moq_parse_goaway(moq, &bytes[offset], plen, &error);
				} else {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Unsupported message '%02x' (%s)\n",
						imquic_get_connection_name(moq->conn), type,
						imquic_moq_message_type_str(type, moq->version));
					error = IMQUIC_MOQ_PROTOCOL_VIOLATION;
#ifdef HAVE_QLOG
					if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
						json_t *message = imquic_qlog_moq_message_prepare("unknown");
						imquic_moq_qlog_control_message_parsed(moq->conn->qlog, stream_id, &bytes[offset], plen, message);
					}
#endif
				}
				goto next;
			}
			/* If we're here, we're on the legacy version of the protocol */
			if(type == IMQUIC_MOQ_CLIENT_SETUP) {
				/* Parse this CLIENT_SETUP message */
				parsed = imquic_moq_parse_client_setup(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SERVER_SETUP) {
				/* Parse this SERVER_SETUP message */
				parsed = imquic_moq_parse_server_setup(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_MAX_REQUEST_ID) {
				/* Parse this MAX_REQUEST_ID message */
				parsed = imquic_moq_parse_max_request_id(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUESTS_BLOCKED) {
				/* Parse this REQUESTS_BLOCKED message */
				parsed = imquic_moq_parse_requests_blocked(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_OK) {
				/* Parse this REQUEST_OK message */
				parsed = imquic_moq_parse_request_ok(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_ERROR) {
				/* Parse this REQUEST_ERROR message */
				parsed = imquic_moq_parse_request_error(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE) {
				/* Parse this PUBLISH_NAMESPACE message */
				parsed = imquic_moq_parse_publish_namespace(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE) {
				/* Parse this PUBLISH_NAMESPACE_DONE message */
				parsed = imquic_moq_parse_publish_namespace_done(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL) {
				/* Parse this PUBLISH_NAMESPACE_CANCEL message */
				parsed = imquic_moq_parse_publish_namespace_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH) {
				/* Parse this PUBLISH message */
				parsed = imquic_moq_parse_publish(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_OK) {
				/* Parse this PUBLISH_OK message */
				parsed = imquic_moq_parse_publish_ok(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE) {
				/* Parse this SUBSCRIBE message */
				parsed = imquic_moq_parse_subscribe(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_UPDATE) {
				/* Parse this REQUEST_UPDATE message */
				parsed = imquic_moq_parse_request_update(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_OK) {
				/* Parse this SUBSCRIBE_OK message */
				parsed = imquic_moq_parse_subscribe_ok(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE) {
				/* Parse this UNSUBSCRIBE message */
				parsed = imquic_moq_parse_unsubscribe(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_DONE) {
				/* Parse this PUBLISH_DONE message */
				parsed = imquic_moq_parse_publish_done(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH) {
				/* Parse this FETCH message */
				parsed = imquic_moq_parse_fetch(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_CANCEL) {
				/* Parse this FETCH_CANCEL message */
				parsed = imquic_moq_parse_fetch_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_OK) {
				/* Parse this FETCH_OK message */
				parsed = imquic_moq_parse_fetch_ok(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS) {
				/* Parse this TRACK_STATUS message */
				parsed = imquic_moq_parse_track_status(moq, NULL, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_GOAWAY) {
				/* Parse this GOAWAY message */
				parsed = imquic_moq_parse_goaway(moq, &bytes[offset], plen, &error);
			} else {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Unsupported message '%02x' (%s)\n",
					imquic_get_connection_name(moq->conn), type,
					imquic_moq_message_type_str(type, moq->version));
				error = IMQUIC_MOQ_PROTOCOL_VIOLATION;
#ifdef HAVE_QLOG
				if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
					json_t *message = imquic_qlog_moq_message_prepare("unknown");
					imquic_moq_qlog_control_message_parsed(moq->conn->qlog, stream_id, &bytes[offset], plen, message);
				}
#endif
			}
next:
			if(error) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Error parsing MoQ message %s: %s\n",
					imquic_get_connection_name(moq->conn),
					imquic_moq_message_type_str(type, moq->version),
					imquic_moq_error_code_str(error));
				imquic_buffer_shift(moq->buffer, plen);
				if(error != IMQUIC_MOQ_UNKNOWN_ERROR)
					imquic_connection_close(moq->conn, error, imquic_moq_error_code_str(error));
				return -1;
			}
			/* Move to the next message */
			if(plen < parsed) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Skipped message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
			}
			offset += plen;
			imquic_buffer_shift(moq->buffer, offset);
			bytes = moq->buffer->bytes;
			blen = moq->buffer->length;
			offset = 0;
		} else if(moq_stream->request_type > 0) {
			/* Control message for requests */
			size_t plen = blen-offset;
			tlen = 2;
			if(blen - offset < tlen) {
				/* Try again later */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to get the length of the control message (%"SCNu8" > %zu), waiting for more data\n",
					imquic_get_connection_name(moq->conn), tlen, blen-offset);
				goto done;
			}
			uint16_t clen = 0;
			memcpy(&clen, &bytes[offset], tlen);
			plen = ntohs(clen);
			offset += tlen;
			if(plen > blen-offset) {
				/* Try again later */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to parse this message (%zu > %zu), waiting for more data\n",
					imquic_get_connection_name(moq->conn), plen, blen-offset);
				goto done;
			}
			if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE) {
				/* Parse this SPUBLISH_NAMESPACE message */
				parsed = imquic_moq_parse_publish_namespace(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE) {
				/* Parse this SUBSCRIBE_NAMESPACE message */
				parsed = imquic_moq_parse_subscribe_namespace(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH) {
				/* Parse this PUBLISH message */
				parsed = imquic_moq_parse_publish(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_OK) {
				/* Parse this PUBLISH_OK message */
				parsed = imquic_moq_parse_publish_ok(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_DONE) {
				/* Parse this PUBLISH_DONE message */
				parsed = imquic_moq_parse_publish_done(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE) {
				/* Parse this SUBSCRIBE message */
				parsed = imquic_moq_parse_subscribe(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_OK) {
				/* Parse this SUBSCRIBE_OK message */
				parsed = imquic_moq_parse_subscribe_ok(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH) {
				/* Parse this FETCH message */
				parsed = imquic_moq_parse_fetch(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_OK) {
				/* Parse this FETCH_OK message */
				parsed = imquic_moq_parse_fetch_ok(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS) {
				/* Parse this TRACK_STATUS message */
				parsed = imquic_moq_parse_track_status(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_UPDATE) {
				/* Parse this REQUEST_UPDATE message */
				parsed = imquic_moq_parse_request_update(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_OK) {
				/* Parse this REQUEST_OK message */
				parsed = imquic_moq_parse_request_ok(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_ERROR) {
				/* Parse this REQUEST_ERROR message */
				parsed = imquic_moq_parse_request_error(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_NAMESPACE) {
				/* Parse this NAMESPACE message */
				parsed = imquic_moq_parse_namespace(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_NAMESPACE_DONE) {
				/* Parse this NAMESPACE_DONE message */
				parsed = imquic_moq_parse_namespace_done(moq, moq_stream, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_BLOCKED) {
				/* Parse this PUBLISH_BLOCKED message */
				parsed = imquic_moq_parse_publish_blocked(moq, moq_stream, &bytes[offset], plen, &error);
			} else {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported message '%02x' (%s) on a %s request stream\n",
					imquic_get_connection_name(moq->conn), type,
					imquic_moq_message_type_str(type, moq->version),
					imquic_moq_message_type_str(moq_stream->request_type, moq->version));
				error = IMQUIC_MOQ_PROTOCOL_VIOLATION;
#ifdef HAVE_QLOG
				if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
					json_t *message = imquic_qlog_moq_message_prepare("unknown");
					imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq_stream->stream_id, &bytes[offset], plen, message);
				}
#endif
			}
			if(error) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Error parsing MoQ message %s: %s\n",
					imquic_get_connection_name(moq->conn),
					imquic_moq_message_type_str(type, moq->version),
					imquic_moq_error_code_str(error));
				imquic_buffer_shift(moq_stream->buffer, plen);
				if(error != IMQUIC_MOQ_UNKNOWN_ERROR)
					imquic_connection_close(moq->conn, error, imquic_moq_error_code_str(error));
				return -1;
			}
			/* Move to the next message */
			if(plen < parsed) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Skipped message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
			}
			offset += plen;
			imquic_buffer_shift(moq_stream->buffer, offset);
			bytes = moq_stream->buffer->bytes;
			blen = moq_stream->buffer->length;
			offset = 0;
		} else {
			/* Data message */
			if((imquic_moq_data_message_type)type == IMQUIC_MOQ_FETCH_HEADER) {
				/* Parse this FETCH_HEADER message */
				parsed = imquic_moq_parse_fetch_header(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(imquic_moq_is_data_message_type_valid(moq->version, type)) {
				/* Parse this SUBGROUP_HEADER message */
				parsed = imquic_moq_parse_subgroup_header(moq, moq_stream, &bytes[offset], blen-offset, (imquic_moq_data_message_type)type, &error);
				IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
				offset += parsed;
			} else {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported data message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
				return -1;
			}
		}
		if(parsed == parsed_prev) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Broken MoQ message (didn't advance from offset %zu/%zu)\n",
				imquic_get_connection_name(moq->conn), parsed, blen);
			return -1;
		}
	}
	/* Check if we have a media stream to process */
	if(moq_stream != NULL && moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE && blen > offset) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] MoQ media stream %"SCNu64" (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), stream_id, blen - offset);
		/* Copy the incoming data to the buffer, as we'll use that for parsing */
		imquic_buffer_append(moq_stream->buffer, bytes + offset, blen - offset);
		while(moq_stream->buffer && moq_stream->buffer->length > 0) {
			/* Parse the object we're receiving on that stream */
			if(moq_stream->type == IMQUIC_MOQ_FETCH_HEADER) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_fetch_header_object(moq, moq_stream, complete, &error) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else if(imquic_moq_is_data_message_type_valid(moq->version, moq_stream->type)) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_subgroup_header_object(moq, moq_stream, complete, &error) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else {
				/* FIXME Shouldn't happen */
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid MoQ stream type '%s' (%02x)\n",
					imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(moq_stream->type, moq->version), moq_stream->type);
				return -1;
			}
		}
		if(error && error != IMQUIC_MOQ_UNKNOWN_ERROR) {
			imquic_connection_close(moq->conn, error, imquic_moq_error_code_str(error));
			return -1;
		}
	}

done:
	if(moq_stream != NULL && complete) {
		if(moq_stream->request_type > 0) {
			/* The request dedicated bidirectional STREAM has been closed */
			imquic_moq_request_stream_closed(moq, moq_stream);
			return 0;
		}
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Media stream %"SCNu64" is complete\n",
			imquic_get_connection_name(moq->conn), stream_id);
		if(!moq_stream->closed && imquic_moq_is_data_message_type_valid(moq->version, moq_stream->type)) {
			/* FIXME Notify an empty payload to signal the end of the stream */
			imquic_moq_object object = {
				.request_id = moq_stream->request_id,
				.track_alias = moq_stream->track_alias,
				.group_id = moq_stream->group_id,
				.subgroup_id = moq_stream->subgroup_id,
				.object_id = 0,	/* FIXME */
				.object_status = IMQUIC_MOQ_NORMAL_OBJECT,
				.priority = 128,
				.payload = NULL,
				.payload_len = 0,
				.delivery = imquic_moq_data_message_type_to_delivery(moq_stream->type, moq->version),
				.end_of_stream = TRUE
			};
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
				moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
		}
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	return 0;
}

size_t imquic_moq_parse_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_17, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "CLIENT_SETUP was deprecated");
	IMQUIC_MOQ_CHECK_ERR(!moq->is_server, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Received a CLIENT_SETUP, but we're a client");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t opts_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(opts_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken CLIENT_SETUP");
	IMQUIC_MOQ_CHECK_ERR(opts_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken CLIENT_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), opts_num);
	imquic_moq_setup_options options = { 0 };
	uint64_t opt = 0, i = 0;
	for(i = 0; i<opts_num; i++) {
		offset += imquic_moq_parse_setup_option(moq, &bytes[offset], blen-offset, &options, &opt, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken CLIENT_SETUP");
	}
	if(options.max_request_id_set) {
		/* Update the value we have */
		moq->max_request_id = options.max_request_id;
	}
	if(options.max_auth_token_cache_size) {
		/* Update the value we have */
		moq->max_auth_token_cache_size = options.max_auth_token_cache_size;
	}
	if(options.moqt_implementation_set) {
		/* Take note of the implemntation */
		g_free(moq->peer_implementation);
		moq->peer_implementation = NULL;
		if(strlen(options.moqt_implementation) > 0)
			moq->peer_implementation = g_strdup(options.moqt_implementation);
	}
	if(options.path_set) {
		/* TODO Handle and validate */
		if(moq->conn->http3 != NULL && moq->conn->http3->webtransport)
			IMQUIC_MOQ_CHECK_ERR(TRUE, error, IMQUIC_MOQ_INVALID_PATH, 0, "PATH received on a WebTransport");
	}
	if(options.authority_set) {
		/* TODO Handle and validate */
		if(moq->conn->http3 != NULL && moq->conn->http3->webtransport)
			IMQUIC_MOQ_CHECK_ERR(TRUE, error, IMQUIC_MOQ_INVALID_PATH, 0, "AUTHORITY received on a WebTransport");
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID option received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		json_object_set_new(message, "number_of_options", json_integer(opts_num));
		imquic_qlog_moq_message_add_setup_options(message, &options, "setup_options");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application, if we have a callback */
	uint64_t error_code = 0;
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_moq_connection) {
		error_code = moq->conn->socket->callbacks.moq.incoming_moq_connection(moq->conn,
			(options.auth_token_set ? options.auth_token : NULL),
			(options.auth_token_set ? options.auth_token_len : 0));
	}
	IMQUIC_MOQ_CHECK_ERR(error_code > 0, error, error_code, 0, "CLIENT_SETUP rejected by application");
	/* If we got here, generate a SERVER_SETUP to send back */
	imquic_moq_setup_options s_options = { 0 };
	if(moq->local_max_request_id > 0) {
		s_options.max_request_id_set = TRUE;
		s_options.max_request_id = moq->local_max_request_id;
	}
	if(moq->local_max_auth_token_cache_size > 0) {
		s_options.max_auth_token_cache_size_set = TRUE;
		s_options.max_auth_token_cache_size = moq->local_max_auth_token_cache_size;
	}
	/* Add the implementation */
	s_options.moqt_implementation_set = TRUE;
	g_snprintf(s_options.moqt_implementation, sizeof(s_options.moqt_implementation), "imquic %s", imquic_version_string_full);
	uint8_t buffer[200];
	size_t buflen = sizeof(buffer);
	size_t ss_len = imquic_moq_add_server_setup(moq, buffer, buflen, &s_options);
	imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
		buffer, ss_len, FALSE);
	g_atomic_int_set(&moq->connected, 1);
	/* Notify the application the session is ready */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.moq_ready)
		moq->conn->socket->callbacks.moq.moq_ready(moq->conn);
	/* Done */
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_17, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "SERVER_SETUP was deprecated");
	IMQUIC_MOQ_CHECK_ERR(moq->is_server, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Received a SERVER_SETUP, but we're a server");
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t opts_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(opts_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SERVER_SETUP");
	IMQUIC_MOQ_CHECK_ERR(opts_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SERVER_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" options:\n",
		imquic_get_connection_name(moq->conn), opts_num);
	uint64_t i = 0;
	imquic_moq_setup_options options = { 0 };
	uint64_t opt = 0;
	for(i = 0; i<opts_num; i++) {
		offset += imquic_moq_parse_setup_option(moq, &bytes[offset], blen-offset, &options, &opt, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SERVER_SETUP");
	}
	if(options.max_request_id_set) {
		/* Update the value we have */
		moq->max_request_id = options.max_request_id;
	}
	if(options.max_auth_token_cache_size_set) {
		/* Update the value we have */
		moq->max_auth_token_cache_size = options.max_auth_token_cache_size;
	}
	if(options.moqt_implementation_set) {
		/* Take note of the implemntation */
		g_free(moq->peer_implementation);
		moq->peer_implementation = NULL;
		if(strlen(options.moqt_implementation) > 0)
			moq->peer_implementation = g_strdup(options.moqt_implementation);
	}
	if(options.path_set) {
		/* Servers can't use PATH */
		IMQUIC_MOQ_CHECK_ERR(!moq->is_server, error, IMQUIC_MOQ_INVALID_PATH, 0, "PATH received from a server");
	}
	if(options.authority_set) {
		/* Servers can't use AUTHORITY */
		IMQUIC_MOQ_CHECK_ERR(!moq->is_server, error, IMQUIC_MOQ_INVALID_PATH, 0, "AUTHORITY received from a server");
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID option received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		json_object_set_new(message, "number_of_options", json_integer(opts_num));
		imquic_qlog_moq_message_add_setup_options(message, &options, "setup_options");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application the session is ready */
	g_atomic_int_set(&moq->connected, 1);
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.moq_ready)
		moq->conn->socket->callbacks.moq.moq_ready(moq->conn);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	IMQUIC_MOQ_CHECK_ERR(moq->version <= IMQUIC_MOQ_VERSION_16, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "SETUP unsupported on older versions");
	/* Parse the SETUP options */
	size_t offset = 0;
	imquic_moq_setup_options options = { 0 };
	uint64_t opt = 0;
	while(bytes != NULL && offset < blen) {
		offset += imquic_moq_parse_setup_option(moq, &bytes[offset], blen-offset, &options, &opt, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SETUP");
	}
	if(options.max_auth_token_cache_size_set) {
		/* Update the value we have */
		moq->max_auth_token_cache_size = options.max_auth_token_cache_size;
	}
	if(options.moqt_implementation_set) {
		/* Take note of the implemntation */
		g_free(moq->peer_implementation);
		moq->peer_implementation = NULL;
		if(strlen(options.moqt_implementation) > 0)
			moq->peer_implementation = g_strdup(options.moqt_implementation);
	}
	if(options.path_set) {
		/* Servers can't use PATH */
		IMQUIC_MOQ_CHECK_ERR(!moq->is_server, error, IMQUIC_MOQ_INVALID_PATH, 0, "PATH received from a server");
	}
	if(options.authority_set) {
		/* Servers can't use AUTHORITY */
		IMQUIC_MOQ_CHECK_ERR(!moq->is_server, error, IMQUIC_MOQ_INVALID_PATH, 0, "AUTHORITY received from a server");
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID option received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("setup");
		imquic_qlog_moq_message_add_setup_options(message, &options, "setup_options");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application the session is ready, if we're done */
	moq->recvd_setup = TRUE;
	/* FIXME */
	if(moq->recvd_setup && moq->sent_setup) {
		g_atomic_int_set(&moq->connected, 1);
		g_atomic_int_set(&moq->check_pending, 1);
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.moq_ready)
			moq->conn->socket->callbacks.moq.moq_ready(moq->conn);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_max_request_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_17, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "MAX_REQUEST_ID was deprecated");
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length) + 1;
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken MAX_REQUEST_ID");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Maximum Request ID %"SCNu64":\n",
		imquic_get_connection_name(moq->conn), max);
	IMQUIC_MOQ_CHECK_ERR(max <= moq->max_request_id, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Equal or smaller Max Request ID received");
	/* Update the value we have */
	moq->max_request_id = max;
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("max_request_id");
		json_object_set_new(message, "request_id", json_integer(max));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_requests_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_17, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "REQUESTS_BLOCKED was deprecated");
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUESTS_BLOCKED");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Maximum Request ID %"SCNu64":\n",
		imquic_get_connection_name(moq->conn), max);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("requests_blocked");
		json_object_set_new(message, "maximum_request_id", json_integer(max));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.requests_blocked)
		moq->conn->socket->callbacks.moq.requests_blocked(moq->conn, max);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_request_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	/* FIXME State management needs to be fixed, because an update will trigger OK/ERROR too */
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type == 0 ||
			!moq_stream->request_sender || (moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT))),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of REQUEST_OK on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->update_request_id;
		moq_stream->update_request_id = 0;
	}
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken REQUEST_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken REQUEST_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken REQUEST_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing REQUEST_OK parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application, but we'll need to check which callback to trigger */
	imquic_mutex_lock(&moq->mutex);
	if(moq_stream != NULL)
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
	imquic_moq_message_type type = GPOINTER_TO_UINT(g_hash_table_lookup(moq->requests, &request_id));
	g_hash_table_remove(moq->requests, &request_id);
	imquic_mutex_unlock(&moq->mutex);
	switch(type) {
		case IMQUIC_MOQ_PUBLISH_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_accepted)
				moq->conn->socket->callbacks.moq.publish_namespace_accepted(moq->conn, request_id, &parameters);
			break;
		case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_namespace_accepted)
				moq->conn->socket->callbacks.moq.subscribe_namespace_accepted(moq->conn, request_id, &parameters);
			break;
		case IMQUIC_MOQ_REQUEST_UPDATE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.request_update_accepted)
				moq->conn->socket->callbacks.moq.request_update_accepted(moq->conn, request_id, &parameters);
			break;
		case IMQUIC_MOQ_TRACK_STATUS:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_accepted)
				moq->conn->socket->callbacks.moq.track_status_accepted(moq->conn, request_id, &parameters);
			break;
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Couldn't find a request associated to ID %"SCNu64" (%s), can't notify success\n",
				imquic_get_connection_name(moq->conn), request_id, imquic_moq_message_type_str(type, moq->version));
			break;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_request_error(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	/* FIXME State management needs to be fixed, because an update will trigger OK/ERROR too */
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type == 0 ||
			!moq_stream->request_sender || (moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT))),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of REQUEST_ERROR on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->update_request_id;
		moq_stream->update_request_id = 0;
	}
	uint64_t error_code = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t retry_interval = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Retry Interval: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), retry_interval);
	uint64_t rs_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
		IMQUIC_MOQ_CHECK_ERR(rs_len > sizeof(reason), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid reason length");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_error");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		json_object_set_new(message, "retry_interval", json_integer(retry_interval));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application, but we'll need to check which callback to trigger */
	imquic_mutex_lock(&moq->mutex);
	if(moq_stream != NULL) {
		moq_stream->request_state = (moq_stream->request_state == IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) ?
			IMQUIC_MOQ_REQUEST_STATE_OK : IMQUIC_MOQ_REQUEST_STATE_ERROR;
	}
	imquic_moq_message_type type = GPOINTER_TO_UINT(g_hash_table_lookup(moq->requests, &request_id));
	g_hash_table_remove(moq->requests, &request_id);
	imquic_mutex_unlock(&moq->mutex);
	switch(type) {
		case IMQUIC_MOQ_PUBLISH_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_error)
				moq->conn->socket->callbacks.moq.publish_namespace_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_PUBLISH:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_error)
				moq->conn->socket->callbacks.moq.publish_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_namespace_error)
				moq->conn->socket->callbacks.moq.subscribe_namespace_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_SUBSCRIBE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_error)
				moq->conn->socket->callbacks.moq.subscribe_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_REQUEST_UPDATE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.request_update_error)
				moq->conn->socket->callbacks.moq.request_update_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_FETCH:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_error)
				moq->conn->socket->callbacks.moq.fetch_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		case IMQUIC_MOQ_TRACK_STATUS:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_error)
				moq->conn->socket->callbacks.moq.track_status_error(moq->conn, request_id, error_code, reason_str, retry_interval);
			break;
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Couldn't find a request associated to ID %"SCNu64" (%s), can't notify error\n",
				imquic_get_connection_name(moq->conn), request_id, imquic_moq_message_type_str(type, moq->version));
			break;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of PUBLISH_NAMESPACE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t required_id_delta = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_PUBLISH_NAMESPACE, tns_num, i, "Broken PUBLISH_NAMESPACE", FALSE);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	uint64_t param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing PUBLISH_NAMESPACE parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "publish_namespace");
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace");
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish_namespace) {
		moq->conn->socket->callbacks.moq.incoming_publish_namespace(moq->conn, request_id, required_id_delta, &tns[0], &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_publish_namespace(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_DONE");
	offset += length;
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_done");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_done)
		moq->conn->socket->callbacks.moq.publish_namespace_done(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	offset += length;
	uint64_t error_code = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_CANCEL");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_CANCEL");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_CANCEL");
		IMQUIC_MOQ_CHECK_ERR(rs_len > sizeof(reason), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid reason length");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_cancel");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish_namespace_cancel)
		moq->conn->socket->callbacks.moq.incoming_publish_namespace_cancel(moq->conn, request_id, error_code, reason);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of PUBLISH on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t required_id_delta = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_PUBLISH, tns_num, i, "Broken PUBLISH", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken PUBLISH", FALSE);
	uint64_t track_alias = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing PUBLISH parameters");
	}
	size_t prop_offset = 0, prop_len = 0;
	prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || (prop_len > 0 && length >= blen-offset), NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Properties Length:  %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), prop_len);
	prop_offset = offset;
	IMQUIC_MOQ_CHECK_ERR(prop_len > blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += prop_len;
	GList *track_properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		track_properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "publish");
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace");
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish) {
		moq->conn->socket->callbacks.moq.incoming_publish(moq->conn,
			request_id, required_id_delta, &tns[0], &tn, track_alias, &parameters, track_properties);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_publish(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	g_list_free_full(track_properties, (GDestroyNotify)imquic_moq_property_free);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH ||
			!moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of PUBLISH_OK on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->request_id;
	}
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing PUBLISH_OK parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	if(moq_stream != NULL)
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_accepted)
		moq->conn->socket->callbacks.moq.publish_accepted(moq->conn, request_id, &parameters);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of SUBSCRIBE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t required_id_delta = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	/* Move on */
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE, tns_num, i, "Broken SUBSCRIBE", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken SUBSCRIBE", FALSE);
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing SUBSCRIBE parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "subscribe");
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace");
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Track this subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, 0);
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe) {
		moq->conn->socket->callbacks.moq.incoming_subscribe(moq->conn,
			request_id, required_id_delta, &tns[0], &tn, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_request_update(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	/* FIXME State management needs to be fixed, because an update will trigger OK/ERROR too */
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type == 0 ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of REQUEST_UPDATE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t sub_request_id = 0, required_id_delta = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		sub_request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscription Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), sub_request_id);
	} else {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken REQUEST_UPDATE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken REQUEST_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken REQUEST_UPDATE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing REQUEST_UPDATE parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			json_object_set_new(message, "subscription_request_id", json_integer(sub_request_id));
		} else {
			json_object_set_new(message, "required_request_id_delta", json_integer(sub_request_id));
		}
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	if(moq_stream != NULL) {
		sub_request_id = moq_stream->request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT;
	}
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.request_updated) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->update_requests, imquic_dup_uint64(request_id), imquic_dup_uint64(sub_request_id));
		imquic_mutex_unlock(&moq->mutex);
		moq->conn->socket->callbacks.moq.request_updated(moq->conn,
			request_id, sub_request_id, required_id_delta, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_request_update(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE ||
			!moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of SUBSCRIBE_OK on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->request_id;
	}
	uint64_t track_alias = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing SUBSCRIBE_OK parameters");
	}
	size_t prop_offset = 0, prop_len = 0;
	prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || (prop_len > 0 && length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Properties Length:  %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), prop_len);
	prop_offset = offset;
	IMQUIC_MOQ_CHECK_ERR(prop_len > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += prop_len;
	GList *track_properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		track_properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	if(moq_stream != NULL)
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_accepted) {
		moq->conn->socket->callbacks.moq.subscribe_accepted(moq->conn,
			request_id, track_alias, &parameters, track_properties);
	}
	g_list_free_full(track_properties, (GDestroyNotify)imquic_moq_property_free);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Get rid of this subscription */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &request_id);
	if(moq_sub != NULL) {
		g_hash_table_remove(moq->subscriptions, &moq_sub->track_alias);
		g_hash_table_remove(moq->subscriptions_by_id, &request_id);
	}
	imquic_mutex_unlock(&moq->mutex);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_done(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH ||
			moq_stream->request_sender || moq_stream->request_state == IMQUIC_MOQ_REQUEST_STATE_NEW ||
			moq_stream->request_state == IMQUIC_MOQ_REQUEST_STATE_ERROR || moq_stream->request_state == IMQUIC_MOQ_REQUEST_STATE_DONE)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of PUBLISH_DONE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->request_id;
	}
	uint64_t status_code = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_pub_done_code_str(status_code), status_code);
	uint64_t streams_count = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Streams Count: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), streams_count);
	uint64_t rs_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
		IMQUIC_MOQ_CHECK_ERR(rs_len > sizeof(reason), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid reason length");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_done");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status_code));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	if(moq_stream != NULL)
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_DONE;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_done) {
		moq->conn->socket->callbacks.moq.publish_done(moq->conn,
			request_id, status_code, streams_count, reason_str);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of SUBSCRIBE_NAMESPACE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t required_id_delta = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE, tns_num, i, "Broken SUBSCRIBE_NAMESPACE", FALSE);
	imquic_moq_subscribe_namespace_options subscribe_options = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || subscribe_options > IMQUIC_MOQ_WANT_PUBLISH_AND_NAMESPACE, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	offset += length;
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	uint64_t param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing SUBSCRIBE_NAMESPACE parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "subscribe_namespace");
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace_prefix");
		json_object_set_new(message, "subscribe_options", json_integer(subscribe_options));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its request ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		moq_stream->namespace_prefix = moq_stream->last_tuple = imquic_moq_namespace_duplicate(tns);
		while(moq_stream->last_tuple->next != NULL)
			moq_stream->last_tuple = moq_stream->last_tuple->next;
		moq_stream->namespace_prefix_size = tns_num;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe_namespace) {
		moq->conn->socket->callbacks.moq.incoming_subscribe_namespace(moq->conn,
			request_id, required_id_delta, &tns[0], subscribe_options, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe_namespace(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE ||
			!moq_stream->request_sender || (moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of NAMESPACE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_NAMESPACE, tns_num, i, "Broken NAMESPACE", TRUE);
	IMQUIC_MOQ_CHECK_ERR((tns_num + moq_stream->namespace_prefix_size) > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("namespace");
		imquic_qlog_moq_message_add_namespace(message, (tns_num > 0 ? &tns[0] : NULL), "track_namespace_suffix");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq_stream->stream_id, bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_namespace) {
		/* Prepare the full track namespace */
		if(tns_num > 0)
			moq_stream->last_tuple->next = &tns[0];
		moq->conn->socket->callbacks.moq.incoming_namespace(moq->conn, moq_stream->request_id, moq_stream->namespace_prefix);
		moq_stream->last_tuple->next = NULL;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_namespace_done(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE ||
			!moq_stream->request_sender || (moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of NAMESPACE_DONE on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_NAMESPACE_DONE, tns_num, i, "Broken NAMESPACE_DONE", TRUE);
	IMQUIC_MOQ_CHECK_ERR((tns_num + moq_stream->namespace_prefix_size) > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("namespace_done");
		imquic_qlog_moq_message_add_namespace(message, (tns_num > 0 ? &tns[0] : NULL), "track_namespace_suffix");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq_stream->stream_id, bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_namespace_done) {
		/* Prepare the full track namespace */
		if(tns_num > 0)
			moq_stream->last_tuple->next = &tns[0];
		moq->conn->socket->callbacks.moq.incoming_namespace_done(moq->conn, moq_stream->request_id, moq_stream->namespace_prefix);
		moq_stream->last_tuple->next = NULL;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_blocked(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE ||
			!moq_stream->request_sender || (moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of PUBLISH_BLOCKED on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_NAMESPACE_DONE, tns_num, i, "Broken PUBLISH_BLOCKED", TRUE);
	IMQUIC_MOQ_CHECK_ERR((tns_num + moq_stream->namespace_prefix_size) > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken PUBLISH_BLOCKED", FALSE);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_blocked");
		imquic_qlog_moq_message_add_namespace(message, (tns_num > 0 ? &tns[0] : NULL), "track_namespace_suffix");
		imquic_qlog_moq_message_add_track(message, &tn);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq_stream->stream_id, bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish_blocked) {
		/* Prepare the full track namespace */
		if(tns_num > 0)
			moq_stream->last_tuple->next = &tns[0];
		moq->conn->socket->callbacks.moq.incoming_publish_blocked(moq->conn, moq_stream->request_id, moq_stream->namespace_prefix, &tn);
		moq_stream->last_tuple->next = NULL;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of FETCH on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t required_id_delta = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		required_id_delta = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Required Request ID Delta: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), required_id_delta);
	}
	/* Move on */
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	imquic_moq_name tn = { 0 };
	imquic_moq_fetch_type type = IMQUIC_MOQ_FETCH_STANDALONE;
	imquic_moq_location_range range = { 0 };
	uint64_t joining_request_id = 0, joining_start = 0;
	type = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
		uint64_t tns_num = 0, i = 0;
		IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_FETCH, tns_num, i, "Broken FETCH", FALSE);
		IMQUIC_MOQ_PARSE_TRACKNAME("Broken FETCH", FALSE);
		range.start.group = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.start.group);
		range.start.object = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.start.object);
		range.end.group = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.end.group);
		range.end.object = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.end.object);
	} else if(type == IMQUIC_MOQ_FETCH_JOINING_RELATIVE || type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE) {
		joining_request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		joining_start = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
	} else {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Broken FETCH, invalid type '%d'\n",
			imquic_get_connection_name(moq->conn), type);
		return 0;
	}
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken FETCH");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing FETCH parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "fetch");
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		json_object_set_new(message, "fetch_type", json_integer(type));
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace");
			imquic_qlog_moq_message_add_track(message, &tn);
			json_object_set_new(message, "start_group", json_integer(range.start.group));
			json_object_set_new(message, "start_object", json_integer(range.start.object));
			json_object_set_new(message, "end_group", json_integer(range.end.group));
			json_object_set_new(message, "end_object", json_integer(range.end.object));
		} else {
			json_object_set_new(message, "joining_request_id", json_integer(joining_request_id));
			json_object_set_new(message, "joining_start", json_integer(joining_start));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its request ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Track this fetch subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, 0);
	moq_sub->fetch = TRUE;
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_standalone_fetch) {
			moq->conn->socket->callbacks.moq.incoming_standalone_fetch(moq->conn,
				request_id, required_id_delta, &tns[0], &tn, &range, &parameters);
		} else {
			/* No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
		}
	} else {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_joining_fetch) {
			moq->conn->socket->callbacks.moq.incoming_joining_fetch(moq->conn,
				request_id, required_id_delta, joining_request_id,
				(type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE), joining_start, &parameters);
		} else {
			/* No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
		}
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_CANCEL");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Get rid of this subscription */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &request_id);
	if(moq_sub == NULL || !moq_sub->fetch) {
		/* FIXME Should we not bobble this up to the application? */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't cancel FETCH, request ID %"SCNu64" is not a FETCH\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		g_hash_table_remove(moq->subscriptions_by_id, &request_id);
	}
	imquic_mutex_unlock(&moq->mutex);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_cancel");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_fetch_cancel)
		moq->conn->socket->callbacks.moq.incoming_fetch_cancel(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_FETCH ||
			!moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of FETCH_OK on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
	} else {
		request_id = moq_stream->request_id;
	}
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	uint8_t end_of_track = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Of Track: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), end_of_track);
	imquic_moq_location largest = { 0 };
	largest.group = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.group);
	largest.object = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.object);
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken FETCH_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0, param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing FETCH_OK parameters");
	}
	size_t prop_offset = 0, prop_len = 0;
	prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || (prop_len > 0 && length >= blen-offset), NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Properties Length:  %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), prop_len);
	prop_offset = offset;
	IMQUIC_MOQ_CHECK_ERR(prop_len > blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += prop_len;
	GList *track_properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		track_properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(largest.group));
		json_object_set_new(message, "largest_object_id", json_integer(largest.object));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	if(moq_stream != NULL)
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_accepted)
		moq->conn->socket->callbacks.moq.fetch_accepted(moq->conn, request_id, &largest, &parameters, track_properties);
	g_list_free_full(track_properties, (GDestroyNotify)imquic_moq_property_free);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	IMQUIC_MOQ_CHECK_ERR((moq->version >= IMQUIC_MOQ_VERSION_17 && (moq_stream == NULL ||
			moq_stream->request_sender || moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_NEW)),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid use of TRACK_STATUS on bidirectional request");
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Move on */
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(IMQUIC_MOQ_TRACK_STATUS, tns_num, i, "Broken TRACK_STATUS", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken TRACK_STATUS", FALSE);
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	uint64_t params_num = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken TRACK_STATUS");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t param = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Error parsing TRACK_STATUS parameters");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "track_status");
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0], "track_namespace");
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : imquic_moq_get_control_stream(moq)), bytes-3, offset+3, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* If we're on a recent version of MoQ, track this request via its ID */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status) {
		moq->conn->socket->callbacks.moq.incoming_track_status(moq->conn,
			request_id, &tns[0], &tn, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_track_status(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", 0);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_datagram_message_type dtype, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	/* TODO Check EOG too */
	gboolean has_prop = FALSE, has_oid = TRUE, has_priority = TRUE;
	imquic_moq_datagram_message_type_parse(moq->version, dtype, NULL, &has_prop, NULL, &has_oid, &has_priority, NULL);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = 0;
	if(has_oid) {
		object_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		offset += length;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint8_t priority = 0;
	if(has_priority) {
		priority = bytes[offset];
		offset++;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	size_t prop_offset = 0, prop_len = 0;
	if(has_prop) {
		/* The object contains properties */
		prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		IMQUIC_MOQ_CHECK_ERR(prop_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Properties length is 0 but type is OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Properties Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), prop_len);
		prop_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || prop_len >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		offset += prop_len;
	}
	GList *properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), blen-offset);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.request_id = 0,	/* TODO remove? */
		.track_alias = track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = 0,
		.priority = priority,
		.payload = (blen-offset > 0 ? &bytes[offset] : NULL),
		.payload_len = blen-offset,
		.properties = properties,
		.delivery = IMQUIC_MOQ_USE_DATAGRAM,
		.end_of_stream = FALSE	/* No stream is involved here */
	};
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		imquic_moq_qlog_object_datagram_parsed(moq->conn->qlog, &object);
	}
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	g_list_free_full(properties, (GDestroyNotify)imquic_moq_property_free);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_datagram_message_type dtype, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	gboolean has_prop = FALSE, has_oid = TRUE, has_priority = TRUE;
	imquic_moq_datagram_message_type_parse(moq->version, dtype, NULL, &has_prop, NULL, &has_oid, &has_priority, NULL);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	if(has_oid) {
		object_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		offset += length;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint8_t priority = 0;
	if(has_priority) {
		priority = bytes[offset];
		offset++;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	size_t prop_offset = 0, prop_len = 0;
	if(has_prop) {
		/* The object contains properties */
		prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		IMQUIC_MOQ_CHECK_ERR(prop_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Properties length is 0 but type is OBJECT_DATAGRAM_STATUS");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Properties Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), prop_len);
		prop_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || prop_len >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		offset += prop_len;
	}
	GList *properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
	uint64_t object_status = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:     %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_status);
	/* Notify this as an object at the application layer */
	imquic_moq_object object = {
		.request_id = 0,	/* TODO remove? */
		.track_alias = track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.priority = priority,
		.payload = NULL,
		.payload_len = 0,
		.properties = properties,
		.delivery = IMQUIC_MOQ_USE_DATAGRAM,
		.end_of_stream = FALSE	/* No stream is involved here */
	};
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		imquic_moq_qlog_object_datagram_status_parsed(moq->conn->qlog, &object);
	}
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	g_list_free_full(properties, (GDestroyNotify)imquic_moq_property_free);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, imquic_moq_data_message_type dtype, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 4)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t subgroup_id = 0;
	/* Starting from v11, the subgroup ID property is optional */
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_prop = FALSE, is_eog = FALSE, has_priority = FALSE, violation = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, dtype,
		&has_subgroup, &is_sgid0, &has_prop, &is_eog, &has_priority, &violation);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][MoQ] SUBGROUP_HEADER type %02x: sg=%d, sgid0=%d, prop=%d, eog=%d, pri=%d, viol=%d\n",
		imquic_get_connection_name(moq->conn), dtype, has_subgroup, is_sgid0, has_prop, is_eog, has_priority, violation);
	IMQUIC_MOQ_CHECK_ERR(violation, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid SUBGROUP_HEADER type");
	if(has_subgroup) {
		subgroup_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
		offset += length;
	} else {
		/* TODO The subgroup ID may need to be set to the first object ID, in some cases */
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subgroup ID:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subgroup_id);
	uint8_t priority = 0;
	if(has_priority) {
		priority = bytes[offset];
		offset++;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = 0;
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->subgroup_id = subgroup_id;
		moq_stream->priority = priority;
		moq_stream->buffer = imquic_buffer_create(NULL, 0);
#ifdef HAVE_QLOG
		if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "subgroup_header");
			imquic_moq_qlog_subgroup_header_parsed(moq->conn->qlog, moq_stream, bytes, offset);
		}
#endif
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t object_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	size_t prop_offset = 0, prop_len = 0;
	/* TODO We can optimize this by only doing it once, when we parse the header */
	/* TODO Check EOG too */
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_prop = FALSE, has_priority = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, &has_subgroup, &is_sgid0, &has_prop, NULL, &has_priority, NULL);
	if(has_prop) {
		/* The object contains properties */
		prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Properties Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), prop_len);
		prop_offset = offset;
		if(length == 0 || prop_len >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += prop_len;
	}
	uint64_t p_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_status = 0;
	if(p_len == 0) {
		object_status = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
		/* TODO An invalid object status should be a protocol violation error */
		//~ IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
		//~ IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && prop_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Properties received in object with status 'Does Not Exist'");
		offset += length;
	}
	if(p_len > blen-offset)
		return -1;	/* Not enough data, try again later */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), p_len);
	if(p_len == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	}
	if(!moq_stream->got_objects && !has_subgroup && !is_sgid0) {
		/* Starting from v11, there are cases where the subgroup ID
		 * is set to the first object we receive in the sequence */
		moq_stream->subgroup_id = object_id;
	}
	/* Object IDs are a delta */
	object_id += moq_stream->last_object_id;
	if(moq_stream->got_objects)
		object_id++;
	if(!moq_stream->got_objects)
		moq_stream->got_objects = TRUE;
	moq_stream->last_object_id = object_id;
	GList *properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.request_id = moq_stream->request_id,
		.track_alias = moq_stream->track_alias,
		.group_id = moq_stream->group_id,
		.subgroup_id = moq_stream->subgroup_id,
		.object_id = object_id,
		.object_status = object_status,
		.priority = moq_stream->priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.properties = properties,
		.delivery = IMQUIC_MOQ_USE_SUBGROUP,
		.end_of_stream = complete
	};
#ifdef HAVE_QLOG
	if(moq_stream != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq)
		imquic_moq_qlog_subgroup_object_parsed(moq->conn->qlog, moq_stream->stream_id, &object);
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	g_list_free_full(properties, (GDestroyNotify)imquic_moq_property_free);
	/* Move on */
	offset += p_len;
	imquic_buffer_shift(moq_stream->buffer, offset);
	if(complete)
		moq_stream->closed = TRUE;
	/* Done */
	return 0;
}

size_t imquic_moq_parse_fetch_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->buffer = imquic_buffer_create(NULL, 0);
#ifdef HAVE_QLOG
		if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "fetch_header");
			imquic_moq_qlog_fetch_header_parsed(moq->conn->qlog, moq_stream, bytes, offset);
		}
#endif
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_fetch_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	/* Since v15, FETCH objects are prefixed by serialization flags
	 * that are supposed to optimize what will and will not be there */
	uint64_t flags = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	if(length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	imquic_moq_fetch_subgroup_type subgroup_type = IMQUIC_MOQ_FETCH_SUBGROUP_ID;
	gboolean has_oid = FALSE, has_group = FALSE, has_priority = FALSE, has_prop = FALSE,
		is_datagram = FALSE, end_ne_range = FALSE, end_uk_range = FALSE, violation = FALSE;
	imquic_moq_parse_fetch_serialization_flags(moq->version, flags,
		&subgroup_type, &has_oid, &has_group, &has_priority, &has_prop, &is_datagram, &end_ne_range, &end_uk_range, &violation);
	uint64_t group_id = 0;
	if(has_group) {
		group_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* TODO The group ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		group_id = moq_stream->group_id;
	}
	uint64_t subgroup_id = 0;
	if(subgroup_type == IMQUIC_MOQ_FETCH_SUBGROUP_ID) {
		subgroup_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* The subgroup ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		if(subgroup_type == IMQUIC_MOQ_FETCH_SUBGROUP_PREVIOUS)
			subgroup_id = moq_stream->subgroup_id;
		else if(subgroup_type == IMQUIC_MOQ_FETCH_SUBGROUP_PLUS_ONE)
			subgroup_id = moq_stream->subgroup_id + 1;
	}
	uint64_t object_id = 0;
	if(has_oid) {
		object_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* The object ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		object_id = moq_stream->last_object_id + 1;
	}
	uint8_t priority = 0;
	if(has_priority) {
		priority = bytes[offset];
		offset++;
	} else {
		/* The priority references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		priority = moq_stream->last_priority;
	}
	size_t prop_offset = 0, prop_len = 0;
	if(has_prop) {
		prop_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Properties Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), prop_len);
		prop_offset = offset;
		if(length == 0 || prop_len >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += prop_len;
	}
	uint64_t p_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_status = 0;
	if(p_len == 0) {
		object_status = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
		/* TODO An invalid object status should be a protocol violation error */
		//~ IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
		//~ IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && prop_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Properties received in object with status 'Does Not Exist'");
		offset += length;
	}
	if(p_len > blen-offset)
		return -1;	/* Not enough data, try again later */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subgroup ID:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subgroup_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), p_len);
	if(p_len == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	}
	if(!moq_stream->got_objects)
		moq_stream->got_objects = TRUE;
	moq_stream->last_group_id = group_id;
	moq_stream->last_subgroup_id = subgroup_id;
	moq_stream->last_object_id = object_id;
	moq_stream->last_priority = priority;
	GList *properties = NULL;
	if(prop_offset > 0 && prop_len > 0) {
		/* TODO Check Protocol Violation cases */
		properties = imquic_moq_parse_properties(moq->version, &bytes[prop_offset], prop_len);
	}
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.request_id = moq_stream->request_id,
		.track_alias = moq_stream->track_alias,
		.group_id = group_id,
		.subgroup_id = subgroup_id,
		.object_id = object_id,
		.object_status = object_status,
		.priority = priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.properties = properties,
		.delivery = IMQUIC_MOQ_USE_FETCH,
		.end_of_stream = complete
	};
#ifdef HAVE_QLOG
	if(moq_stream != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq)
		imquic_moq_qlog_fetch_object_parsed(moq->conn->qlog, moq_stream->stream_id, &object);
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	g_list_free_full(properties, (GDestroyNotify)imquic_moq_property_free);
	/* Move on */
	offset += p_len;
	imquic_buffer_shift(moq_stream->buffer, offset);
	if(complete)
		moq_stream->closed = TRUE;
	/* Done */
	return 0;
}

size_t imquic_moq_parse_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t uri_len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken GOAWAY");
	offset += length;
	char uri[8192], *uri_str = NULL;
	if(uri_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(moq->is_server, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Clients can't provide a new session URI");
		IMQUIC_MOQ_CHECK_ERR(uri_len > blen-offset, NULL, 0, 0, "Broken GOAWAY");
		IMQUIC_MOQ_CHECK_ERR(uri_len > sizeof(uri), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid new session URI length");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- New session URI:\n",
			imquic_get_connection_name(moq->conn));
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)uri_len, &bytes[offset]);
		if(uri_len > 0) {
			g_snprintf(uri, sizeof(uri), "%.*s\n", (int)uri_len, &bytes[offset]);
			uri_str = uri;
		}
	}
	offset += uri_len;
	uint64_t timeout = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		timeout = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken GOAWAY");
		offset += length;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("goaway");
		imquic_qlog_event_add_raw(message, "new_session_uri", (uint8_t *)uri_str, uri_len);
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "timeout", json_integer(timeout));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, imquic_moq_get_control_stream(moq), bytes-3, offset+3, message);
	}
#endif
	IMQUIC_MOQ_CHECK_ERR(!g_atomic_int_compare_and_exchange(&moq->got_goaway, 0, 1),
		error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Multiple GOAWAY messages received");
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_goaway)
		moq->conn->socket->callbacks.moq.incoming_goaway(moq->conn, uri_str, timeout);
	if(error)
		*error = 0;
	return offset;
}

/* Message building */
size_t imquic_moq_add_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_setup_options *options) {
	if(bytes == NULL || blen < 2 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_CLIENT_SETUP, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_CLIENT_SETUP);
	uint8_t opts_num = 0;
	offset += imquic_moq_setup_options_serialize(moq, options, &bytes[offset], blen-offset, &opts_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		json_object_set_new(message, "number_of_options", json_integer(opts_num));
		imquic_qlog_moq_message_add_setup_options(message, options, "setup_options");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_setup_options *options) {
	if(bytes == NULL || blen < 2 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SERVER_SETUP, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SERVER_SETUP);
	uint8_t opts_num = 0;
	offset += imquic_moq_setup_options_serialize(moq, options, &bytes[offset], blen-offset, &opts_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("setup");
		imquic_qlog_moq_message_add_setup_options(message, options, "setup_options");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_setup_options *options) {
	if(bytes == NULL || blen < 2 || moq->version <= IMQUIC_MOQ_VERSION_16) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SETUP, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SETUP);
	uint8_t opts_num = 0;
	offset += imquic_moq_setup_options_serialize(moq, options, &bytes[offset], blen-offset, &opts_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		json_object_set_new(message, "number_of_options", json_integer(opts_num));
		imquic_qlog_moq_message_add_setup_options(message, options, "setup_options");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_max_request_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_request_id) {
	if(bytes == NULL || blen < 1 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_MAX_REQUEST_ID, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_MAX_REQUEST_ID);
	offset += imquic_write_moqint(moq->version, max_request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("max_request_id");
		json_object_set_new(message, "request_id", json_integer(max_request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_requests_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_request_id) {
	if(bytes == NULL || blen < 1 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUESTS_BLOCKED, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUESTS_BLOCKED);
	offset += imquic_write_moqint(moq->version, max_request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("requests_blocked");
		json_object_set_new(message, "maximum_request_id", json_integer(max_request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_request_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUEST_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUEST_OK);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_REQUEST_OK, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_request_error(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t error, const char *reason, uint64_t retry_interval) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUEST_ERROR, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUEST_ERROR);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, error, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, retry_interval, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_moqint(moq->version, reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_error");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		json_object_set_new(message, "retry_interval", json_integer(retry_interval));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t required_id_delta, imquic_moq_namespace *track_namespace, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			 (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH_NAMESPACE);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_PUBLISH_NAMESPACE, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "publish_namespace");
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace");
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_done");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024) || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_moqint(moq->version, reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_cancel");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_PUBLISH);
	offset += imquic_write_moqint(moq->version, track_alias, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_PUBLISH, parameters, &bytes[offset], blen-offset, &params_num);
	/* Check if there are properties to encode */
	uint8_t properties[256];
	size_t properties_len = 0;
	properties_len = imquic_moq_build_properties(moq->version, track_properties, properties, sizeof(properties));
	offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, properties_len);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "publish");
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace");
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 2 || (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_OK);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_PUBLISH_OK, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_SUBSCRIBE);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_SUBSCRIBE, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "subscribe");
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace");
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_request_update(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t sub_request_id, uint64_t required_id_delta, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUEST_UPDATE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUEST_UPDATE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		offset += imquic_write_moqint(moq->version, sub_request_id, &bytes[offset], blen-offset);
	} else {
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_REQUEST_UPDATE, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			json_object_set_new(message, "subscription_request_id", json_integer(sub_request_id));
		} else {
			json_object_set_new(message, "required_request_id_delta", json_integer(sub_request_id));
		}
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id,
		uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties) {
	if(bytes == NULL || blen < 3 || (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_OK);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, track_alias, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_SUBSCRIBE_OK, parameters, &bytes[offset], blen-offset, &params_num);
	/* Check if there are properties to encode */
	uint8_t properties[256];
	size_t properties_len = 0;
	properties_len = imquic_moq_build_properties(moq->version, track_properties, properties, sizeof(properties));
	offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, properties_len);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 2) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_UNSUBSCRIBE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_done(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_pub_done_code status, uint64_t streams_count, const char *reason) {
	if(bytes == NULL || blen < 5 || (reason && strlen(reason) > 1024) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_DONE);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, status, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, streams_count, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_moqint(moq->version, reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_done");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t required_id_delta, imquic_moq_namespace *track_namespace,
		imquic_moq_subscribe_namespace_options subscribe_options, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE);
	offset += imquic_write_moqint(moq->version, subscribe_options, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_SUBSCRIBE_NAMESPACE, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "subscribe_namespace");
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace_prefix");
		json_object_set_new(message, "subscribe_options", json_integer(subscribe_options));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq_stream->stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_namespace(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_NAMESPACE);
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_NAMESPACE);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("namespace");
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace_suffix");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq_stream->stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_namespace_done(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_NAMESPACE_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_NAMESPACE_DONE);
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_NAMESPACE_DONE);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("namespace_done");
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace_suffix");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq_stream->stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_blocked(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace, imquic_moq_name *track_name) {
	if(bytes == NULL || blen < 1 || moq_stream == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_NAMESPACE_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_BLOCKED);
	/* FIXME A tuple of size 0 is allowed here, this macro needs fixing */
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH_BLOCKED);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_PUBLISH_BLOCKED);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_blocked");
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace_suffix");
		imquic_qlog_moq_message_add_track(message, track_name);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq_stream->stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, imquic_moq_fetch_type type,
		uint64_t request_id, uint64_t required_id_delta, uint64_t joining_request_id, uint64_t preceding_group_offset,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name,
		imquic_moq_location_range *range, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (range == NULL && type == IMQUIC_MOQ_FETCH_STANDALONE) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH, moq->version));
		return 0;
	}
	if(type == IMQUIC_MOQ_FETCH_STANDALONE &&
			(track_namespace == NULL || track_name == NULL || (track_name->buffer == NULL && track_name->length > 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH, moq->version));
		return 0;
	}
	if(type != IMQUIC_MOQ_FETCH_STANDALONE && type != IMQUIC_MOQ_FETCH_JOINING_RELATIVE && type != IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, required_id_delta, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, type, &bytes[offset], blen-offset);
	if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
		IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_FETCH);
		IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_FETCH);
		offset += imquic_write_moqint(moq->version, range->start.group, &bytes[offset], blen-offset);
		offset += imquic_write_moqint(moq->version, range->start.object, &bytes[offset], blen-offset);
		offset += imquic_write_moqint(moq->version, range->end.group, &bytes[offset], blen-offset);
		offset += imquic_write_moqint(moq->version, range->end.object, &bytes[offset], blen-offset);
	} else {
		offset += imquic_write_moqint(moq->version, joining_request_id, &bytes[offset], blen-offset);
		offset += imquic_write_moqint(moq->version, preceding_group_offset, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_FETCH, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "fetch");
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "required_request_id_delta", json_integer(required_id_delta));
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace");
			imquic_qlog_moq_message_add_track(message, track_name);
			json_object_set_new(message, "start_group", json_integer(range->start.group));
			json_object_set_new(message, "start_object", json_integer(range->start.object));
			json_object_set_new(message, "end_group", json_integer(range->end.group));
			json_object_set_new(message, "end_object", json_integer(range->end.object));
		} else {
			json_object_set_new(message, "joining_request_id", json_integer(joining_request_id));
			json_object_set_new(message, "preceding_group_offset", json_integer(preceding_group_offset));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1 || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_CANCEL, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH_CANCEL);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_cancel");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_ok(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t request_id,
		uint8_t end_of_track, imquic_moq_location *end_location, imquic_moq_request_parameters *parameters, GList *track_properties) {
	if(bytes == NULL || blen < 1 || (moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH_OK);
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	bytes[offset] = end_of_track;
	offset++;
	offset += imquic_write_moqint(moq->version, end_location->group, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, end_location->object, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_FETCH_OK, parameters, &bytes[offset], blen-offset, &params_num);
	/* Check if there are properties to encode */
	uint8_t properties[256];
	size_t properties_len = 0;
	properties_len = imquic_moq_build_properties(moq->version, track_properties, properties, sizeof(properties));
	offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, properties_len);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		if(moq->version <= IMQUIC_MOQ_VERSION_16)
			json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(end_location->group));
		json_object_set_new(message, "largest_object_id", json_integer(end_location->object));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_qlog_moq_message_add_properties(message, track_properties, "track_properties");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && moq_stream == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_TRACK_STATUS);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_TRACK_STATUS);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_TRACK_STATUS);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, IMQUIC_MOQ_TRACK_STATUS, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		if(moq_stream != NULL)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, TRUE, moq_stream->stream_id, "track_status");
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace, "track_namespace");
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog,
			(moq_stream ? moq_stream->stream_id : moq->control_stream_id), bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, const char *new_session_uri, uint64_t timeout) {
	if(bytes == NULL || blen < 1 || (new_session_uri && strlen(new_session_uri) > 8192)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_GOAWAY, moq->version));
		return 0;
	}
	if(!moq->is_server && new_session_uri != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: clients can't send a new session URI\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_GOAWAY, moq->version));
		return 0;
	}
	size_t uri_len = new_session_uri ? strlen(new_session_uri) : 0;
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_GOAWAY);
	offset += imquic_write_moqint(moq->version, uri_len, &bytes[offset], blen-offset);
	if(uri_len > 0) {
		memcpy(&bytes[offset], new_session_uri, uri_len);
		offset += uri_len;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_17)
		offset += imquic_write_moqint(moq->version, timeout, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("goaway");
		imquic_qlog_event_add_raw(message, "new_session_uri", (uint8_t *)new_session_uri, uri_len);
		if(moq->version >= IMQUIC_MOQ_VERSION_17)
			json_object_set_new(message, "timeout", json_integer(timeout));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t track_alias,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint8_t priority,
		uint8_t *payload, size_t plen, uint8_t *properties, size_t prlen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM, moq->version));
		return 0;
	}
	/* TODO Involve EOG */
	gboolean has_prop = (properties != NULL && prlen > 0), is_eog = FALSE;
	gboolean has_oid = (object_id != 0);
	gboolean has_priority = TRUE;	/* FIXME */
	imquic_moq_datagram_message_type dtype = imquic_moq_datagram_message_type_return(moq->version,
		TRUE,			/* Payload */
		has_prop,		/* Properties */
		is_eog,			/* End of Group */
		has_oid,		/* Object ID */
		has_priority);	/* Priority */
	size_t offset = imquic_write_moqint(moq->version, dtype, bytes, blen);
	offset += imquic_write_moqint(moq->version, track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, group_id, &bytes[offset], blen-offset);
	if(has_oid)
		offset += imquic_write_moqint(moq->version, object_id, &bytes[offset], blen-offset);
	if(has_priority) {
		bytes[offset] = priority;
		offset++;
	}
	if(has_prop)
		offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, prlen);
	if(payload != NULL && plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t track_alias, uint64_t group_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *properties, size_t prlen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version));
		return 0;
	}
	gboolean has_prop = (properties != NULL && prlen > 0);
	gboolean has_oid = (object_id != 0);
	gboolean has_priority = TRUE;	/* FIXME */
	imquic_moq_datagram_message_type dtype = imquic_moq_datagram_message_type_return(moq->version,
		FALSE,			/* Status */
		has_prop,		/* Properties */
		FALSE,			/* End of Group */
		has_oid,		/* Object ID */
		has_priority);	/* Priority */
	size_t offset = imquic_write_moqint(moq->version, dtype, bytes, blen);
	offset += imquic_write_moqint(moq->version, track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, group_id, &bytes[offset], blen-offset);
	if(has_oid)
		offset += imquic_write_moqint(moq->version, object_id, &bytes[offset], blen-offset);
	if(has_priority) {
		bytes[offset] = priority;
		offset++;
	}
	if(has_prop)
		offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, prlen);
	offset += imquic_write_moqint(moq->version, object_status, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t track_alias, uint64_t group_id, uint64_t subgroup_id, uint8_t priority) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	imquic_moq_data_message_type dtype = moq_stream->type;
	gboolean has_sg = FALSE, has_priority = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, &has_sg, NULL, NULL, NULL, &has_priority, NULL);
	size_t offset = imquic_write_moqint(moq->version, dtype, bytes, blen);
	offset += imquic_write_moqint(moq->version, track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, group_id, &bytes[offset], blen-offset);
	if(has_sg)
		offset += imquic_write_moqint(moq->version, subgroup_id, &bytes[offset], blen-offset);
	if(has_sg) {
		bytes[offset] = priority;
		offset++;
	}
	return offset;
}

size_t imquic_moq_add_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t object_id, uint64_t object_status,
		uint8_t *payload, size_t plen, uint8_t *properties, size_t prlen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_moqint(moq->version, object_id, &bytes[offset], blen-offset);
	/* TODO We can optimize this by only doing it once, when we parse the header */
	/* TODO Involve EOG too */
	gboolean has_prop = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, NULL, NULL, &has_prop, NULL, NULL, NULL);
	if(has_prop)
		offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, prlen);
	if(payload == NULL)
		plen = 0;
	offset += imquic_write_moqint(moq->version, plen, &bytes[offset], blen-offset);
	if(plen == 0)
		offset += imquic_write_moqint(moq->version, object_status, &bytes[offset], blen-offset);
	if(plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_fetch_header(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version));
		return 0;
	}
	size_t offset = imquic_write_moqint(moq->version, IMQUIC_MOQ_FETCH_HEADER, bytes, blen);
	offset += imquic_write_moqint(moq->version, request_id, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_fetch_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t flags, uint64_t group_id, uint64_t subgroup_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *payload, size_t plen, uint8_t *properties, size_t prlen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version));
		return 0;
	}
	size_t offset = 0;
	imquic_moq_fetch_subgroup_type subgroup_type = IMQUIC_MOQ_FETCH_SUBGROUP_ID;
	gboolean has_oid = FALSE, has_group = FALSE, has_priority = FALSE, has_prop = FALSE, is_datagram = FALSE;
	imquic_moq_parse_fetch_serialization_flags(moq->version, flags,
		&subgroup_type, &has_oid, &has_group, &has_priority, &has_prop, &is_datagram, NULL, NULL, NULL);
	offset += imquic_write_moqint(moq->version, flags, &bytes[offset], blen-offset);
	if(has_group)
		offset += imquic_write_moqint(moq->version, group_id, &bytes[offset], blen-offset);
	if(subgroup_type == IMQUIC_MOQ_FETCH_SUBGROUP_ID && !is_datagram)
		offset += imquic_write_moqint(moq->version, subgroup_id, &bytes[offset], blen-offset);
	if(has_oid)
		offset += imquic_write_moqint(moq->version, object_id, &bytes[offset], blen-offset);
	if(has_priority) {
		bytes[offset] = priority;
		offset++;
	}
	if(has_prop)
		offset += imquic_moq_add_properties(moq, &bytes[offset], blen-offset, properties, prlen);
	if(payload == NULL)
		plen = 0;
	offset += imquic_write_moqint(moq->version, plen, &bytes[offset], blen-offset);
	if(plen == 0)
		offset += imquic_write_moqint(moq->version, object_status, &bytes[offset], blen-offset);
	if(plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_properties(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint8_t *properties, size_t prlen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't serialize MoQ properties: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	if(properties == NULL || prlen == 0) {
		properties = NULL;
		prlen = 0;
	}
	size_t offset = 0;
	offset += imquic_write_moqint(moq->version, prlen, &bytes[offset], blen-offset);
	if(properties != NULL && prlen > 0) {
		memcpy(&bytes[offset], properties, prlen);
		offset += prlen;
	}
	return offset;
}

/* Adding and parsing setup options and parameters to a buffer */
size_t imquic_moq_setup_option_add_int(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, uint64_t number) {
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric setup option %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(param % 2 != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric setup option %"SCNu64": type is odd\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(prev > param) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric setup option %"SCNu64": previous setup option %"SCNu64" for delta-encoding is larger\n",
			imquic_get_connection_name(moq->conn), param, prev);
		return 0;
	}
	param -= prev;
	size_t offset = imquic_write_moqint(moq->version, param, &bytes[0], blen);
	offset += imquic_write_moqint(moq->version, number, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_setup_option_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0 || (buflen > 0 && buf == 0) || buflen > UINT16_MAX) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data setup option %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(param % 2 != 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data setup option %"SCNu64": type is even\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(prev > param) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data setup option %"SCNu64": previous setup option %"SCNu64" for delta-encoding is larger\n",
			imquic_get_connection_name(moq->conn), param, prev);
		return 0;
	}
	param -= prev;
	size_t offset = imquic_write_moqint(moq->version, param, &bytes[0], blen);
	offset += imquic_write_moqint(moq->version, buflen, &bytes[offset], blen);
	if(buflen > 0) {
		memcpy(&bytes[offset], buf, buflen);
		offset += buflen;
	}
	return offset;
}

size_t imquic_moq_parse_setup_option(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_setup_options *params, uint64_t *param_type, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ setup parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
	offset += length;
	type += *param_type;
	*param_type = type;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_setup_option_type_str(type), type);
	uint64_t len = 0;
	if(type % 2 == 1) {
		len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ setup parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
	}
	/* Update the parsed parameter */
	if(type == IMQUIC_MOQ_SETUP_OPTION_PATH) {
		params->path_set = TRUE;
		if(len > 0)
			g_snprintf(params->path, sizeof(params->path), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->path);
	} else if(type == IMQUIC_MOQ_SETUP_OPTION_MAX_REQUEST_ID) {
		params->max_request_id = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_request_id_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		len = length;
	} else if(type == IMQUIC_MOQ_SETUP_OPTION_MAX_AUTH_TOKEN_CACHE_SIZE) {
		params->max_auth_token_cache_size = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_auth_token_cache_size_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		len = length;
	} else if(type == IMQUIC_MOQ_SETUP_OPTION_AUTHORIZATION_TOKEN) {
		params->auth_token_set = TRUE;
		size_t auth_len = len;
		if(auth_len > sizeof(params->auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), len, sizeof(params->auth_token));
			auth_len = sizeof(params->auth_token);
		}
		memcpy(params->auth_token, &bytes[offset], auth_len);
		params->auth_token_len = auth_len;
		char ai_str[513];
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %s\n",
			imquic_get_connection_name(moq->conn), imquic_hex_str(&bytes[offset], auth_len, ai_str, sizeof(ai_str)));
	} else if(type == IMQUIC_MOQ_SETUP_OPTION_AUTHORITY) {
		params->authority_set = TRUE;
		if(len > 0)
			g_snprintf(params->authority, sizeof(params->authority), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->authority);
	} else if(type == IMQUIC_MOQ_SETUP_OPTION_MOQT_IMPLEMENTATION) {
		params->moqt_implementation_set = TRUE;
		if(len > 0)
			g_snprintf(params->moqt_implementation, sizeof(params->moqt_implementation), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->moqt_implementation);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_17 && imquic_moq_is_grease(type)) {
		/* This is a GREASE setup option, just skip it */
		if(type % 2 == 0) {
			(void)imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
			len = length;
		}
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter '%"SCNu64"'\n",
			imquic_get_connection_name(moq->conn), type);
		params->unknown = TRUE;
		if(type % 2 == 0)
			len = length;
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parameter_add_varint(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, uint64_t number) {
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ varint parameter %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_16 && param % 2 != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ varint parameter %"SCNu64": type is odd\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(prev > param) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ varint parameter %"SCNu64": previous parameter %"SCNu64" for delta-encoding is larger\n",
			imquic_get_connection_name(moq->conn), param, prev);
		return 0;
	}
	param -= prev;
	size_t offset = 0;
	offset += imquic_write_moqint(moq->version, param, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, number, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_parameter_add_uint8(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, uint8_t number) {
	if(moq->version <= IMQUIC_MOQ_VERSION_16)
		return imquic_moq_parameter_add_varint(moq, bytes, blen, param, prev, number);
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ byte parameter %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(prev > param) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ byte parameter %"SCNu64": previous parameter %"SCNu64" for delta-encoding is larger\n",
			imquic_get_connection_name(moq->conn), param, prev);
		return 0;
	}
	param -= prev;
	size_t offset = imquic_write_moqint(moq->version, param, bytes, blen);
	bytes[offset] = number;
	return offset+1;
}

size_t imquic_moq_parameter_add_location(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, imquic_moq_location *location) {
	if(bytes == NULL || blen == 0 || location == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ location parameter %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_16) {
		uint8_t temp[40];
		size_t tlen = sizeof(temp);
		size_t toffset = imquic_write_moqint(moq->version, location->group, temp, tlen);
		toffset += imquic_write_moqint(moq->version, location->object, &temp[toffset], tlen-toffset);
		return imquic_moq_parameter_add_data(moq, bytes, blen, param, prev, temp, toffset);
	}
	param -= prev;
	size_t offset = 0;
	offset += imquic_write_moqint(moq->version, param, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, location->group, &bytes[offset], blen-offset);
	offset += imquic_write_moqint(moq->version, location->object, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_parameter_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t param, uint64_t prev, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0 || (buflen > 0 && buf == 0) || buflen > UINT16_MAX) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %"SCNu64": invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_16 && param % 2 != 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %"SCNu64": type is even\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(prev > param) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %"SCNu64": previous parameter %"SCNu64" for delta-encoding is larger\n",
			imquic_get_connection_name(moq->conn), param, prev);
		return 0;
	}
	param -= prev;
	size_t offset = imquic_write_moqint(moq->version, param, &bytes[0], blen);
	offset += imquic_write_moqint(moq->version, buflen, &bytes[offset], blen);
	if(buflen > 0) {
		memcpy(&bytes[offset], buf, buflen);
		offset += buflen;
	}
	return offset;
}

size_t imquic_moq_parse_request_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_request_parameters *params, uint64_t *param_type, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ subscribe parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
	offset += length;
	type += *param_type;
	*param_type = type;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_parameter_type_str(type, moq->version), type);
	uint64_t len = 0;
	/* Parameters are formatted differently, depending on the version:
	 * older versions used TLV, while newer versions have hardcoded
	 * mappings between known parameters and the types to parse them as.
	 * As such, we only read the length if it's an older version and
	 * TLS tells us so, or for newer versions for params that need it */
	if((moq->version <= IMQUIC_MOQ_VERSION_16 && type % 2 == 1) ||
			(moq->version >= IMQUIC_MOQ_VERSION_17 && (type == IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN ||
				type == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER))) {
		len = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
	}
	/* Update the parsed parameter */
	if(type == IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN) {
		params->auth_token_set = TRUE;
		size_t auth_len = len;
		if(auth_len > sizeof(params->auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), len, sizeof(params->auth_token));
			auth_len = sizeof(params->auth_token);
		}
		memcpy(params->auth_token, &bytes[offset], auth_len);
		params->auth_token_len = auth_len;
		char ai_str[513];
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %s\n",
			imquic_get_connection_name(moq->conn), imquic_hex_str(&bytes[offset], auth_len, ai_str, sizeof(ai_str)));
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT) {
		params->delivery_timeout = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || params->delivery_timeout == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->delivery_timeout_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->delivery_timeout);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_RENDEZVOUS_TIMEOUT) {
		params->rendezvous_timeout = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || params->rendezvous_timeout == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->rendezvous_timeout_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->rendezvous_timeout);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY) {
		uint64_t subscriber_priority = 0;
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			subscriber_priority = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || subscriber_priority > 255, NULL, 0, 0, "Broken MoQ request parameter");
		} else {
			subscriber_priority = bytes[offset];
			length = 1;
		}
		params->subscriber_priority = subscriber_priority;
		params->subscriber_priority_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->subscriber_priority);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER) {
		uint64_t group_order = 0;
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			group_order = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || group_order > 255, NULL, 0, 0, "Broken MoQ request parameter");
		} else {
			group_order = bytes[offset];
			length = 1;
		}
		params->group_order = group_order;
		params->group_order_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64" (%s)\n",
			imquic_get_connection_name(moq->conn), group_order, imquic_moq_group_order_str(group_order));
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER) {
		uint8_t *tmp = &bytes[offset];
		size_t toffset = 0, tlen = len;
		params->subscription_filter.type = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		toffset += length;
		if(params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			params->subscription_filter.start_location.group = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			toffset += length;
			params->subscription_filter.start_location.object = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			toffset += length;
		}
		if(params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			params->subscription_filter.end_group = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			/* The End group property is a delta, starting from v17, but
			 * we expose the full actual value to the application */
			if(moq->version >= IMQUIC_MOQ_VERSION_17)
				params->subscription_filter.end_group += params->subscription_filter.start_location.group;
		}
		params->subscription_filter_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %d\n",
			imquic_get_connection_name(moq->conn), params->subscription_filter.type);
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_EXPIRES) {
		params->expires = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->expires_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->expires);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT) {
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			uint8_t *tmp = &bytes[offset];
			size_t toffset = 0, tlen = len;
			params->largest_object.group = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			toffset += length;
			params->largest_object.object = imquic_read_moqint(moq->version, &tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		} else {
			params->largest_object.group = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			len = length;
			params->largest_object.object = imquic_read_moqint(moq->version, &bytes[offset+length], blen-offset-length, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			len += length;
		}
		params->largest_object_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64" / %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->largest_object.group, params->largest_object.object);
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_FORWARD) {
		uint64_t forward = 0;
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			forward = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || forward > 255, NULL, 0, 0, "Broken MoQ request parameter");
		} else {
			forward = bytes[offset];
			length = 1;
		}
		params->forward = (forward > 0);
		params->forward_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->forward);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST) {
		params->new_group_request = imquic_read_moqint(moq->version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->new_group_request_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->new_group_request);
		len = length;
	} else {
		if(moq->version <= IMQUIC_MOQ_VERSION_16) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), type);
			if(type % 2 == 0)
				len = length;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Unsupported parameter %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), type);
			if(error)
				*error = IMQUIC_MOQ_PROTOCOL_VIOLATION;
			return 0;
		}
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

/* Version getter */
imquic_moq_version imquic_moq_get_version(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_version version = moq->version;
	/* Done */
	imquic_mutex_unlock(&moq->mutex);
	imquic_refcount_decrease(&moq->ref);
	return version;
}

/* Connection auth configuration */
int imquic_moq_set_connection_auth(imquic_connection *conn, uint8_t *auth, size_t authlen) {
	if(auth == NULL || authlen == 0) {
		auth = NULL;
		authlen = 0;
	}
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(conn->is_server || moq == NULL || moq->auth_set) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(!moq->auth_set) {
		moq->auth = auth;
		moq->authlen = authlen;
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

/* Maximum Request ID management */
int imquic_moq_set_max_request_id(imquic_connection *conn, uint64_t max_request_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->version >= IMQUIC_MOQ_VERSION_17 ||
			max_request_id == 0 || moq->local_max_request_id >= max_request_id) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	moq->local_max_request_id = max_request_id;
	imquic_mutex_unlock(&moq_mutex);
	max_request_id--;
	if(g_atomic_int_get(&moq->connected)) {
		/* Already connected, send a MAX_REQUEST_ID */
		uint8_t buffer[20];
		size_t blen = sizeof(buffer);
		size_t ms_len = imquic_moq_add_max_request_id(moq, buffer, blen, max_request_id);
		imquic_connection_send_on_stream(conn, moq->control_stream_id,
			buffer, ms_len, FALSE);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;

}

uint64_t imquic_moq_get_next_request_id(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return 0;
	}
	uint64_t next = moq->next_request_id;
	imquic_mutex_unlock(&moq_mutex);
	return next;
}

const char *imquic_moq_get_remote_implementation(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return 0;
	}
	const char *implementation = (const char *)moq->peer_implementation;
	imquic_mutex_unlock(&moq_mutex);
	return implementation;
}

/* Properties management */
GList *imquic_moq_parse_properties(imquic_moq_version version, uint8_t *properties, size_t prlen) {
	if(properties == NULL || prlen == 0)
		return NULL;
	GList *props = NULL;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t last_id = 0;
	/* Parse properties */
	while(prlen-offset > 0) {
		uint64_t prop_type = imquic_read_moqint(version, &properties[offset], prlen-offset, &length);
		if(length == 0 || length >= prlen-offset) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken properties\n");
			g_list_free_full(props, (GDestroyNotify)imquic_moq_property_free);
			return 0;
		}
		prop_type += last_id;
		last_id = prop_type;
		offset += length;
		if(prop_type % 2 == 0) {
			/* Even types are followed by a numeric value */
			uint64_t prop_val = imquic_read_moqint(version, &properties[offset], prlen-offset, &length);
			if(length == 0 || length > prlen-offset) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken properties\n");
				g_list_free_full(props, (GDestroyNotify)imquic_moq_property_free);
				return 0;
			}
			offset += length;
			imquic_moq_property *property = g_malloc0(sizeof(imquic_moq_property));
			property->id = prop_type;
			property->value.number = prop_val;
			props = g_list_prepend(props, property);
		} else {
			/* Odd typed are followed by a length and a value */
			uint64_t prop_len = imquic_read_moqint(version, &properties[offset], prlen-offset, &length);
			if(length == 0 || length >= prlen-offset || prop_len >= prlen-offset) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken properties\n");
				g_list_free_full(props, (GDestroyNotify)imquic_moq_property_free);
				return 0;
			}
			/* TODO A length larger than UINT16_MAX should be a protocol violation error */
			//~ IMQUIC_MOQ_CHECK_ERR(prop_len > UINT16_MAX, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Key-Value-Pair length");
			offset += length;
			imquic_moq_property *property = g_malloc0(sizeof(imquic_moq_property));
			property->id = prop_type;
			if(prop_len > 0) {
				property->value.data.length = prop_len;
				property->value.data.buffer = g_malloc(prop_len);
				memcpy(property->value.data.buffer, &properties[offset], prop_len);
			}
			props = g_list_prepend(props, property);
			offset += prop_len;
		}
	}
	return g_list_reverse(props);
}

static int imquic_moq_property_type_sort(imquic_moq_property *a, imquic_moq_property *b) {
	if(!a && !b)
		return 0;
	else if(!b || a->id < b->id)
		return -1;
	else if(!a || a->id > b->id)
		return 1;
	return 0;
}

size_t imquic_moq_build_properties(imquic_moq_version version, GList *properties, uint8_t *bytes, size_t blen) {
	if(properties == NULL || bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	/* Starting from v16, properties are encoded with the type delta-encoded,
	 * which means we need to sort them all in increasing type order */
	GList *ordered = g_list_sort(g_list_copy(properties), (GCompareFunc)imquic_moq_property_type_sort);
	GList *temp = ordered;
	uint64_t last_id = 0;
	while(temp) {
		imquic_moq_property *prop = (imquic_moq_property *)temp->data;
		offset += imquic_write_moqint(version, (prop->id - last_id), &bytes[offset], blen-offset);
		last_id = prop->id;
		if(prop->id % 2 == 0) {
			offset += imquic_write_moqint(version, prop->value.number, &bytes[offset], blen-offset);
		} else {
			offset += imquic_write_moqint(version, prop->value.data.length, &bytes[offset], blen-offset);
			if(prop->value.data.length > 0) {
				memcpy(&bytes[offset], prop->value.data.buffer, prop->value.data.length);
				offset += prop->value.data.length;
			}
		}
		temp = temp->next;
	}
	g_list_free(ordered);
	return offset;
}

/* Auth token management */
int imquic_moq_parse_auth_token(imquic_moq_version version, uint8_t *bytes, size_t blen, imquic_moq_auth_token *token) {
	if(bytes == NULL || blen == 0 || token == NULL)
		return -1;
	memset(token, 0, sizeof(*token));
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t alias_type = imquic_read_moqint(version, &bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
	offset += length;
	if(alias_type != IMQUIC_MOQ_AUTH_TOKEN_DELETE && alias_type != IMQUIC_MOQ_AUTH_TOKEN_REGISTER &&
			alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_ALIAS && alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid alias type %"SCNu64"\n", alias_type);
		return -1;
	}
	token->alias_type = alias_type;
	if(alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		uint64_t token_alias = imquic_read_moqint(version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
		offset += length;
		token->token_alias_set = TRUE;
		token->token_alias = token_alias;
	}
	if(alias_type == IMQUIC_MOQ_AUTH_TOKEN_REGISTER || alias_type == IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		uint64_t token_type = imquic_read_moqint(version, &bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
		offset += length;
		token->token_type_set = TRUE;
		token->token_type = token_type;
		token->token_value.length = blen-offset;
		token->token_value.buffer = (token->token_value.length > 0 ? &bytes[offset] : NULL);
	}
	return 0;
}

size_t imquic_moq_build_auth_token(imquic_moq_version version, imquic_moq_auth_token *token, uint8_t *bytes, size_t blen) {
	if(token == NULL || bytes == NULL || blen == 0)
		return 0;
	if(token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_DELETE && token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_REGISTER &&
			token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_ALIAS && token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid alias type %d\n", token->alias_type);
		return 0;
	}
	size_t offset = imquic_write_moqint(version, token->alias_type, bytes, blen);
	if(token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		if(!token->token_alias_set) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Token alias is required when using %s\n", imquic_moq_auth_token_alias_type_str(token->alias_type));
			return 0;
		}
		offset += imquic_write_moqint(version, token->token_alias, &bytes[offset], blen-offset);
	}
	if(token->alias_type == IMQUIC_MOQ_AUTH_TOKEN_REGISTER || token->alias_type == IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		if(!token->token_type_set) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Token type is required when using %s\n", imquic_moq_auth_token_alias_type_str(token->alias_type));
			return 0;
		}
		offset += imquic_write_moqint(version, token->token_type, &bytes[offset], blen-offset);
		if(token->token_value.buffer && token->token_value.length > 0) {
			memcpy(&bytes[offset], token->token_value.buffer, token->token_value.length);
			offset += token->token_value.length;
		}
	}
	return offset;
}

/* Namespaces and subscriptions */
int imquic_moq_publish_namespace(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_PUBLISH_NAMESPACE));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_PUBLISH_NAMESPACE;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_publish_namespace(moq, moq_stream, buffer, blen, request_id, required_id_delta, tns, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, ann_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_publish_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_OK/ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH_NAMESPACE || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_request_ok(moq, moq_stream, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, ann_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_publish_namespace(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_OK/ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH_NAMESPACE || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, ann_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish_namespace_done(imquic_connection *conn, uint64_t request_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if we have a STREAM to close */
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		/* On newer versions of MoQ, requests uses a dedicated
		 * bidirectional STREAM, so we simply close the STREAM */
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH_NAMESPACE || !moq_stream->request_sender ||
				(moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT)) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		/* Reset the STREAM */
		imquic_connection_reset_stream(moq->conn, moq_stream->stream_id, IMQUIC_MOQ_RESET_CANCELLED);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return 0;
	}
	/* If we're here,we're sending the legacy PUBLISH_NAMESPACE_DONE */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_publish_namespace_done(moq, buffer, blen, request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, ann_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta, imquic_moq_namespace *tns, imquic_moq_name *tn,
		uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Track this subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, track_alias);
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_PUBLISH));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_PUBLISH;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_publish(moq, moq_stream, buffer, blen,
		request_id, required_id_delta, tns, tn, track_alias, parameters, track_properties);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(parameters && parameters->subscription_filter_set && parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE &&
			parameters->subscription_filter.end_group > 0 && parameters->subscription_filter.start_location.group > parameters->subscription_filter.end_group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn),
			parameters->subscription_filter.end_group,
			parameters->subscription_filter.start_location.group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the PUBLISH_OK responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_publish_ok(moq, moq_stream, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_publish(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH_NAMESPACE || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(parameters && parameters->subscription_filter_set && parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE &&
			parameters->subscription_filter.end_group > 0 && parameters->subscription_filter.start_location.group > parameters->subscription_filter.end_group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn),
			parameters->subscription_filter.end_group,
			parameters->subscription_filter.start_location.group);
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_SUBSCRIBE));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_SUBSCRIBE;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_subscribe(moq, moq_stream, buffer, blen,
		request_id, required_id_delta, tns, tn, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_request_parameters *parameters, GList *track_properties) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the SUBSCRIBE_OK responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &request_id);
	if(moq_sub != NULL) {
		/* Track this subscription */
		moq_sub->track_alias = track_alias;
		g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
	}
	imquic_mutex_unlock(&moq->mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_subscribe_ok(moq, moq_stream, buffer, blen,
		request_id, track_alias, parameters, track_properties);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_update_request(imquic_connection *conn, uint64_t request_id, uint64_t sub_request_id, uint64_t required_id_delta, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(parameters && parameters->subscription_filter_set && parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE &&
			parameters->subscription_filter.end_group > 0 && parameters->subscription_filter.start_location.group > parameters->subscription_filter.end_group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn),
			parameters->subscription_filter.end_group,
			parameters->subscription_filter.start_location.group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_REQUEST_UPDATE));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_UPDATE responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &sub_request_id);
		if(moq_stream == NULL || moq_stream->request_type == 0 || !moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->update_request_id = request_id;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t su_len = imquic_moq_add_request_update(moq, moq_stream, buffer, blen,
		request_id, sub_request_id, required_id_delta, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, su_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_request_update(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check which request this update refers to */
	imquic_mutex_lock(&moq->mutex);
	uint64_t *rid = g_hash_table_lookup(moq->update_requests, &request_id);
	if(rid == NULL) {
		imquic_mutex_unlock(&moq->mutex);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		return -1;
	}
	uint64_t sub_request_id = *rid;
	g_hash_table_remove(moq->update_requests, &request_id);
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_OK responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &sub_request_id);
		if(moq_stream == NULL || moq_stream->request_type == 0 || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_ok(moq, moq_stream, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_request_update(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check which request this update refers to */
	imquic_mutex_lock(&moq->mutex);
	uint64_t *rid = g_hash_table_lookup(moq->update_requests, &request_id);
	if(rid == NULL) {
		imquic_mutex_unlock(&moq->mutex);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		return -1;
	}
	uint64_t sub_request_id = *rid;
	g_hash_table_remove(moq->update_requests, &request_id);
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &sub_request_id);
		if(moq_stream == NULL || moq_stream->request_type == 0 || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		/* FIXME We mark the state as OK, as this is an update */
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if we have a STREAM to close */
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		/* On newer versions of MoQ, requests uses a dedicated
		 * bidirectional STREAM, so we simply close the STREAM */
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE || !moq_stream->request_sender) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		/* Send a STOP_SENDING */
		imquic_connection_stop_sending_stream(moq->conn, moq_stream->stream_id, IMQUIC_MOQ_RESET_CANCELLED);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return 0;
	}
	/* If we're here,we're sending the legacy UNSUBSCRIBE */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_unsubscribe(moq, buffer, blen, request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Find the subscription to compute the streams count */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &request_id);
	if(moq_sub == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
			imquic_get_connection_name(conn), request_id);
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_increase(&moq->ref);
		return -1;
	}
	uint64_t streams_count = moq_sub->streams_count;
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the PUBLISH_DONE responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_PUBLISH || !moq_stream->request_sender ||
				(moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT)) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sd_len = imquic_moq_add_publish_done(moq, moq_stream, buffer, blen,
		request_id, status_code, streams_count, reason);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sd_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe_namespace(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *tns, imquic_moq_subscribe_namespace_options subscribe_options, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = tns;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
				imquic_get_connection_name(moq->conn));
			imquic_mutex_unlock(&moq_mutex);
			return -1;
		}
		tns_num++;
		temp = temp->next;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callback if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v16, SUBSCRIBE_NAMESPACE goes on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = g_malloc0(sizeof(imquic_moq_stream));
	imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
	moq_stream->request_type = IMQUIC_MOQ_SUBSCRIBE_NAMESPACE;
	moq_stream->request_id = request_id;
	moq_stream->request_sender = TRUE;
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
	imquic_mutex_unlock(&moq->mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_subscribe_namespace(moq, moq_stream, buffer, blen, request_id, required_id_delta, tns, subscribe_options, parameters);
	/* Track the request, and map it to the dedicated bidirectional STREAM */
	moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
	moq_stream->request_id = request_id;
	moq_stream->namespace_prefix = moq_stream->last_tuple = tns ? imquic_moq_namespace_duplicate(tns) : g_malloc0(sizeof(imquic_moq_namespace));
	while(moq_stream->last_tuple != NULL && moq_stream->last_tuple->next != NULL)
		moq_stream->last_tuple = moq_stream->last_tuple->next;
	moq_stream->namespace_prefix_size = tns_num;
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
	imquic_mutex_unlock(&moq->mutex);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v16, SUBSCRIBE_NAMESPACE goes on a dedicated
	 * bidirectional STREAM, and the same applies to REQUEST_OK/ERROR */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE || moq_stream->request_sender ||
			moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
			imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
	imquic_mutex_unlock(&moq->mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_ok(moq, moq_stream, buffer, blen, request_id, parameters);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe_namespace(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v16, SUBSCRIBE_NAMESPACE goes on a dedicated
	 * bidirectional STREAM, and the same applies to REQUEST_OK/ERROR */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE || moq_stream->request_sender ||
			moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
			imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
	imquic_mutex_unlock(&moq->mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, sb_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unsubscribe_namespace(imquic_connection *conn, uint64_t request_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* On newer versions of MoQ, SUBSCRIBE_NAMESPACE uses a dedicated
	 * bidirectional STREAM, so unsubscribing is done without sending
	 * any actual message: we simply close the STREAM */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE ||
			!moq_stream->request_sender) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments: no such subscription\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* Reset the STREAM */
	imquic_connection_reset_stream(moq->conn, moq_stream->stream_id, IMQUIC_MOQ_RESET_CANCELLED);
	g_hash_table_remove(moq->streams_by_reqid, &request_id);
	g_hash_table_remove(moq->streams, &moq_stream->stream_id);
	imquic_mutex_unlock(&moq->mutex);
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_notify_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if the request ID exists */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE || moq_stream->request_sender ||
			(moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) ||
			!imquic_moq_namespace_contains(moq_stream->namespace_prefix, tns)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
			imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	imquic_mutex_unlock(&moq->mutex);
	/* We need the track namespace suffix */
	imquic_moq_namespace *tns_suffix = tns;
	for(uint8_t i=0; i<moq_stream->namespace_prefix_size; i++)
		tns_suffix = tns_suffix->next;
	/* Prepare the message */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t nn_len = imquic_moq_add_namespace(moq, moq_stream, buffer, blen, tns_suffix);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, nn_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_notify_namespace_done(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if the request ID exists */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE || moq_stream->request_sender ||
			(moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) ||
			!imquic_moq_namespace_contains(moq_stream->namespace_prefix, tns)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
			imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	imquic_mutex_unlock(&moq->mutex);
	/* We need the track namespace suffix */
	imquic_moq_namespace *tns_suffix = tns;
	for(uint8_t i=0; i<moq_stream->namespace_prefix_size; i++)
		tns_suffix = tns_suffix->next;
	/* Prepare the message */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t nn_len = imquic_moq_add_namespace_done(moq, moq_stream, buffer, blen, tns_suffix);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, nn_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_notify_publish_blocked(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || tn->buffer == 0 || tn->length == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if the request ID exists */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
	if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_SUBSCRIBE_NAMESPACE || moq_stream->request_sender ||
			(moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_OK && moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_UPDATE_SENT) ||
			!imquic_moq_namespace_contains(moq_stream->namespace_prefix, tns)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
			imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
		imquic_mutex_unlock(&moq->mutex);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	imquic_mutex_unlock(&moq->mutex);
	/* We need the track namespace suffix */
	imquic_moq_namespace *tns_suffix = tns;
	for(uint8_t i=0; i<moq_stream->namespace_prefix_size; i++)
		tns_suffix = tns_suffix->next;
	/* Prepare the message */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t nn_len = imquic_moq_add_publish_blocked(moq, moq_stream, buffer, blen, tns_suffix, tn);
	/* Send on the dedicated bidirectional STREAM */
	imquic_connection_send_on_stream(conn, moq_stream->stream_id,
		buffer, nn_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_standalone_fetch(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_location_range *range, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tn == NULL || range == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_FETCH));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_FETCH;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = 0;
	f_len = imquic_moq_add_fetch(moq, moq_stream, buffer, blen,
		IMQUIC_MOQ_FETCH_STANDALONE,
		request_id, required_id_delta,
		0, 0,	/* Ignored, as they're only used for Joining Fetch */
		tns, tn,
		range, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, f_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_joining_fetch(imquic_connection *conn, uint64_t request_id, uint64_t required_id_delta, uint64_t joining_request_id,
		gboolean absolute, uint64_t joining_start, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_FETCH));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_FETCH;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = 0;
	f_len = imquic_moq_add_fetch(moq, moq_stream, buffer, blen,
		(absolute ? IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE : IMQUIC_MOQ_FETCH_JOINING_RELATIVE),
		request_id, required_id_delta, joining_request_id, joining_start,
		NULL, NULL,	/* Ignored, as namespaces/track are only used for Standalone Fetch */
		NULL,	/* Ignored, as the fetch range is only used for Standalone Fetch */
		parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, f_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_fetch(imquic_connection *conn, uint64_t request_id, imquic_moq_location *largest,
		imquic_moq_request_parameters *parameters, GList *track_properties) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || largest == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the FETCH_OK responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_FETCH || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	/* TODO Make other properties configurable */
	size_t f_len = imquic_moq_add_fetch_ok(moq, moq_stream, buffer, blen,
		request_id,
		0,	/* TODO End of track */
		largest,	/* Largest location */
		parameters, track_properties);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, f_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_fetch(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type == 0 || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = imquic_moq_add_request_error(moq, moq_stream, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, f_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_cancel_fetch(imquic_connection *conn, uint64_t request_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = imquic_moq_add_fetch_cancel(moq, buffer, blen, request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, f_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_track_status(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(parameters && parameters->subscription_filter_set && parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE &&
			parameters->subscription_filter.end_group > 0 && parameters->subscription_filter.start_location.group > parameters->subscription_filter.end_group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn),
			parameters->subscription_filter.end_group,
			parameters->subscription_filter.start_location.group);
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	/* Make sure we can send this */
	if(!moq_is_request_id_valid(moq, request_id, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid Request ID\n", imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	moq->next_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Map this request ID to this message type, so that we can trigger
	 * the right application callbac if/when we get a response later on */
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_TRACK_STATUS));
	imquic_mutex_unlock(&moq->mutex);
	/* Starting from v17, requests on a dedicated bidirectional STREAM */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		moq_stream = g_malloc0(sizeof(imquic_moq_stream));
		imquic_connection_new_stream_id(moq->conn, TRUE, &moq_stream->stream_id);
		moq_stream->request_type = IMQUIC_MOQ_TRACK_STATUS;
		moq_stream->request_id = request_id;
		moq_stream->request_sender = TRUE;
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_SENT;
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->streams, imquic_dup_uint64(moq_stream->stream_id), moq_stream);
		g_hash_table_insert(moq->streams_by_reqid, imquic_dup_uint64(request_id), moq_stream);
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_track_status(moq, moq_stream, buffer, blen,
		request_id, tns, tn, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, sb_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_track_status(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_OK responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_TRACK_STATUS || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_OK;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t tso_len = imquic_moq_add_request_ok(moq, moq_stream, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn,
		moq_stream ? moq_stream->stream_id : moq->control_stream_id,
		buffer, tso_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_track_status(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Starting from v17, requests go on a dedicated bidirectional
	 * STREAM, and the same applies to the REQUEST_ERROR responses */
	imquic_moq_stream *moq_stream = NULL;
	if(moq->version >= IMQUIC_MOQ_VERSION_17) {
		imquic_mutex_lock(&moq->mutex);
		moq_stream = g_hash_table_lookup(moq->streams_by_reqid, &request_id);
		if(moq_stream == NULL || moq_stream->request_type != IMQUIC_MOQ_TRACK_STATUS || moq_stream->request_sender ||
				moq_stream->request_state != IMQUIC_MOQ_REQUEST_STATE_SENT) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid request/state (%s)\n",
				imquic_get_connection_name(conn), moq_stream ? imquic_media_stream_request_state_str(moq_stream->request_state) : "No stream");
			imquic_mutex_unlock(&moq->mutex);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq_stream->request_state = IMQUIC_MOQ_REQUEST_STATE_ERROR;
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t tsr_len = imquic_moq_add_request_error(moq, NULL, buffer, blen, request_id, error_code, reason, retry_interval);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, tsr_len, moq_stream ? TRUE : FALSE);
	if(moq_stream != NULL) {
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_remove(moq->streams, &moq_stream->stream_id);
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_requests_blocked(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->version >= IMQUIC_MOQ_VERSION_17) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t r_len = imquic_moq_add_requests_blocked(moq, buffer, blen, moq->max_request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, r_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_goaway(imquic_connection *conn, const char *uri, uint64_t timeout) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t g_len = imquic_moq_add_goaway(moq, buffer, blen, uri, timeout);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, g_len, FALSE);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_send_object(imquic_connection *conn, imquic_moq_object *object) {
	if(object == NULL || object->object_status > IMQUIC_MOQ_END_OF_TRACK) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		return -1;
	}
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if we have data to send */
	gboolean has_payload = (object->payload_len > 0 && object->payload != NULL);
	gboolean valid_pkt = has_payload || (object->object_status != IMQUIC_MOQ_NORMAL_OBJECT);
	/* Check if there are properties to encode */
	uint8_t properties[256];
	size_t properties_len = 0;
	if(object->properties != NULL)
		properties_len = imquic_moq_build_properties(moq->version, object->properties, properties, sizeof(properties));
	/* Check how we should send this */
	size_t bufsize = properties_len + object->payload_len + 100;
	uint8_t *buffer = g_malloc(bufsize);	/* FIXME */
	if(object->delivery == IMQUIC_MOQ_USE_DATAGRAM) {
		/* Use a datagram */
		if(has_payload) {
			size_t dg_len = imquic_moq_add_object_datagram(moq, buffer, bufsize,
				object->request_id, object->track_alias, object->group_id, object->object_id, object->object_status,
				object->priority, object->payload, object->payload_len,
				properties, properties_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_object_datagram_created(conn->qlog, object);
#endif
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
		} else {
			size_t dg_len = imquic_moq_add_object_datagram_status(moq, buffer, bufsize,
				object->track_alias, object->group_id, object->object_id, object->priority,
				object->object_status, properties, properties_len);
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_object_datagram_status_created(conn->qlog, object);
#endif
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_SUBGROUP && (valid_pkt || object->end_of_stream)) {
		/* Use HEADER_SUBGROUP */
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions, &object->track_alias);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] No such subscription with track alias '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->track_alias);
			imquic_refcount_decrease(&moq->ref);
			g_free(buffer);
			return -1;
		}
		/* FIXME Create a single lookup key out of both group and subgroup IDs */
		uint64_t lookup_id = (object->group_id << 32) + object->subgroup_id;
		imquic_moq_stream *moq_stream = g_hash_table_lookup(moq_sub->streams_by_subgroup, &lookup_id);
		if(moq_stream == NULL) {
			if(!valid_pkt && object->end_of_stream) {
				/* Nothing to do here */
				imquic_mutex_unlock(&moq->mutex);
				imquic_refcount_decrease(&moq->ref);
				g_free(buffer);
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			/* TODO Change the type depending on whether properties/subgroup will be set:
			 * since we don't have an API for that, for now we always set the type
			 * that will allow us to dynamically use them all. This also means we
			 * currently don't have a way to specify an End-of-Group flag */
			moq_stream->type = imquic_moq_data_message_type_from_subgroup_header(moq->version,
				TRUE,	/* We'll explicitly specify the Subgroup ID */
				FALSE,	/* Whether the default Subgroup ID is 0 (ignored, since we set it) */
				TRUE,	/* We'll add the properties block, whether there are properties or not */
				TRUE,	/* End-of-Group is set */
				TRUE);	/* We'll add the Publisher Priority property */
			moq_stream->priority = 128;	/* FIXME */
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			g_hash_table_insert(moq_sub->streams_by_subgroup, imquic_dup_uint64(lookup_id), moq_stream);
			moq_sub->streams_count++;
			imquic_mutex_unlock(&moq->mutex);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_stream_type_set(conn->qlog, TRUE, moq_stream->stream_id, "subgroup_header");
#endif
			/* Send a SUBGROUP_HEADER */
			size_t shg_len = imquic_moq_add_subgroup_header(moq, moq_stream, buffer, bufsize,
				object->request_id, object->track_alias, object->group_id, object->subgroup_id, object->priority);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_subgroup_header_created(conn->qlog, moq_stream, buffer, shg_len);
#endif
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, shg_len, FALSE);
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shgo_len = 0;
		if(valid_pkt) {
			uint64_t object_id = object->object_id;
			/* Object IDs are a delta */
			if(moq_stream->got_objects && object_id <= moq_stream->last_object_id) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't send older object on this subgroup (%"SCNu64" <= %"SCNu64")\n",
					imquic_get_connection_name(conn), object_id, moq_stream->last_object_id);
				imquic_refcount_decrease(&moq->ref);
				g_free(buffer);
				return -1;
			}
			object_id -= moq_stream->last_object_id;
			if(moq_stream->got_objects)
				object_id--;
			moq_stream->got_objects = TRUE;
			moq_stream->last_object_id = object->object_id;
			shgo_len = imquic_moq_add_subgroup_header_object(moq, moq_stream, buffer, bufsize,
				object_id, object->object_status, object->payload, object->payload_len,
				properties, properties_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_subgroup_object_created(conn->qlog, moq_stream->stream_id, object);
#endif
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, shgo_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_GROUP));
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_GROUP) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq_sub->streams_by_subgroup, &lookup_id);
			imquic_mutex_unlock(&moq->mutex);
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_FETCH && (valid_pkt || object->end_of_stream)) {
		/* Use FETCH_HEADER */
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &object->request_id);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->request_id);
			imquic_refcount_decrease(&moq->ref);
			g_free(buffer);
			return -1;
		}
		imquic_moq_stream *moq_stream = moq_sub->stream;
		if(moq_stream == NULL) {
			if(!valid_pkt && object->end_of_stream) {
				/* Nothing to do here */
				imquic_mutex_unlock(&moq->mutex);
				imquic_refcount_decrease(&moq->ref);
				g_free(buffer);
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			moq_stream->type = IMQUIC_MOQ_FETCH_HEADER;
			moq_stream->priority = 128;	/* FIXME */
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			moq_sub->stream = moq_stream;
			moq_sub->streams_count++;
			imquic_mutex_unlock(&moq->mutex);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_stream_type_set(conn->qlog, TRUE, moq_stream->stream_id, "fetch_header");
#endif
			/* Send a FETCH_HEADER */
			size_t sht_len = imquic_moq_add_fetch_header(moq, buffer, bufsize, object->request_id);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_fetch_header_created(conn->qlog, moq_stream, buffer, sht_len);
#endif
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, sht_len, FALSE);
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shto_len = 0;
		if(valid_pkt) {
			/* TODO Compute which flags we should use, rather than hardcoding them */
			uint64_t flags = imquic_moq_generate_fetch_serialization_flags(moq->version,
				IMQUIC_MOQ_FETCH_SUBGROUP_ID,	/* We write the Subgroup ID */
				TRUE,	/* We write the Object ID */
				TRUE,	/* We write the Group ID */
				TRUE,	/* We write the Priority */
				TRUE,	/* We add properties */
				FALSE,	/* We assume Forwarding Preference is not DATAGRAM */
				FALSE, FALSE);	/* We don't use the "end of range" flags */
			shto_len = imquic_moq_add_fetch_header_object(moq, buffer, bufsize, flags,
				object->group_id, object->subgroup_id, object->object_id, object->priority,
				object->object_status, object->payload, object->payload_len,
				properties, properties_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_fetch_object_created(conn->qlog, moq_stream->stream_id, object);
#endif
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, shto_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK));
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq->subscriptions_by_id, &object->request_id);
			imquic_mutex_unlock(&moq->mutex);
		}
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	g_free(buffer);
	return 0;
}

/* Reading and writing MoQ's flavour of variable size integers */
static uint64_t imquic_read_moqint(imquic_moq_version version, uint8_t *bytes, size_t blen, uint8_t *length) {
	if(version <= IMQUIC_MOQ_VERSION_16)
		return imquic_read_varint(bytes, blen, length);
	if(length)
		*length = 0;
	if(bytes == NULL || blen == 0)
		return 0;
	if(bytes[0] == 0xFC) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid moqint code point\n");
		return 0;
	}
	/* Check how many bytes we need */
	uint8_t len = 0;
	uint64_t res = 0;
	if((bytes[0] >> 7) == 0) {
		len = 1;
		res = bytes[0];
		goto done;
	} else if((bytes[0] >> 6) == 0x02) {
		len = 2;
	} else if((bytes[0] >> 5) == 0x06) {
		len = 3;
	} else if((bytes[0] >> 4) == 0x0E) {
		len = 4;
	} else if((bytes[0] >> 3) == 0x1E) {
		len = 5;
	} else if((bytes[0] >> 2) == 0x3E) {
		len = 6;
	} else if((bytes[0]) == 0xFE) {
		len = 8;
	} else if((bytes[0]) == 0xFF) {
		len = 9;
	}
	if(len == 0 || len > blen) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid moqint (%"SCNu8" > %zu)\n", len, blen);
		return 0;
	}
	if(len < 8) {
		uint8_t temp = bytes[0] << len;
		res = temp >> len;
	}
	for(uint8_t i=1; i<len; i++) {
		res = (res << 8) + bytes[i];
	}
done:
	if(length)
		*length = len;
	return res;
}

static uint8_t imquic_write_moqint(imquic_moq_version version, uint64_t number, uint8_t *bytes, size_t blen) {
	if(version <= IMQUIC_MOQ_VERSION_16)
		return imquic_write_varint(number, bytes, blen);
	if(blen < 1)
		return 0;
	if(number <= 127) {
		/* Let's use one byte */
		*bytes = number;
		return 1;
	} else if(number <= 16383) {
		/* Let's use two bytes */
		if(blen < 2) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 2 bytes)\n", number);
			return 0;
		}
		uint16_t num = number;
		num = g_htons(num);
		memcpy(bytes, &num, sizeof(num));
		*bytes += 1 << 7;
		return 2;
	} else if(number <= 2097151) {
		/* Let's use three bytes */
		if(blen < 3) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 3 bytes)\n", number);
			return 0;
		}
		uint32_t num = number;
		num = g_htonl(num);
		memcpy(bytes, ((uint8_t*)&num) + 1, 3);
		*bytes += 3 << 6;
		return 3;
	} else if(number <= 268435455) {
		/* Let's use four bytes */
		if(blen < 4) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 4 bytes)\n", number);
			return 0;
		}
		uint32_t num = number;
		num = g_htonl(num);
		memcpy(bytes, &num, sizeof(num));
		*bytes += 7 << 5;
		return 4;
	} else if(number <= 34359738367) {
		/* Let's use five bytes */
		if(blen < 5) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 5 bytes)\n", number);
			return 0;
		}
		number = htonll(number);
		memcpy(bytes, ((uint8_t*)&number) + 3, 5);
		*bytes += 15 << 4;
		return 5;
	} else if(number <= 4398046511103) {
		/* Let's use six bytes */
		if(blen < 6) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 6 bytes)\n", number);
			return 0;
		}
		number = htonll(number);
		memcpy(bytes, ((uint8_t*)&number) + 2, 6);
		*bytes += 31 << 3;
		return 6;
	} else if(number <= 72057594037927935) {
		/* Let's use eight bytes */
		if(blen < 8) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 8 bytes)\n", number);
			return 0;
		}
		number = htonll(number);
		memcpy(bytes, &number, sizeof(number));
		*bytes = 0xFE;
		return 8;
	} else {
		/* Let's use nine bytes */
		if(blen < 9) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough room to write moqint '%"SCNu64"' (need at least 9 bytes)\n", number);
			return 0;
		}
		number = htonll(number);
		memcpy(bytes + 1, &number, sizeof(number));
		*bytes = 0xFF;
		return 9;
	}
	IMQUIC_LOG(IMQUIC_LOG_WARN, "Didn't write moqint '%"SCNu64"'\n", number);
	return 0;
}

/* Helpers to check and generate GREASE values */
static gboolean imquic_moq_is_grease(uint64_t value) {
	if(value < IMQUIC_MOQ_GREASE_SUM)
		return FALSE;
	uint64_t n = (value - IMQUIC_MOQ_GREASE_SUM) / IMQUIC_MOQ_GREASE_BASE;
	return (((n * IMQUIC_MOQ_GREASE_BASE) + IMQUIC_MOQ_GREASE_SUM) == value);
}

static uint64_t imquic_moq_random_grease(void) {
	/* FIXME */
	uint64_t n = g_random_int_range(0, 1000);
	return (n * IMQUIC_MOQ_GREASE_BASE) + IMQUIC_MOQ_GREASE_SUM;
}

#ifdef HAVE_QLOG
/* QLOG support */
json_t *imquic_qlog_moq_message_prepare(const char *type) {
	if(type == NULL)
		return NULL;
	json_t *message = json_object();
	json_object_set_new(message, "type", json_string(type));
	return message;
}

void imquic_qlog_moq_message_add_namespace(json_t *message, imquic_moq_namespace *track_namespace, const char *name) {
	if(message == NULL || name == NULL)
		return;
	json_t *tns_list = json_array(), *tns = NULL;
	char tns_buffer[256];
	const char *ns = NULL;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		ns = imquic_moq_namespace_str(temp, tns_buffer, sizeof(tns_buffer), FALSE);
		tns = json_object();
		json_object_set_new(tns, "value", json_string(ns ? ns : ""));
		json_array_append_new(tns_list, tns);
		temp = temp->next;
	}
	json_object_set_new(message, name, tns_list);
}

void imquic_qlog_moq_message_add_track(json_t *message, imquic_moq_name *track_name) {
	if(message == NULL)
		return;
	char tn_buffer[256];
	const char *name = imquic_moq_track_str(track_name, tn_buffer, sizeof(tn_buffer));
	json_t *tn = json_object();
	json_object_set_new(tn, "value", json_string(name ? name : ""));
	json_object_set_new(message, "track_name", tn);
}

void imquic_qlog_moq_message_add_setup_options(json_t *message, imquic_moq_setup_options *options, const char *name) {
	if(message == NULL || options == NULL || name == NULL)
		return;
	json_t *opts = json_array();
	if(options->path_set) {
		json_t *path = json_object();
		json_object_set_new(path, "name", json_string("path"));
		json_object_set_new(path, "value", json_string(options->path));
		json_array_append_new(opts, path);
	}
	if(options->max_request_id_set) {
		json_t *max_request_id = json_object();
		json_object_set_new(max_request_id, "name", json_string("max_request_id"));
		json_object_set_new(max_request_id, "value", json_integer(options->max_request_id));
		json_array_append_new(opts, max_request_id);
	}
	if(options->max_auth_token_cache_size_set) {
		json_t *max_auth_token_cache_size = json_object();
		json_object_set_new(max_auth_token_cache_size, "name", json_string("max_auth_token_cache_size"));
		json_object_set_new(max_auth_token_cache_size, "value", json_integer(options->max_auth_token_cache_size));
		json_array_append_new(opts, max_auth_token_cache_size);
	}
	if(options->auth_token_set && options->auth_token_len > 0) {
		json_t *auth_token = json_object();
		json_object_set_new(auth_token, "name", json_string("authorization_token"));
		char ai_str[513];
		json_object_set_new(auth_token, "value", json_string(imquic_hex_str(options->auth_token, options->auth_token_len, ai_str, sizeof(ai_str))));
		json_array_append_new(opts, auth_token);
	}
	if(options->authority_set) {
		json_t *authority = json_object();
		json_object_set_new(authority, "name", json_string("authority"));
		json_object_set_new(authority, "value", json_string(options->authority));
		json_array_append_new(opts, authority);
	}
	if(options->moqt_implementation_set) {
		json_t *moqt_implementation = json_object();
		json_object_set_new(moqt_implementation, "name", json_string("moqt_implementation"));
		json_object_set_new(moqt_implementation, "value", json_string(options->moqt_implementation));
		json_array_append_new(opts, moqt_implementation);
	}
	if(options->unknown) {
		json_t *unknown = json_object();
		json_object_set_new(unknown, "name", json_string("unknown"));
		json_array_append_new(opts, unknown);
	}
	json_object_set_new(message, name, opts);
}

void imquic_qlog_moq_message_add_request_parameters(json_t *message, imquic_moq_version version, imquic_moq_request_parameters *parameters, const char *name) {
	if(message == NULL || parameters == NULL || name == NULL)
		return;
	json_t *params = json_array();
	if(parameters->auth_token_set && parameters->auth_token_len > 0) {
		json_t *auth_token = json_object();
		json_object_set_new(auth_token, "name", json_string("authorization_token"));
		char ai_str[513];
		json_object_set_new(auth_token, "value", json_string(imquic_hex_str(parameters->auth_token, parameters->auth_token_len, ai_str, sizeof(ai_str))));
		json_array_append_new(params, auth_token);
	}
	if(parameters->delivery_timeout_set) {
		json_t *delivery_timeout = json_object();
		json_object_set_new(delivery_timeout, "name", json_string("delivery_timeout"));
		json_object_set_new(delivery_timeout, "value", json_integer(parameters->delivery_timeout));
		json_array_append_new(params, delivery_timeout);
	}
	if(parameters->rendezvous_timeout_set) {
		json_t *rendezvous_timeout = json_object();
		json_object_set_new(rendezvous_timeout, "name", json_string("rendezvous_timeout"));
		json_object_set_new(rendezvous_timeout, "value", json_integer(parameters->rendezvous_timeout));
		json_array_append_new(params, rendezvous_timeout);
	}
	if(parameters->subscriber_priority_set) {
		json_t *subscriber_priority = json_object();
		json_object_set_new(subscriber_priority, "name", json_string("subscriber_priority"));
		json_object_set_new(subscriber_priority, "value", json_integer(parameters->subscriber_priority));
		json_array_append_new(params, subscriber_priority);
	}
	if(parameters->group_order_set) {
		json_t *group_order = json_object();
		json_object_set_new(group_order, "name", json_string("group_order"));
		json_object_set_new(group_order, "value", json_integer(parameters->group_order));
		json_array_append_new(params, group_order);
	}
	if(parameters->subscription_filter_set) {
		json_t *subscription_filter = json_object();
		json_object_set_new(subscription_filter, "name", json_string("subscription_filter"));
		/* FIXME */
		json_t *sf = json_object();
		json_object_set_new(sf, "type", json_integer(parameters->subscription_filter.type));
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			json_t *lo = json_object();
			json_object_set_new(lo, "group", json_integer(parameters->subscription_filter.start_location.group));
			json_object_set_new(lo, "object", json_integer(parameters->subscription_filter.start_location.object));
			json_object_set_new(sf, "start_location", lo);
		}
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			if(version <= IMQUIC_MOQ_VERSION_16)
				json_object_set_new(sf, "end_group", json_integer(parameters->subscription_filter.end_group));
			else
				json_object_set_new(sf, "end_group_delta", json_integer(parameters->subscription_filter.end_group - parameters->subscription_filter.start_location.group));
		}
		json_object_set_new(subscription_filter, "value", sf);
		json_array_append_new(params, subscription_filter);
	}
	if(parameters->expires_set) {
		json_t *expires = json_object();
		json_object_set_new(expires, "name", json_string("expires"));
		json_object_set_new(expires, "value", json_integer(parameters->expires));
		json_array_append_new(params, expires);
	}
	if(parameters->largest_object_set) {
		json_t *largest_object = json_object();
		json_object_set_new(largest_object, "name", json_string("largest_object"));
		/* FIXME */
		json_t *lo = json_object();
		json_object_set_new(lo, "group", json_integer(parameters->largest_object.group));
		json_object_set_new(lo, "object", json_integer(parameters->largest_object.object));
		json_object_set_new(largest_object, "value", lo);
		json_array_append_new(params, largest_object);
	}
	if(parameters->forward_set) {
		json_t *forward = json_object();
		json_object_set_new(forward, "name", json_string("forward"));
		json_object_set_new(forward, "value", json_integer(parameters->forward));
		json_array_append_new(params, forward);
	}
	if(parameters->new_group_request_set) {
		json_t *new_group_request = json_object();
		json_object_set_new(new_group_request, "name", json_string("new_group_request"));
		json_object_set_new(new_group_request, "value", json_integer(parameters->new_group_request));
		json_array_append_new(params, new_group_request);
	}
	if(parameters->unknown) {
		json_t *unknown = json_object();
		json_object_set_new(unknown, "name", json_string("unknown"));
		json_array_append_new(params, unknown);
	}
	json_object_set_new(message, name, params);
}

void imquic_qlog_moq_message_add_properties(json_t *message, GList *properties, const char *name) {
	if(message == NULL || properties == NULL || name == NULL)
		return;
	json_t *headers = json_array();
	GList *temp = properties;
	while(temp) {
		imquic_moq_property *prop = (imquic_moq_property *)temp->data;
		json_t *header = json_object();
		json_object_set_new(header, "type", json_integer(prop->id));
		if(prop->id % 2 == 0) {
			json_object_set_new(header, "value", json_integer(prop->value.number));
		} else {
			/* FIXME */
			json_object_set_new(header, "length", json_integer(prop->value.data.length));
		}
		json_array_append_new(headers, header);
		temp = temp->next;
	}
	json_object_set_new(message, name, headers);
}

void imquic_moq_qlog_control_message_created(imquic_qlog *qlog, uint64_t stream_id, uint8_t *bytes, size_t length, json_t *message) {
	if(qlog == NULL) {
		if(message != NULL)
			json_decref(message);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("moqt:control_message_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "length", json_integer(length));
	if(message != NULL)
		json_object_set_new(data, "message", message);
	if(qlog->moq_messages && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_control_message_parsed(imquic_qlog *qlog, uint64_t stream_id, uint8_t *bytes, size_t length, json_t *message) {
	if(qlog == NULL) {
		if(message != NULL)
			json_decref(message);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("moqt:control_message_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "length", json_integer(length));
	if(message != NULL)
		json_object_set_new(data, "message", message);
	if(qlog->moq_messages && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_stream_type_set(imquic_qlog *qlog, gboolean local, uint64_t stream_id, const char *type) {
	if(qlog == NULL || type == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:stream_type_set");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "owner", json_string(local ? "local" : "remote"));
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "stream_type", json_string(type));
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_object_datagram_created(imquic_qlog *qlog, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:object_datagram_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "track_alias", json_integer(object->track_alias));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_object_datagram_parsed(imquic_qlog *qlog, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:object_datagram_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "track_alias", json_integer(object->track_alias));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_object_datagram_status_created(imquic_qlog *qlog, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:object_datagram_status_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "track_alias", json_integer(object->track_alias));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_object_datagram_status_parsed(imquic_qlog *qlog, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:object_datagram_status_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "track_alias", json_integer(object->track_alias));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_header_created(imquic_qlog *qlog, imquic_moq_stream *stream, uint8_t *bytes, size_t length) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_header_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "type", json_integer(stream->type));
	json_object_set_new(data, "track_alias", json_integer(stream->track_alias));
	json_object_set_new(data, "group_id", json_integer(stream->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(stream->subgroup_id));
	json_object_set_new(data, "publisher_priority", json_integer(stream->priority));
	/* FIXME Not part of the spec, but may be useful */
	if(qlog->moq_objects && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_header_parsed(imquic_qlog *qlog, imquic_moq_stream *stream, uint8_t *bytes, size_t length) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_header_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "type", json_integer(stream->type));
	json_object_set_new(data, "track_alias", json_integer(stream->track_alias));
	json_object_set_new(data, "group_id", json_integer(stream->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(stream->subgroup_id));
	json_object_set_new(data, "publisher_priority", json_integer(stream->priority));
	/* FIXME Not part of the spec, but may be useful */
	if(qlog->moq_objects && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_object_created(imquic_qlog *qlog, uint64_t stream_id, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_object_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_payload_length", json_integer(object->payload_len));
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_object_parsed(imquic_qlog *qlog, uint64_t stream_id, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_object_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	json_object_set_new(data, "publisher_priority", json_integer(object->priority));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_payload_length", json_integer(object->payload_len));
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_header_created(imquic_qlog *qlog, imquic_moq_stream *stream, uint8_t *bytes, size_t length) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_header_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "request_id", json_integer(stream->request_id));
	/* FIXME Not part of the spec, but may be useful */
	if(qlog->moq_objects && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_header_parsed(imquic_qlog *qlog, imquic_moq_stream *stream, uint8_t *bytes, size_t length) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_header_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "request_id", json_integer(stream->request_id));
	/* FIXME Not part of the spec, but may be useful */
	if(qlog->moq_objects && bytes != NULL && length > 0)
		imquic_qlog_event_add_raw(data, "raw", bytes, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_object_created(imquic_qlog *qlog, uint64_t stream_id, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_object_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_payload_length", json_integer(object->payload_len));
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_object_parsed(imquic_qlog *qlog, uint64_t stream_id, imquic_moq_object *object) {
	if(qlog == NULL || object == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_object_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream_id));
	json_object_set_new(data, "group_id", json_integer(object->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(object->group_id));
	json_object_set_new(data, "object_id", json_integer(object->object_id));
	imquic_qlog_moq_message_add_properties(data, object->properties, "properties");
	json_object_set_new(data, "object_payload_length", json_integer(object->payload_len));
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

#endif
