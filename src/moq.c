/*! \file   moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Media Over QUIC (MoQ) stack
 * \details Implementation of the Media Over QUIC (MoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) versions from -06 to to -14 of the protocol.
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
#include "internal/quic.h"
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

/* Initialization */
static void imquic_moq_context_destroy(imquic_moq_context *moq);
static void imquic_moq_context_free(const imquic_refcount *moq_ref);
void imquic_moq_init(void) {
	moq_sessions = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_moq_context_destroy);
}

void imquic_moq_deinit(void) {
	imquic_mutex_lock(&moq_mutex);
	if(moq_sessions != NULL)
		g_hash_table_unref(moq_sessions);
	moq_sessions = NULL;
	imquic_mutex_unlock(&moq_mutex);
}

/* Helper to dynamically return the MoQ version associated with the negotiated ALPN */
static imquic_moq_version imquic_moq_version_from_alpn(const char *alpn, imquic_moq_version fallback) {
	if(alpn == NULL)
		return fallback;
	if(!strcasecmp(alpn, "moq-00"))
		return IMQUIC_MOQ_VERSION_ANY_LEGACY;
	else if(!strcasecmp(alpn, "moq-15"))
		return IMQUIC_MOQ_VERSION_15;
	else if(!strcasecmp(alpn, "moq-14"))
		return IMQUIC_MOQ_VERSION_14;
	else if(!strcasecmp(alpn, "moq-13"))
		return IMQUIC_MOQ_VERSION_13;
	else if(!strcasecmp(alpn, "moq-12"))
		return IMQUIC_MOQ_VERSION_12;
	else if(!strcasecmp(alpn, "moq-11"))
		return IMQUIC_MOQ_VERSION_11;
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
	if(alpn == NULL && moq->version == IMQUIC_MOQ_VERSION_ANY)
		moq->version = IMQUIC_MOQ_VERSION_ANY_LEGACY;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s][MoQ] MoQ version: %s (%s)\n", imquic_get_connection_name(conn),
		imquic_moq_version_str(moq->version), alpn);
	moq->streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	moq->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_subscription_destroy);
	moq->requests = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->buffer = g_malloc0(sizeof(imquic_moq_buffer));
	imquic_mutex_init(&moq->mutex);
	imquic_refcount_init(&moq->ref, imquic_moq_context_free);
	imquic_mutex_lock(&moq_mutex);
	g_hash_table_insert(moq_sessions, conn, moq);
	imquic_mutex_unlock(&moq_mutex);
	/* If we're a client, let's create a control stream */
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
	/* Notify the application: for clients, we'll need it to set role and version */
	if(conn->socket && conn->socket->callbacks.moq.new_connection)
		conn->socket->callbacks.moq.new_connection(conn, user_data);
	/* After the function returns, check if we can do something */
	if(!moq->is_server) {
		/* Generate a CLIENT_SETUP */
		imquic_moq_setup_parameters parameters = { 0 };
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
		if((moq->version >= IMQUIC_MOQ_VERSION_14 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
				moq->version == IMQUIC_MOQ_VERSION_ANY) {
			/* FIXME */
			parameters.moqt_implementation_set = TRUE;
			g_snprintf(parameters.moqt_implementation, sizeof(parameters.moqt_implementation), "imquic %s", imquic_version_string_full);
		}
		/* TODO For raw quic connections, we should expose ways to
		 * fill in and use the PATH and ATTRIBUTE parameters as well */
		/* Version is only negotiated here for versions of the draft older than v15 */
		GList *versions = NULL;
		if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
			if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
				/* Offer all newer supported versions */
				versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_14));
				versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_13));
				versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_12));
				versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_11));
			} else {
				/* Offer a specific version */
				versions = g_list_append(versions, GUINT_TO_POINTER(moq->version));
			}
		}
		uint8_t buffer[200];
		size_t blen = sizeof(buffer);
		size_t cs_len = imquic_moq_add_client_setup(moq, buffer, blen, versions, &parameters);
		g_list_free(versions);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			buffer, moq->control_stream_offset, cs_len, FALSE);
		moq->control_stream_offset += cs_len;
		imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	}
}

void imquic_moq_stream_incoming(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	/* Got incoming data via STREAM */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] [STREAM-%"SCNu64"] Got data: %"SCNu64"--%"SCNu64" (%s)\n",
		imquic_get_connection_name(conn),
		stream_id, offset, offset+length, (complete ? "complete" : "not complete"));
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_mutex_unlock(&moq_mutex);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Ignoring incoming STREAM data on unknown context\n",
			imquic_get_connection_name(conn));
		return;
	}
	if(offset == 0 && !moq->has_control_stream) {
		uint64_t actual_id = 0;
		gboolean client_initiated = FALSE, bidirectional = FALSE;
		imquic_parse_stream_id(stream_id, &actual_id, &client_initiated, &bidirectional);
		if(!bidirectional) {
			/* First stream we get is not a bidirectional control stream */
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Not a bidirectional MoQ control stream\n",
				imquic_get_connection_name(conn));
			return;
		}
		moq->has_control_stream = TRUE;
		moq->control_stream_id = stream_id;
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->moq)
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq->control_stream_id, "control");
#endif
	}
	imquic_moq_parse_message(moq, stream_id, bytes, length, complete, FALSE);
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

void imquic_moq_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	imquic_mutex_lock(&moq_mutex);
	gboolean removed = g_hash_table_remove(moq_sessions, conn);
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
	if(moq->requests)
		g_hash_table_unref(moq->requests);
	imquic_moq_buffer_destroy(moq->buffer);
	g_free(moq);
}

static void imquic_moq_object_extension_free(imquic_moq_object_extension *extension) {
	if(extension != NULL) {
		if(extension->value.data.buffer != NULL)
			g_free(extension->value.data.buffer);
		g_free(extension);
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
		case IMQUIC_MOQ_TOO_MANY_REQUESTS:
			return "Too Many Requests";
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
			return "INTERNAL_ERROR";
		case IMQUIC_MOQ_REQERR_UNAUTHORIZED:
			return "UNAUTHORIZED";
		case IMQUIC_MOQ_REQERR_TIMEOUT:
			return "TIMEOUT";
		case IMQUIC_MOQ_REQERR_NOT_SUPPORTED:
			return "NOT_SUPPORTED";
		case IMQUIC_MOQ_REQERR_MALFORMED_AUTH_TOKEN:
			return "MALFORMED_AUTH_TOKEN";
		case IMQUIC_MOQ_REQERR_EXPIRED_AUTH_TOKEN:
			return "EXPIRED_AUTH_TOKEN";
		case IMQUIC_MOQ_REQERR_DOES_NOT_EXIST:
			return "DOES_NOT_EXIST";
		case IMQUIC_MOQ_REQERR_INVALID_RANGE:
			return "INVALID_RANGE";
		case IMQUIC_MOQ_REQERR_MALFORMED_TRACK:
			return "MALFORMED_TRACK";
		case IMQUIC_MOQ_REQERR_UNINTERESTED:
			return "UNINTERESTED";
		case IMQUIC_MOQ_REQERR_PREFIX_OVERLAP:
			return "PREFIX_OVERLAP";
		case IMQUIC_MOQ_REQERR_INVALID_JOINING_REQUEST_ID:
			return "INVALID_JOINING_REQUEST_ID";
		case IMQUIC_MOQ_REQERR_UNKNOWN_STATUS_IN_RANGE:
			return "UNKNOWN_STATUS_IN_RANGE";
		default: break;
	}
	return NULL;
}

imquic_moq_legacy_error_code imquic_moq_request_error_code_to_legacy(imquic_moq_version version, imquic_moq_request_error_code code) {
	if(version >= IMQUIC_MOQ_VERSION_15)
		return (imquic_moq_legacy_error_code)code;
	switch(code) {
		/* Same code */
		case IMQUIC_MOQ_REQERR_INTERNAL_ERROR:
		case IMQUIC_MOQ_REQERR_UNAUTHORIZED:
		case IMQUIC_MOQ_REQERR_TIMEOUT:
		case IMQUIC_MOQ_REQERR_NOT_SUPPORTED:
			return (imquic_moq_legacy_error_code)code;
		/* Error code was different up to v14 */
		case IMQUIC_MOQ_REQERR_MALFORMED_AUTH_TOKEN:
			return IMQUIC_MOQ_OLDERR_MALFORMED_AUTH_TOKEN;
		case IMQUIC_MOQ_REQERR_EXPIRED_AUTH_TOKEN:
			return IMQUIC_MOQ_OLDERR_EXPIRED_AUTH_TOKEN;
		case IMQUIC_MOQ_REQERR_DOES_NOT_EXIST:
			return IMQUIC_MOQ_OLDERR_TRACK_DOES_NOT_EXIST;
		case IMQUIC_MOQ_REQERR_INVALID_RANGE:
			return IMQUIC_MOQ_OLDERR_INVALID_RANGE;
		case IMQUIC_MOQ_REQERR_MALFORMED_TRACK:
			return IMQUIC_MOQ_OLDERR_MALFORMED_TRACK;
		case IMQUIC_MOQ_REQERR_UNINTERESTED:
			return IMQUIC_MOQ_OLDERR_UNINTERESTED;
		case IMQUIC_MOQ_REQERR_INVALID_JOINING_REQUEST_ID:
			return IMQUIC_MOQ_OLDERR_INVALID_JOINING_REQUEST_ID;
		case IMQUIC_MOQ_REQERR_UNKNOWN_STATUS_IN_RANGE:
			return IMQUIC_MOQ_OLDERR_UNKNOWN_STATUS_IN_RANGE;
		/* New error codes with no mapping to old ones */
		case IMQUIC_MOQ_REQERR_PREFIX_OVERLAP:
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't translate new error code %s (%s) to old error code\n",
				imquic_moq_request_error_code_str(code), imquic_moq_version_str(version));
			break;
	}
	/* As a fallback, we return a generic internal error */
	return IMQUIC_MOQ_OLDERR_INTERNAL_ERROR;
}

imquic_moq_request_error_code imquic_moq_request_error_code_from_legacy(imquic_moq_version version, imquic_moq_legacy_error_code code) {
	if(version >= IMQUIC_MOQ_VERSION_15)
		return (imquic_moq_request_error_code)code;
	switch(code) {
		/* Same code */
		case IMQUIC_MOQ_OLDERR_INTERNAL_ERROR:
		case IMQUIC_MOQ_OLDERR_UNAUTHORIZED:
		case IMQUIC_MOQ_OLDERR_TIMEOUT:
		case IMQUIC_MOQ_OLDERR_NOT_SUPPORTED:
			return (imquic_moq_request_error_code)code;
		case IMQUIC_MOQ_OLDERR_TRACK_DOES_NOT_EXIST:
			/* Note: there's actually a conflit here (it's also the
			 * old UNINTERESTED), but this is more common/important */
			return IMQUIC_MOQ_REQERR_DOES_NOT_EXIST;
		case IMQUIC_MOQ_OLDERR_INVALID_RANGE:
			return IMQUIC_MOQ_REQERR_INVALID_RANGE;
		case IMQUIC_MOQ_OLDERR_INVALID_JOINING_REQUEST_ID:
			return IMQUIC_MOQ_REQERR_INVALID_JOINING_REQUEST_ID;
		case IMQUIC_MOQ_OLDERR_UNKNOWN_STATUS_IN_RANGE:
			return IMQUIC_MOQ_REQERR_UNKNOWN_STATUS_IN_RANGE;
		case IMQUIC_MOQ_OLDERR_MALFORMED_TRACK:
			return IMQUIC_MOQ_REQERR_MALFORMED_TRACK;
		case IMQUIC_MOQ_OLDERR_MALFORMED_AUTH_TOKEN:
			return IMQUIC_MOQ_REQERR_MALFORMED_AUTH_TOKEN;
		case IMQUIC_MOQ_OLDERR_EXPIRED_AUTH_TOKEN:
			return IMQUIC_MOQ_REQERR_EXPIRED_AUTH_TOKEN;
		/* No mapping or multiple (ambiguous) mappings */
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't translate (%s) old error code '%02x' to new request error codes\n",
				imquic_moq_version_str(version), code);
			break;
	}
	/* As a fallback, we return a generic internal error */
	return IMQUIC_MOQ_REQERR_INTERNAL_ERROR;
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
		case IMQUIC_MOQ_PUBDONE_MALFORMED_TRACK:
			return "Malformed Track";
		case IMQUIC_MOQ_PUBDONE_UPDATE_FAILED:
			return "Update Failed";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_message_type_str(imquic_moq_message_type type, imquic_moq_version version) {
	if(version <= IMQUIC_MOQ_VERSION_14) {
		switch(type) {
			case IMQUIC_MOQ_SUBSCRIBE:
				return "SUBSCRIBE";
			case IMQUIC_MOQ_SUBSCRIBE_OK:
				return "SUBSCRIBE_OK";
			case IMQUIC_MOQ_SUBSCRIBE_ERROR:
				return "SUBSCRIBE_ERROR";
			case IMQUIC_MOQ_SUBSCRIBE_UPDATE:
				return "SUBSCRIBE_UPDATE";
			case IMQUIC_MOQ_PUBLISH_NAMESPACE:
				return "PUBLISH_NAMESPACE";
			case IMQUIC_MOQ_PUBLISH_NAMESPACE_OK:
				return "PUBLISH_NAMESPACE_OK";
			case IMQUIC_MOQ_PUBLISH_NAMESPACE_ERROR:
				return "PUBLISH_NAMESPACE_ERROR";
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
			case IMQUIC_MOQ_TRACK_STATUS_OK:
				return "TRACK_STATUS_OK";
			case IMQUIC_MOQ_TRACK_STATUS_ERROR:
				return "TRACK_STATUS_ERROR";
			case IMQUIC_MOQ_GOAWAY:
				return "GOAWAY";
			case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE:
				return "SUBSCRIBE_NAMESPACE";
			case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_OK:
				return "SUBSCRIBE_NAMESPACE_OK";
			case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_ERROR:
				return "SUBSCRIBE_NAMESPACE_ERROR";
			case IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE:
				return "UNSUBSCRIBE_NAMESPACE";
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
			case IMQUIC_MOQ_FETCH_ERROR:
				return "FETCH_ERROR";
			case IMQUIC_MOQ_CLIENT_SETUP:
				return "CLIENT_SETUP";
			case IMQUIC_MOQ_SERVER_SETUP:
				return "SERVER_SETUP";
			case IMQUIC_MOQ_PUBLISH:
				return "PUBLISH";
			case IMQUIC_MOQ_PUBLISH_OK:
				return "PUBLISH_OK";
			case IMQUIC_MOQ_PUBLISH_ERROR:
				return "PUBLISH_ERROR";
			default: break;
		}
	} else {
		switch(type) {
			case IMQUIC_MOQ_REQUEST_OK:
				return "REQUEST_OK";
			case IMQUIC_MOQ_REQUEST_ERROR:
				return "REQUEST_ERROR";
			case IMQUIC_MOQ_SUBSCRIBE:
				return "SUBSCRIBE";
			case IMQUIC_MOQ_SUBSCRIBE_OK:
				return "SUBSCRIBE_OK";
			case IMQUIC_MOQ_SUBSCRIBE_UPDATE:
				return "SUBSCRIBE_UPDATE";
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
			case IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE:
				return "UNSUBSCRIBE_NAMESPACE";
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
			case IMQUIC_MOQ_PUBLISH:
				return "PUBLISH";
			case IMQUIC_MOQ_PUBLISH_OK:
				return "PUBLISH_OK";
			default: break;
		}
	}
	return NULL;
}

gboolean imquic_moq_is_datagram_message_type_valid(imquic_moq_version version, uint8_t type) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		return (type <= 0x03);
	} else if(version == IMQUIC_MOQ_VERSION_12 || version == IMQUIC_MOQ_VERSION_13) {
		return (type <= 0x05);
	} else if(version == IMQUIC_MOQ_VERSION_14) {
		return (type <= 0x07 || type == 0x20 || type == 0x21);
	} else {
		return (type <= 0x0F || (type >= 0x20 && type <= 0x2D));
	}
	return FALSE;
}

uint8_t imquic_moq_datagram_message_type_return(imquic_moq_version version,
		gboolean payload, gboolean ext, gboolean eog, gboolean oid, gboolean priority) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(payload)
			return ext ? 0x01 : 0x00;
		else
			return ext ? 0x03 : 0x02;
	} else if(version == IMQUIC_MOQ_VERSION_12 || version == IMQUIC_MOQ_VERSION_13) {
		/* v12 and v13 */
		if(payload) {
			uint8_t type = 0x00;
			if(eog)
				type |= 0x02;
			if(ext)
				type |= 0x01;
			return type;
		} else {
			return ext ? 0x05 : 0x04;
		}
	} else if(version == IMQUIC_MOQ_VERSION_14) {
		/* v14 */
		if(payload) {
			uint8_t type = 0x00;
			if(eog)
				type |= 0x02;
			if(ext)
				type |= 0x01;
			if(!oid)
				type |= 0x04;
			return type;
		} else {
			return ext ? 0x21 : 0x20;
		}
	} else {
		/* v15 and later */
		uint8_t type = payload ? 0x00 : 0x20;
		if(!payload)
			eog = FALSE;
		if(eog)
			type |= 0x02;
		if(ext)
			type |= 0x01;
		if(!oid)
			type |= 0x04;
		if(!priority)
			type |= 0x08;
		return type;
	}
}

void imquic_moq_datagram_message_type_parse(imquic_moq_version version, uint8_t type,
		gboolean *payload, gboolean *ext, gboolean *eog, gboolean *oid, gboolean *priority, gboolean *violation) {
	if(oid)
		*oid = TRUE;
	if(priority)
		*priority = TRUE;
	if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(payload)
			*payload = (type == 0x00 || type == 0x01);
		if(ext)
			*ext = (type == 0x01 || type == 0x03);
		if(violation)
			*violation = (type > 0x03);
	} else if(version == IMQUIC_MOQ_VERSION_12 || version == IMQUIC_MOQ_VERSION_13) {
		/* v12 and v13 */
		if(payload)
			*payload = (type <= 0x03);
		if(ext)
			*ext = (type & 0x01);
		if(eog)
			*eog = (type & 0x02);
		if(violation)
			*violation = (type > 0x05);
	} else if(version == IMQUIC_MOQ_VERSION_14) {
		/* v14 */
		if(payload)
			*payload = (type <= 0x07);
		if(ext)
			*ext = (type & 0x01);
		if(eog)
			*eog = (type & 0x02);
		if(oid)
			*oid = !(type & 0x04);
		if(violation)
			*violation = ((type > 0x05 && type < 0x20) || (type > 0x21));
	} else {
		/* v15 and later */
		if(payload)
			*payload = (type <= 0x0F);
		if(ext)
			*ext = (type & 0x01);
		if(eog)
			*eog = (type & 0x02);
		if(oid)
			*oid = !(type & 0x04);
		if(priority)
			*priority = !(type & 0x08);
		if(violation)
			*violation = (type > 0x2D || (type >= 0x20 && (type & 0x02)));
	}
}

const char *imquic_moq_datagram_message_type_str(uint8_t type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		if(type == 0x00 || type == 0x01)
			return "OBJECT_DATAGRAM";
		else if(type == 0x02 || type == 0x03)
			return "OBJECT_DATAGRAM_STATUS";
	} else if(version == IMQUIC_MOQ_VERSION_12 || version == IMQUIC_MOQ_VERSION_13) {
		if(type <= 0x03)
			return "OBJECT_DATAGRAM";
		else if(type == 0x04 || type == 0x05)
			return "OBJECT_DATAGRAM_STATUS";
	} else if(version == IMQUIC_MOQ_VERSION_14) {
		if(type <= 0x07)
			return "OBJECT_DATAGRAM";
		else if(type == 0x20 || type == 0x21)
			return "OBJECT_DATAGRAM_STATUS";
	} else {
		if(type <= 0x0F)
			return "OBJECT_DATAGRAM";
		else if(type >= 0x20 && type <= 0x2D)
			return "OBJECT_DATAGRAM_STATUS";
	}
	return NULL;
}

gboolean imquic_moq_is_data_message_type_valid(imquic_moq_version version, uint8_t type) {
	if(type == IMQUIC_MOQ_FETCH_HEADER)
		return TRUE;
	if(version == IMQUIC_MOQ_VERSION_11) {
		if(type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11 ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11 ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_v11)
			return TRUE;
	} else {
		if((type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) ||
				(version >= IMQUIC_MOQ_VERSION_15 && (type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX)))
			return TRUE;
	}
	return FALSE;
}

uint8_t imquic_moq_data_message_type_from_subgroup_header(imquic_moq_version version,
		gboolean subgroup, gboolean sgid0, gboolean ext, gboolean eog, gboolean priority) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(!subgroup && sgid0 && !ext)
			return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11;
		else if(!subgroup && sgid0 && ext)
			return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11;
		else if(!subgroup && !sgid0 && !ext)
			return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_v11;
		else if(!subgroup && !sgid0 && ext)
			return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11;
		else if(subgroup && !ext)
			return IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11;
		return IMQUIC_MOQ_SUBGROUP_HEADER_v11;
	}
	/* If we're here, we're on v12 or later */
	uint8_t type = 0;
	if(subgroup) {
		sgid0 = FALSE;
		type |= 0x04;
	}
	if(sgid0)
		type |= 0x02;
	if(ext)
		type |= 0x01;
	if(eog)
		type |= 0x08;
	if(version >= IMQUIC_MOQ_VERSION_15)
		priority = TRUE;
	type |= (priority ? 0x10 : 0x30);
	return type;
}

void imquic_moq_data_message_type_to_subgroup_header(imquic_moq_version version, uint8_t type,
		gboolean *subgroup, gboolean *sgid0, gboolean *ext, gboolean *eog, gboolean *priority, gboolean *violation) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(subgroup)
			*subgroup = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_v11);
		if(sgid0)
			*sgid0 = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11);
		if(ext)
			*ext = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_v11);
		if(priority)
			*priority = TRUE;
	} else {
		/* v12 and later */
		uint8_t base = 0x10;
		if(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) {
			base = 0x10;
		} else if(type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX) {
			if(version < IMQUIC_MOQ_VERSION_15) {
				/* This range is only allowed starting from v15 */
				if(violation)
					*violation = TRUE;
				return;
			}
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
		if(ext)
			*ext = (bitmask & 0x01);
		if(eog)
			*eog = (bitmask & 0x08);
	}
}

const char *imquic_moq_data_message_type_str(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_v11:
				return "SUBGROUP_HEADER";
			case IMQUIC_MOQ_FETCH_HEADER:
				return "FETCH_HEADER";
			default: break;
		}
	} else {
		if(type == IMQUIC_MOQ_FETCH_HEADER)
			return "FETCH_HEADER";
		else if(imquic_moq_is_data_message_type_valid(version, type))
			return "SUBGROUP_HEADER";
	}
	return NULL;
}

imquic_moq_delivery imquic_moq_data_message_type_to_delivery(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11:
			case IMQUIC_MOQ_SUBGROUP_HEADER_v11:
				return IMQUIC_MOQ_USE_SUBGROUP;
			case IMQUIC_MOQ_FETCH_HEADER:
				return IMQUIC_MOQ_USE_FETCH;
			default: break;
		}
	} else {
		if(type == IMQUIC_MOQ_FETCH_HEADER)
			return IMQUIC_MOQ_USE_FETCH;
		else if((type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE1_MAX) ||
				(version >= IMQUIC_MOQ_VERSION_15 && (type >= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MIN && type <= IMQUIC_MOQ_SUBGROUP_HEADER_RANGE2_MAX)))
			return IMQUIC_MOQ_USE_SUBGROUP;
	}
	return -1;
}

const char *imquic_moq_setup_parameter_type_str(imquic_moq_setup_parameter_type type) {
	switch(type) {
		case IMQUIC_MOQ_SETUP_PARAM_PATH:
			return "PATH";
		case IMQUIC_MOQ_SETUP_PARAM_MAX_REQUEST_ID:
			return "MAX_REQUEST_ID";
		case IMQUIC_MOQ_SETUP_PARAM_AUTHORIZATION_TOKEN:
			return "AUTHORIZATION_TOKEN";
		case IMQUIC_MOQ_SETUP_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE:
			return "MAX_AUTH_TOKEN_CACHE_SIZE";
		case IMQUIC_MOQ_SETUP_PARAM_AUTHORITY:
			return "AUTHORITY";
		case IMQUIC_MOQ_SETUP_PARAM_MOQT_IMPLEMENTATION:
			return "MOQT_IMPLEMENTATION";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_request_parameter_type_str(imquic_moq_request_parameter_type type, imquic_moq_version version) {
	switch(type) {
		case IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN_v11:
			if(version < IMQUIC_MOQ_VERSION_12)
				return "AUTHORIZATION_TOKEN";
			break;
		case IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT:
			return "DELIVERY_TIMEOUT";
		case IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN:
			return "AUTHORIZATION_TOKEN";
		case IMQUIC_MOQ_REQUEST_PARAM_MAX_CACHE_DURATION:
			return "MAX_CACHE_DURATION";
		case IMQUIC_MOQ_REQUEST_PARAM_PUBLISHER_PRIORITY:
			return "PUBLISHER_PRIORITY";
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
		case IMQUIC_MOQ_REQUEST_PARAM_DYNAMIC_GROUPS:
			return "DYNAMIC_GROUPS";
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

/* MoQ parameters */
size_t imquic_moq_setup_parameters_serialize(imquic_moq_context *moq,
		imquic_moq_setup_parameters *parameters,
		uint8_t *bytes, size_t blen, uint8_t *params_num) {
	*params_num = 0;
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	if(parameters == NULL) {
		/* No parameters */
		offset += imquic_write_varint(0, &bytes[offset], blen-offset);
	} else {
		if(parameters->path_set)
			*params_num = *params_num + 1;
		if(parameters->max_request_id_set)
			*params_num = *params_num + 1;
		if(parameters->max_auth_token_cache_size_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_12 && parameters->auth_token_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_14 && parameters->authority_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_14 && parameters->moqt_implementation_set)
			*params_num = *params_num + 1;
		offset += imquic_write_varint(*params_num, &bytes[offset], blen-offset);
		if(*params_num > 0) {
			if(parameters->path_set) {
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_PATH, (uint8_t *)parameters->path, strlen(parameters->path));
			}
			if(parameters->max_request_id_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_MAX_REQUEST_ID, parameters->max_request_id);
			}
			if(parameters->max_auth_token_cache_size_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE, parameters->max_auth_token_cache_size);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_12 && parameters->auth_token_set) {
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_AUTHORIZATION_TOKEN, parameters->auth_token, parameters->auth_token_len);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_14 && parameters->authority_set) {
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_AUTHORITY, (uint8_t *)parameters->authority, strlen(parameters->authority));
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_14 && parameters->moqt_implementation_set) {
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_MOQT_IMPLEMENTATION, (uint8_t *)parameters->moqt_implementation, strlen(parameters->moqt_implementation));
			}
		}
	}
	return offset;
}

void imquic_moq_request_parameters_init_defaults(imquic_moq_request_parameters *parameters) {
	if(parameters == NULL)
		return;
	memset(parameters, 0, sizeof(imquic_moq_request_parameters));
	parameters->publisher_priority = 128;
	parameters->subscriber_priority = 128;
	parameters->group_order_ascending = TRUE;
	parameters->forward = TRUE;
}

size_t imquic_moq_request_parameters_serialize(imquic_moq_context *moq,
		imquic_moq_request_parameters *parameters,
		uint8_t *bytes, size_t blen, uint8_t *params_num) {
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	if(parameters == NULL) {
		/* No parameters */
		offset += imquic_write_varint(0, &bytes[offset], blen-offset);
	} else {
		if(parameters->auth_token_set)
			*params_num = *params_num + 1;
		if(parameters->delivery_timeout_set)
			*params_num = *params_num + 1;
		if(parameters->max_cache_duration_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->publisher_priority_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->subscriber_priority_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->group_order_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->subscription_filter_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->expires_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->largest_object_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->forward_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->dynamic_groups_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->new_group_request_set)
			*params_num = *params_num + 1;
		offset += imquic_write_varint(*params_num, &bytes[offset], blen-offset);
		if(*params_num > 0) {
			if(parameters->auth_token_set) {
				int param = (moq->version >= IMQUIC_MOQ_VERSION_12 ?
					IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN : IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN_v11);
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					param, parameters->auth_token, parameters->auth_token_len);
			}
			if(parameters->delivery_timeout_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_DELIVERY_TIMEOUT, parameters->delivery_timeout);
			}
			if(parameters->max_cache_duration_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_MAX_CACHE_DURATION, parameters->max_cache_duration);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->publisher_priority_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_PUBLISHER_PRIORITY, (uint64_t)parameters->publisher_priority);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->subscriber_priority_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY, (uint64_t)parameters->subscriber_priority);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->group_order_set) {
				uint64_t group_order = parameters->group_order_ascending ? IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER, group_order);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->subscription_filter_set) {
				uint8_t temp[40];
				size_t tlen = sizeof(temp);
				size_t toffset = imquic_write_varint(parameters->subscription_filter.type, temp, tlen);
				if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
						parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
					toffset += imquic_write_varint(parameters->subscription_filter.start_location.group, &temp[toffset], tlen-toffset);
					toffset += imquic_write_varint(parameters->subscription_filter.start_location.object, &temp[toffset], tlen-toffset);
				}
				if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
					toffset += imquic_write_varint(parameters->subscription_filter.end_group, &temp[toffset], tlen-toffset);
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER, temp, toffset);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->expires_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_EXPIRES, parameters->expires);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->largest_object_set) {
				uint8_t temp[40];
				size_t tlen = sizeof(temp);
				size_t toffset = imquic_write_varint(parameters->largest_object.group, temp, tlen);
				toffset += imquic_write_varint(parameters->largest_object.object, &temp[toffset], tlen-toffset);
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT, temp, toffset);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->forward_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_FORWARD, (uint64_t)parameters->forward);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->dynamic_groups_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_DYNAMIC_GROUPS, (uint64_t)parameters->dynamic_groups);
			}
			if(moq->version >= IMQUIC_MOQ_VERSION_15 && parameters->new_group_request_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST, (uint64_t)parameters->new_group_request);
			}
		}
	}
	return offset;
}

/* MoQ Buffer */
gboolean imquic_moq_buffer_resize(imquic_moq_buffer *buffer, uint64_t new_size) {
	if(buffer == NULL || buffer->size >= new_size)
		return FALSE;
	if(buffer->bytes == NULL)
		buffer->bytes = g_malloc(new_size);
	else
		buffer->bytes = g_realloc(buffer->bytes, new_size);
	buffer->size = new_size;
	return TRUE;
}

void imquic_moq_buffer_append(imquic_moq_buffer *buffer, uint8_t *bytes, uint64_t length) {
	if(buffer == NULL || bytes == NULL || length == 0)
		return;
	if(buffer->size < buffer->length + length) {
		if(!imquic_moq_buffer_resize(buffer, buffer->length + length)) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't resize MoQ buffer\n");
			return;
		}
	}
	memcpy(buffer->bytes + buffer->length, bytes, length);
	buffer->length += length;
}

void imquic_moq_buffer_shift(imquic_moq_buffer *buffer, uint64_t length) {
	if(buffer == NULL || buffer->bytes == NULL || length == 0)
		return;
	if(length >= buffer->length) {
		buffer->length = 0;
	} else {
		memmove(buffer->bytes, buffer->bytes + length, buffer->length - length);
		buffer->length -= length;
	}
}

void imquic_moq_buffer_destroy(imquic_moq_buffer *buffer) {
	if(buffer != NULL) {
		g_free(buffer->bytes);
		g_free(buffer);
	}
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
		imquic_moq_buffer_destroy(moq_stream->buffer);
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

#define IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, error_message, last) \
	do { \
		tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length); \
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, error_message); \
		IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces"); \
		offset += length; \
		i = 0; \
		for(i = 0; i < tns_num; i++) { \
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, error_message); \
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length); \
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, error_message); \
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
		} \
	} while(0)

#define IMQUIC_MOQ_PARSE_TRACKNAME(error_message, last) \
	do { \
		uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length); \
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
		if(tns_num == 0 || tns_num > 32) { \
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n", \
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(request, moq->version)); \
			return 0; \
		} \
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset); \
		temp = track_namespace; \
		while(temp) { \
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset); \
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
		offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset); \
		if(track_name->length > 0) { \
			memcpy(&bytes[offset], track_name->buffer, track_name->length); \
			offset += track_name->length; \
		} \
	} while(0)

#define IMQUIC_MOQ_ADD_MESSAGE_TYPE(type) \
	do { \
		offset = imquic_write_varint(type, bytes, blen); \
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
int imquic_moq_parse_message(imquic_moq_context *moq, uint64_t stream_id, uint8_t *bytes, size_t blen, gboolean complete, gboolean datagram) {
	size_t offset = 0, parsed = 0, parsed_prev = 0;
	uint8_t tlen = 0, error = 0;
	/* If this is a datagram, it can only be OBJECT_DATAGRAM or OBJECT_DATAGRAM_STATUS */
	if(datagram) {
		imquic_moq_datagram_message_type dtype = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
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
	if(stream_id == moq->control_stream_id) {
		imquic_moq_buffer_append(moq->buffer, bytes, blen);
		bytes = moq->buffer->bytes;
		blen = moq->buffer->length;
	}
	/* Iterate on all frames */
	while(moq_stream == NULL && blen-offset > 0) {
		/* If we're here, we're either on the control stream, or on a media stream waiting to know what it will be like */
		imquic_moq_message_type type = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ][%zu] >> %s (%02x, %u)\n",
			imquic_get_connection_name(moq->conn), offset, imquic_moq_message_type_str(type, moq->version), type, tlen);
		if(stream_id != moq->control_stream_id) {
			/* Not the control stream, make sure it's a supported message */
			imquic_moq_data_message_type dtype = (imquic_moq_data_message_type)type;
			if(imquic_moq_is_data_message_type_valid(moq->version, dtype)) {
				/* Create a new MoQ stream and track it */
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
		if(stream_id == moq->control_stream_id) {
			/* Control message */
			size_t plen = blen-offset;
			if((moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
					moq->version == IMQUIC_MOQ_VERSION_ANY || moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
				/* Versions 11 and beyond require a 16 bit integer */
				tlen = 2;
				if(blen - offset < tlen) {
					/* Try again later */
					IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to get the length of the control message (%"SCNu8" > %zu), waiting for more data\n",
						imquic_get_connection_name(moq->conn), tlen, blen-offset);
					return 0;
				}
				uint16_t clen = 0;
				memcpy(&clen, &bytes[offset], tlen);
				plen = ntohs(clen);
				offset += tlen;
				if(plen > blen-offset) {
					/* Try again later */
					IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to parse this message (%zu > %zu), waiting for more data\n",
						imquic_get_connection_name(moq->conn), plen, blen-offset);
					return 0;
				}
			}
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
			} else if(type == IMQUIC_MOQ_REQUEST_OK && moq->version >= IMQUIC_MOQ_VERSION_15 && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
				/* Parse this REQUEST_OK message */
				parsed = imquic_moq_parse_request_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUEST_ERROR && moq->version >= IMQUIC_MOQ_VERSION_15 && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
				/* Parse this REQUEST_ERROR message */
				parsed = imquic_moq_parse_request_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE) {
				/* Parse this PUBLISH_NAMESPACE message */
				parsed = imquic_moq_parse_publish_namespace(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_OK && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this PUBLISH_NAMESPACE_OK message */
				parsed = imquic_moq_parse_publish_namespace_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this PUBLISH_NAMESPACE_ERROR message */
				parsed = imquic_moq_parse_publish_namespace_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE) {
				/* Parse this PUBLISH_NAMESPACE_DONE message */
				parsed = imquic_moq_parse_publish_namespace_done(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL) {
				/* Parse this PUBLISH_NAMESPACE_CANCEL message */
				parsed = imquic_moq_parse_publish_namespace_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH) {
				/* Parse this PUBLISH message */
				parsed = imquic_moq_parse_publish(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_OK) {
				/* Parse this PUBLISH_OK message */
				parsed = imquic_moq_parse_publish_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this PUBLISH_ERROR message */
				parsed = imquic_moq_parse_publish_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE) {
				/* Parse this SUBSCRIBE message */
				parsed = imquic_moq_parse_subscribe(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_UPDATE) {
				/* Parse this SUBSCRIBE_UPDATE message */
				parsed = imquic_moq_parse_subscribe_update(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_OK) {
				/* Parse this SUBSCRIBE_OK message */
				parsed = imquic_moq_parse_subscribe_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this SUBSCRIBE_ERROR message */
				parsed = imquic_moq_parse_subscribe_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE) {
				/* Parse this UNSUBSCRIBE message */
				parsed = imquic_moq_parse_unsubscribe(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_DONE) {
				/* Parse this PUBLISH_DONE message */
				parsed = imquic_moq_parse_publish_done(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE) {
				/* Parse this SUBSCRIBE_NAMESPACE message */
				parsed = imquic_moq_parse_subscribe_namespace(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_OK && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this SUBSCRIBE_NAMESPACE_OK message */
				parsed = imquic_moq_parse_subscribe_namespace_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this SUBSCRIBE_NAMESPACE_ERROR message */
				parsed = imquic_moq_parse_subscribe_namespace_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE) {
				/* Parse this UNSUBSCRIBE_NAMESPACE message */
				parsed = imquic_moq_parse_unsubscribe_namespace(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH) {
				/* Parse this FETCH message */
				parsed = imquic_moq_parse_fetch(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_CANCEL) {
				/* Parse this FETCH_CANCEL message */
				parsed = imquic_moq_parse_fetch_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_OK) {
				/* Parse this FETCH_OK message */
				parsed = imquic_moq_parse_fetch_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this FETCH_ERROR message */
				parsed = imquic_moq_parse_fetch_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS) {
				/* Parse this TRACK_STATUS message */
				parsed = imquic_moq_parse_track_status(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS_OK && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this TRACK_STATUS_OK message */
				parsed = imquic_moq_parse_track_status_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS_ERROR && moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14) {
				/* Parse this TRACK_STATUS_ERROR message */
				parsed = imquic_moq_parse_track_status_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_GOAWAY) {
				/* Parse this GOAWAY message */
				parsed = imquic_moq_parse_goaway(moq, &bytes[offset], plen, &error);
			} else {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
#ifdef HAVE_QLOG
				if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
					json_t *message = imquic_qlog_moq_message_prepare("unknown");
					imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, &bytes[offset], plen, message);
				}
#endif
				imquic_moq_buffer_shift(moq->buffer, plen);
				return -1;
			}
			if(error) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Error parsing MoQ message %s: %s\n",
					imquic_get_connection_name(moq->conn),
					imquic_moq_message_type_str(type, moq->version),
					imquic_moq_error_code_str(error));
				imquic_moq_buffer_shift(moq->buffer, plen);
				if(error != IMQUIC_MOQ_UNKNOWN_ERROR)
					imquic_connection_close(moq->conn, error, IMQUIC_CONNECTION_CLOSE_APP, imquic_moq_error_code_str(error));
				return -1;
			}
			/* Move to the next message */
			if(plen < parsed) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Skipped message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
			}
			offset += plen;
			imquic_moq_buffer_shift(moq->buffer, offset);
			bytes = moq->buffer->bytes;
			blen = moq->buffer->length;
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
	if(moq_stream != NULL && blen > offset) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] MoQ media stream %"SCNu64" (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), stream_id, blen - offset);
		/* Copy the incoming data to the buffer, as we'll use that for parsing */
		imquic_moq_buffer_append(moq_stream->buffer, bytes + offset, blen - offset);
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
			imquic_connection_close(moq->conn, error, IMQUIC_CONNECTION_CLOSE_APP, imquic_moq_error_code_str(error));
			return -1;
		}
	}
	if(moq_stream != NULL && complete) {
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
		g_hash_table_remove(moq->streams, &stream_id);
	}
	/* Done */
	return 0;
}

size_t imquic_moq_parse_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	if(!moq->is_server) {
		/* Got a CLIENT_SETUP but we're a client */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Received a CLIENT_SETUP, but we're a client\n",
			imquic_get_connection_name(moq->conn));
		if(error)
			*error = IMQUIC_MOQ_PROTOCOL_VIOLATION;
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	/* Version is only negotiated here for versions up to v14 */
	uint64_t supported_vers = 0, i = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
		supported_vers = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken CLIENT_SETUP");
		offset += length;
		uint64_t version = 0;
		gboolean version_set = FALSE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- %"SCNu64" supported versions:\n",
			imquic_get_connection_name(moq->conn), supported_vers);
		g_list_free(moq->supported_versions);
		moq->supported_versions = NULL;
		for(i = 0; i<supported_vers; i++) {
			version = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken CLIENT_SETUP");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
				imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
			if(!version_set) {
				if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
					version_set = TRUE;
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- -- Selected version %"SCNu32"\n",
						imquic_get_connection_name(moq->conn), moq->version);
				} else if((version >= IMQUIC_MOQ_VERSION_MIN && version <= IMQUIC_MOQ_VERSION_14) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
					moq->version = version;
					version_set = TRUE;
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- Selected version %"SCNu32"\n",
						imquic_get_connection_name(moq->conn), moq->version);
				} else {
					/* Keep looking */
					version = 0;
				}
			}
			uint32_t v = version;
			moq->supported_versions = g_list_prepend(moq->supported_versions, GUINT_TO_POINTER(v));
			offset += length;
		}
		moq->supported_versions = g_list_reverse(moq->supported_versions);
		IMQUIC_MOQ_CHECK_ERR(version == 0, error, IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED, 0, "No supported version");
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken CLIENT_SETUP");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken CLIENT_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_setup_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		offset += imquic_moq_parse_setup_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken CLIENT_SETUP");
	}
	if(parameters.max_request_id_set) {
		/* Update the value we have */
		moq->max_request_id = parameters.max_request_id;
	}
	if(parameters.max_auth_token_cache_size) {
		/* Update the value we have */
		moq->max_auth_token_cache_size = parameters.max_auth_token_cache_size;
	}
	if(parameters.moqt_implementation_set && moq->version >= IMQUIC_MOQ_VERSION_14) {
		/* Take note of the implemntation */
		g_free(moq->peer_implementation);
		moq->peer_implementation = NULL;
		if(strlen(parameters.moqt_implementation) > 0)
			moq->peer_implementation = g_strdup(parameters.moqt_implementation);
	}
	if(parameters.path_set) {
		/* TODO Handle and validate */
		if(moq->conn->http3 != NULL && moq->conn->http3->webtransport)
			IMQUIC_MOQ_CHECK_ERR(TRUE, error, IMQUIC_MOQ_INVALID_PATH, 0, "PATH received on a WebTransport");
	}
	if(parameters.authority_set) {
		/* TODO Handle and validate */
		if(moq->conn->http3 != NULL && moq->conn->http3->webtransport)
			IMQUIC_MOQ_CHECK_ERR(TRUE, error, IMQUIC_MOQ_INVALID_PATH, 0, "AUTHORITY received on a WebTransport");
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID parameter received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
			json_object_set_new(message, "number_of_supported_versions", json_integer(supported_vers));
			json_t *versions = json_array();
			GList *temp = moq->supported_versions;
			while(temp) {
				json_array_append_new(versions, json_integer(GPOINTER_TO_UINT(temp->data)));
				temp = temp->next;
			}
			json_object_set_new(message, "supported_versions", versions);
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, &parameters, "setup_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application, if we have a callback */
	uint64_t error_code = 0;
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_moq_connection) {
		error_code = moq->conn->socket->callbacks.moq.incoming_moq_connection(moq->conn,
			(parameters.auth_token_set ? parameters.auth_token : NULL),
			(parameters.auth_token_set ? parameters.auth_token_len : 0));
	}
	IMQUIC_MOQ_CHECK_ERR(error_code > 0, error, error_code, 0, "CLIENT_SETUP rejected by application");
	/* If we got here, generate a SERVER_SETUP to send back */
	imquic_moq_setup_parameters s_parameters = { 0 };
	if(moq->local_max_request_id > 0) {
		s_parameters.max_request_id_set = TRUE;
		s_parameters.max_request_id = moq->local_max_request_id;
	}
	if(moq->local_max_auth_token_cache_size > 0) {
		s_parameters.max_auth_token_cache_size_set = TRUE;
		s_parameters.max_auth_token_cache_size = moq->local_max_auth_token_cache_size;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_14) {
		/* FIXME */
		s_parameters.moqt_implementation_set = TRUE;
		g_snprintf(s_parameters.moqt_implementation, sizeof(s_parameters.moqt_implementation), "imquic %s", imquic_version_string_full);
	}
	uint8_t buffer[200];
	size_t buflen = sizeof(buffer);
	size_t ss_len = imquic_moq_add_server_setup(moq, buffer, buflen, moq->version, &s_parameters);
	imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, ss_len, FALSE);
	moq->control_stream_offset += ss_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	if(bytes == NULL || blen < 5)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	/* Version is only negotiated here for versions up to v14 */
	uint64_t version = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Supported version:\n",
			imquic_get_connection_name(moq->conn));
		version = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SERVER_SETUP");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
			imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
		if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
				imquic_get_connection_name(moq->conn), moq->version);
		} else if((version >= IMQUIC_MOQ_VERSION_MIN && version <= IMQUIC_MOQ_VERSION_14) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
			moq->version = version;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
				imquic_get_connection_name(moq->conn), moq->version);
		} else {
			IMQUIC_MOQ_CHECK_ERR(version == 0, error, IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED, 0, "No supported version");
		}
		offset += length;
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SERVER_SETUP");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SERVER_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	imquic_moq_setup_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		offset += imquic_moq_parse_setup_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SERVER_SETUP");
	}
	if(parameters.max_request_id_set) {
		/* Update the value we have */
		moq->max_request_id = parameters.max_request_id;
	}
	if(parameters.max_auth_token_cache_size_set) {
		/* Update the value we have */
		moq->max_auth_token_cache_size = parameters.max_auth_token_cache_size;
	}
	if(parameters.moqt_implementation_set && moq->version >= IMQUIC_MOQ_VERSION_14) {
		/* Take note of the implemntation */
		g_free(moq->peer_implementation);
		moq->peer_implementation = NULL;
		if(strlen(parameters.moqt_implementation) > 0)
			moq->peer_implementation = g_strdup(parameters.moqt_implementation);
	}
	if(parameters.path_set) {
		/* Servers can't use PATH */
		IMQUIC_MOQ_CHECK_ERR(version == 0, error, IMQUIC_MOQ_INVALID_PATH, 0, "PATH received from a server");
	}
	if(parameters.authority_set) {
		/* Servers can't use AUTHORITY */
		IMQUIC_MOQ_CHECK_ERR(version == 0, error, IMQUIC_MOQ_INVALID_PATH, 0, "AUTHORITY received from a server");
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID parameter received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14))
			json_object_set_new(message, "selected_version", json_integer(version));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, &parameters, "setup_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
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

size_t imquic_moq_parse_max_request_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_varint(&bytes[offset], blen-offset, &length) + 1;
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_requests_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUESTS_BLOCKED");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Maximum Request ID %"SCNu64":\n",
		imquic_get_connection_name(moq->conn), max);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("requests_blocked");
		json_object_set_new(message, "maximum_request_id", json_integer(max));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.requests_blocked)
		moq->conn->socket->callbacks.moq.requests_blocked(moq->conn, max);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_request_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken REQUEST_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken REQUEST_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken REQUEST_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken REQUEST_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken REQUEST_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application, but we'll need to check which callback to trigger */
	imquic_mutex_lock(&moq->mutex);
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
		case IMQUIC_MOQ_SUBSCRIBE_UPDATE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_update_accepted)
				moq->conn->socket->callbacks.moq.subscribe_update_accepted(moq->conn, request_id, &parameters);
			break;
		case IMQUIC_MOQ_TRACK_STATUS:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_accepted)
				moq->conn->socket->callbacks.moq.track_status_accepted(moq->conn, request_id, 0, &parameters);
			break;
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Couldn't find a request associated to ID %"SCNu64" (type %d), can't notify success\n",
				imquic_get_connection_name(moq->conn), request_id, type);
			break;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_request_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken REQUEST_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application, but we'll need to check which callback to trigger */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_message_type type = GPOINTER_TO_UINT(g_hash_table_lookup(moq->requests, &request_id));
	g_hash_table_remove(moq->requests, &request_id);
	imquic_mutex_unlock(&moq->mutex);
	switch(type) {
		case IMQUIC_MOQ_PUBLISH_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_error)
				moq->conn->socket->callbacks.moq.publish_namespace_error(moq->conn, request_id, error_code, reason_str);
			break;
		case IMQUIC_MOQ_PUBLISH:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_error)
				moq->conn->socket->callbacks.moq.publish_error(moq->conn, request_id, error_code, reason_str);
			break;
		case IMQUIC_MOQ_SUBSCRIBE_NAMESPACE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_namespace_error)
				moq->conn->socket->callbacks.moq.subscribe_namespace_error(moq->conn, request_id, error_code, reason_str);
			break;
		case IMQUIC_MOQ_SUBSCRIBE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_error)
				moq->conn->socket->callbacks.moq.subscribe_error(moq->conn, request_id, error_code, reason_str, 0);
			break;
		case IMQUIC_MOQ_SUBSCRIBE_UPDATE:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_update_error)
				moq->conn->socket->callbacks.moq.subscribe_update_error(moq->conn, request_id, error_code, reason_str);
			break;
		case IMQUIC_MOQ_FETCH:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_error)
				moq->conn->socket->callbacks.moq.fetch_error(moq->conn, request_id, error_code, reason_str);
			break;
		case IMQUIC_MOQ_TRACK_STATUS:
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_error)
				moq->conn->socket->callbacks.moq.track_status_error(moq->conn, request_id, error_code, reason_str);
			break;
		default:
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Couldn't find a request associated to ID %"SCNu64" (type %d), can't notify error\n",
				imquic_get_connection_name(moq->conn), request_id, type);
			break;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken PUBLISH_NAMESPACE", FALSE);
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken PUBLISH_NAMESPACE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish_namespace) {
		moq->conn->socket->callbacks.moq.incoming_publish_namespace(moq->conn, request_id, &tns[0], &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_publish_namespace(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "publish_namespace_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_accepted) {
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		moq->conn->socket->callbacks.moq.publish_namespace_accepted(moq->conn, request_id, &params);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_namespace_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "publish_namespace_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_error) {
		moq->conn->socket->callbacks.moq.publish_namespace_error(moq->conn,
			request_id, error_code, reason_str);
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
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken PUBLISH_NAMESPACE_DONE", TRUE);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_done");
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_namespace_done)
		moq->conn->socket->callbacks.moq.publish_namespace_done(moq->conn, &tns[0]);
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
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t error_code = 0;
	char reason[1024], *reason_str = NULL;
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken PUBLISH_NAMESPACE_CANCEL", FALSE);
	error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_CANCEL");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_NAMESPACE_CANCEL");
	offset += length;
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
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish_namespace_cancel)
		moq->conn->socket->callbacks.moq.incoming_publish_namespace_cancel(moq->conn, &tns[0], error_code, reason);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken PUBLISH", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken PUBLISH", FALSE);
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(group_order > IMQUIC_MOQ_ORDERING_DESCENDING, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint8_t content_exists = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(content_exists > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
		IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), content_exists);
		if(content_exists > 0) {
			parameters.largest_object_set = TRUE;
			parameters.largest_object.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.group);
			parameters.largest_object.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.object);
		}
		uint8_t forward = bytes[offset];
		IMQUIC_MOQ_CHECK_ERR(forward > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		parameters.forward_set = TRUE;
		parameters.forward = (forward > 0);
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.forward);
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken PUBLISH");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters.largest_object_set));
			if(parameters.largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters.largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters.largest_object.object));
			}
			json_object_set_new(message, "forward", json_integer(parameters.forward));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish) {
		moq->conn->socket->callbacks.moq.incoming_publish(moq->conn,
			request_id, &tns[0], &tn, track_alias, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_publish(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		uint8_t forward = bytes[offset];
		IMQUIC_MOQ_CHECK_ERR(forward > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		parameters.forward_set = TRUE;
		parameters.forward = (forward > 0);
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.forward);
		parameters.subscriber_priority_set = TRUE;
		parameters.subscriber_priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.subscriber_priority);
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR((group_order > IMQUIC_MOQ_ORDERING_DESCENDING), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
		IMQUIC_MOQ_CHECK_ERR((filter < 0x1 || filter > 0x4), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Filter type");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
			imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
		parameters.subscription_filter_set = TRUE;
		parameters.subscription_filter.type = filter;
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.start_location.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.group);
			parameters.subscription_filter.start_location.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.object);
		}
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.end_group);
		}
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken PUBLISH_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken PUBLISH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken PUBLISH_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "forward", json_integer(parameters.forward));
			json_object_set_new(message, "subscriber_priority", json_integer(parameters.subscriber_priority));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "filter_type", json_integer(parameters.subscription_filter.type));
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters.subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters.subscription_filter.start_location.object));
			}
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
				json_object_set_new(message, "end_group", json_integer(parameters.subscription_filter.end_group));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_accepted)
		moq->conn->socket->callbacks.moq.publish_accepted(moq->conn, request_id, &parameters);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_ERROR");
	offset += length;
	uint64_t recvd_error_code = error_code;
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error_code = imquic_moq_request_error_code_from_legacy(moq->version, error_code);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_error_code_str(error_code), recvd_error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken PUBLISH_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "publish_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(recvd_error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_error)
		moq->conn->socket->callbacks.moq.publish_error(moq->conn, request_id, error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Move on */
	uint64_t track_alias = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), track_alias);
	}
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken SUBSCRIBE", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken SUBSCRIBE", FALSE);
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.subscriber_priority_set = TRUE;
		parameters.subscriber_priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.subscriber_priority);
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR((group_order > IMQUIC_MOQ_ORDERING_DESCENDING), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint8_t forward = bytes[offset];
		IMQUIC_MOQ_CHECK_ERR(forward > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		parameters.forward_set = TRUE;
		parameters.forward = (forward > 0);
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), forward);
		uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_MOQ_CHECK_ERR((filter < 0x1 || filter > 0x4), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Filter type");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
			imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
		parameters.subscription_filter_set = TRUE;
		parameters.subscription_filter.type = filter;
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.start_location.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.group);
			parameters.subscription_filter.start_location.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.object);
		}
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.end_group);
		}
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters.subscriber_priority));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "forward", json_integer(parameters.forward));
			json_object_set_new(message, "filter_type", json_integer(parameters.subscription_filter.type));
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters.subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters.subscription_filter.start_location.object));
			}
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
				json_object_set_new(message, "end_group", json_integer(parameters.subscription_filter.end_group));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Track this subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, track_alias);
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	if(moq->version < IMQUIC_MOQ_VERSION_12)
		g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe) {
		moq->conn->socket->callbacks.moq.incoming_subscribe(moq->conn,
			request_id, track_alias, &tns[0], &tn, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled", track_alias);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t sub_request_id = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_14) {
		sub_request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscription Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), sub_request_id);
	}
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.subscription_filter_set = TRUE;
		parameters.subscription_filter.type = IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE;	/* FIXME */
		parameters.subscription_filter.start_location.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.group);
		parameters.subscription_filter.start_location.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.object);
		parameters.subscription_filter.end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), parameters.subscription_filter.end_group);
		parameters.subscriber_priority_set = TRUE;
		parameters.subscriber_priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.subscriber_priority);
		uint8_t forward = bytes[offset];
		IMQUIC_MOQ_CHECK_ERR(forward > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		parameters.forward_set = TRUE;
		parameters.forward = (forward > 0);
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), forward);
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_14)
			json_object_set_new(message, "subscription_request_id", json_integer(sub_request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "start_group", json_integer(parameters.subscription_filter.start_location.group));
			json_object_set_new(message, "start_object", json_integer(parameters.subscription_filter.start_location.object));
			json_object_set_new(message, "end_group", json_integer(parameters.subscription_filter.end_group));
			json_object_set_new(message, "subscriber_priority", json_integer(parameters.subscriber_priority));
			json_object_set_new(message, "forward", json_integer(parameters.forward));
			json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		}
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	if(moq->version >= IMQUIC_MOQ_VERSION_14) {
		/* Make sure this is in line with the expected request ID */
		IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
		moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_updated) {
		moq->conn->socket->callbacks.moq.subscribe_updated(moq->conn,
			request_id, sub_request_id, &parameters);
	} else if(moq->version != IMQUIC_MOQ_VERSION_15) {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe_update(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t track_alias = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_12) {
		track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), track_alias);
	}
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.expires_set = TRUE;
		parameters.expires = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Expires: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), parameters.expires);
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR((group_order > IMQUIC_MOQ_ORDERING_DESCENDING), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint8_t content_exists = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(content_exists > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
		IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), content_exists);
		if(content_exists > 0) {
			parameters.largest_object_set = TRUE;
			parameters.largest_object.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.group);
			parameters.largest_object.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.object);
		}
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "expires", json_integer(parameters.expires));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters.largest_object_set));
			if(parameters.largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters.largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters.largest_object.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_accepted) {
		moq->conn->socket->callbacks.moq.subscribe_accepted(moq->conn,
			request_id, track_alias, &parameters);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	uint64_t recvd_error_code = error_code;
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error_code = imquic_moq_request_error_code_from_legacy(moq->version, error_code);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_error_code_str(error_code), recvd_error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
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
	uint64_t track_alias = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
		track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), track_alias);
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "error_code", json_integer(recvd_error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_error) {
		moq->conn->socket->callbacks.moq.subscribe_error(moq->conn,
			request_id, error_code, reason_str, track_alias);
	}
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
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_publish_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t status_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_pub_done_code_str(status_code), status_code);
	uint64_t streams_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Streams Count: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), streams_count);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status_code));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_done) {
		moq->conn->socket->callbacks.moq.publish_done(moq->conn,
			request_id, status_code, streams_count, reason_str);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken SUBSCRIBE_NAMESPACE", FALSE);
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_request_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe_namespace) {
		moq->conn->socket->callbacks.moq.incoming_subscribe_namespace(moq->conn,
			request_id, &tns[0], &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe_namespace(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_namespace_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "subscribe_namespace_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_namespace_accepted) {
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		moq->conn->socket->callbacks.moq.subscribe_namespace_accepted(moq->conn, request_id, &params);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_namespace_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_NAMESPACE_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "subscribe_namespace_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_namespace_error)
		moq->conn->socket->callbacks.moq.subscribe_namespace_error(moq->conn, request_id, error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unsubscribe_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	uint64_t request_id = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE_NAMESPACE");
		offset += length;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken UNSUBSCRIBE_NAMESPACE", TRUE);
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe_namespace");
		if(moq->version >= IMQUIC_MOQ_VERSION_15)
			json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14)
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe_namespace)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe_namespace(moq->conn, request_id, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Move on */
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	imquic_moq_name tn = { 0 };
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.subscriber_priority_set = TRUE;
		parameters.subscriber_priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.subscriber_priority);
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(group_order > IMQUIC_MOQ_ORDERING_DESCENDING, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
	}
	imquic_moq_fetch_type type = IMQUIC_MOQ_FETCH_STANDALONE;
	imquic_moq_location_range range = { 0 };
	uint64_t joining_request_id = 0, joining_start = 0;
	type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
		uint64_t tns_num = 0, i = 0;
		IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken FETCH", FALSE);
		IMQUIC_MOQ_PARSE_TRACKNAME("Broken FETCH", FALSE);
		range.start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.start.group);
		range.start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.start.object);
		range.end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.end.group);
		range.end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), range.end.object);
	} else if(type == IMQUIC_MOQ_FETCH_JOINING_RELATIVE || type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE) {
		joining_request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		joining_start = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
	} else {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Broken FETCH, invalid type '%d'\n",
			imquic_get_connection_name(moq->conn), type);
		return 0;
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken FETCH");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken FETCH");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters.subscriber_priority));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
		}
		json_object_set_new(message, "fetch_type", json_integer(type));
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
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
				request_id, &tns[0], &tn, &range, &parameters);
		} else {
			/* No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
		}
	} else {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_joining_fetch) {
			moq->conn->socket->callbacks.moq.incoming_joining_fetch(moq->conn,
				request_id, joining_request_id,
				(type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE), joining_start, &parameters);
		} else {
			/* No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
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
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_fetch_cancel)
		moq->conn->socket->callbacks.moq.incoming_fetch_cancel(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(group_order > IMQUIC_MOQ_ORDERING_DESCENDING, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
	}
	uint8_t end_of_track = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Of Track: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), end_of_track);
	imquic_moq_location largest = { 0 };
	largest.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.group);
	largest.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.object);
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken FETCH_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken FETCH_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
		}
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(largest.group));
		json_object_set_new(message, "largest_object_id", json_integer(largest.object));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_accepted)
		moq->conn->socket->callbacks.moq.fetch_accepted(moq->conn, request_id, &largest, &parameters);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
	offset += length;
	uint64_t recvd_error_code = error_code;
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error_code = imquic_moq_request_error_code_from_legacy(moq->version, error_code);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_error_code_str(error_code), recvd_error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "fetch_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(recvd_error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_error)
		moq->conn->socket->callbacks.moq.fetch_error(moq->conn, request_id, error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_13) {
		/* Since the format changed too much, we ignored it on versions older than v13 */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Ignoring %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS, moq->version),
			imquic_moq_version_str(moq->version));
		return blen;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Move on */
	imquic_moq_namespace tns[32];
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = 0, i = 0;
	IMQUIC_MOQ_PARSE_NAMESPACES(tns_num, i, "Broken TRACK_STATUS", FALSE);
	imquic_moq_name tn = { 0 };
	IMQUIC_MOQ_PARSE_TRACKNAME("Broken TRACK_STATUS", FALSE);
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.subscriber_priority_set = TRUE;
		parameters.subscriber_priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.subscriber_priority);
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(group_order > IMQUIC_MOQ_ORDERING_DESCENDING, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint8_t forward = bytes[offset];
		IMQUIC_MOQ_CHECK_ERR(forward > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		parameters.forward_set = TRUE;
		parameters.forward = (forward > 0);
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), parameters.forward);
		uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_MOQ_CHECK_ERR((filter < 0x1 || filter > 0x4), error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Filter type");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
			imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
		parameters.subscription_filter_set = TRUE;
		parameters.subscription_filter.type = filter;
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.start_location.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.group);
			parameters.subscription_filter.start_location.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.start_location.object);
		}
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			parameters.subscription_filter.end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), parameters.subscription_filter.end_group);
		}
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken TRACK_STATUS");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken TRACK_STATUS");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters.subscriber_priority));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "forward", json_integer(parameters.forward));
			json_object_set_new(message, "filter_type", json_integer(parameters.subscription_filter.type));
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters.subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters.subscription_filter.start_location.object));
			}
			if(parameters.subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
				json_object_set_new(message, "end_group", json_integer(parameters.subscription_filter.end_group));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(!moq_is_request_id_valid(moq, request_id, FALSE), error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	moq->expected_request_id = request_id + IMQUIC_MOQ_REQUEST_ID_INCREMENT;
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status) {
		moq->conn->socket->callbacks.moq.incoming_track_status(moq->conn,
			request_id, &tns[0], &tn, &parameters);
	} else {
		/* No handler for this request, let's reject it ourselves */
		imquic_moq_reject_track_status(moq->conn, request_id, IMQUIC_MOQ_REQERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_13) {
		/* Since the format changed too much, we ignored it on versions older than v13 */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Ignoring %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS, moq->version),
			imquic_moq_version_str(moq->version));
		return blen;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t track_alias = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), track_alias);
	}
	/* For versions older than v15, we need to parse some attributes manually,
	 * but we'll add them to the parameters object for the application anyway */
	imquic_moq_request_parameters parameters;
	imquic_moq_request_parameters_init_defaults(&parameters);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		parameters.expires_set = TRUE;
		parameters.expires = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Expires: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), parameters.expires);
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		uint8_t group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(group_order > IMQUIC_MOQ_ORDERING_DESCENDING, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), group_order);
		parameters.group_order_set = TRUE;
		parameters.group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		uint8_t content_exists = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(content_exists > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
		IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), content_exists);
		if(content_exists > 0) {
			parameters.largest_object_set = TRUE;
			parameters.largest_object.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.group);
			parameters.largest_object.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), parameters.largest_object.object);
		}
	}
	uint64_t params_num = 0;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_OK");
	params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params_num > 0 && (length == 0 || length >= blen-offset), NULL, 0, 0, "Broken TRACK_STATUS_OK");
	IMQUIC_MOQ_CHECK_ERR(params_num == 0 && (length == 0 || length > blen-offset), NULL, 0, 0, "Broken TRACK_STATUS_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_OK");
		offset += imquic_moq_parse_request_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken TRACK_STATUS_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "track_status_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "track_alias", json_integer(track_alias));
			json_object_set_new(message, "expires", json_integer(parameters.expires));
			json_object_set_new(message, "group_order", json_integer(parameters.group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters.largest_object_set));
			if(parameters.largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters.largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters.largest_object.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_accepted) {
		moq->conn->socket->callbacks.moq.track_status_accepted(moq->conn,
			request_id, track_alias, &parameters);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_13)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_ERROR");
	offset += length;
	uint64_t recvd_error_code = error_code;
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error_code = imquic_moq_request_error_code_from_legacy(moq->version, error_code);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_error_code_str(error_code), recvd_error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "track_status_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(recvd_error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.track_status_error)
		moq->conn->socket->callbacks.moq.track_status_error(moq->conn, request_id, error_code, reason_str);
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
	gboolean has_ext = FALSE, has_oid = TRUE, has_priority = TRUE;
	imquic_moq_datagram_message_type_parse(moq->version, dtype, NULL, &has_ext, NULL, &has_oid, &has_priority, NULL);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = 0;
	if(has_oid) {
		object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
	size_t ext_offset = 0, ext_len = 0;
	if(has_ext) {
		/* The object contains extensions */
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		IMQUIC_MOQ_CHECK_ERR(ext_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions length is 0 but type is OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || ext_len >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		offset += ext_len;
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
		.extensions = (ext_len > 0 ? &bytes[ext_offset] : NULL),
		.extensions_len = ext_len,
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
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_datagram_message_type dtype, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	gboolean has_ext = FALSE, has_oid = TRUE, has_priority = TRUE;
	imquic_moq_datagram_message_type_parse(moq->version, dtype, NULL, &has_ext, NULL, &has_oid, &has_priority, NULL);
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(has_oid) {
		object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
	size_t ext_offset = 0, ext_len = 0;
	if(has_ext) {
		/* The object contains extensions */
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		IMQUIC_MOQ_CHECK_ERR(ext_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions length is 0 but type is OBJECT_DATAGRAM_STATUS");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || ext_len >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		offset += ext_len;
	}
	uint64_t object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
	IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && ext_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions received in object with status 'Does Not Exist'");
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
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
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
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t subgroup_id = 0;
	/* Starting from v11, the subgroup ID property is optional */
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_ext = FALSE, is_eog = FALSE, has_priority = FALSE, violation = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, dtype,
		&has_subgroup, &is_sgid0, &has_ext, &is_eog, &has_priority, &violation);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][MoQ] SUBGROUP_HEADER type %02x: sg=%d, sgid0=%d, ext=%d, eog=%d, pri=%d, viol=%d\n",
		imquic_get_connection_name(moq->conn), dtype, has_subgroup, is_sgid0, has_ext, is_eog, has_priority, violation);
	IMQUIC_MOQ_CHECK_ERR(violation, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid SUBGROUP_HEADER type");
	if(has_subgroup) {
		subgroup_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
		moq_stream->request_id = 0;	/* TODO remove? */
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->subgroup_id = subgroup_id;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
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
	/* Note: this will be a delta, on v14 and later */
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	size_t ext_offset = 0, ext_len = 0;
	/* TODO We can optimize this by only doing it once, when we parse the header */
	/* TODO Check EOG too */
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_ext = FALSE, has_priority = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, &has_subgroup, &is_sgid0, &has_ext, NULL, &has_priority, NULL);
	if(has_ext) {
		/* The object contains extensions */
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		if(length == 0 || ext_len >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += ext_len;
	}
	uint64_t p_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_status = 0;
	if(p_len == 0) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
		/* TODO An invalid object status should be a protocol violation error */
		//~ IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
		//~ IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && ext_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions received in object with status 'Does Not Exist'");
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
	if(moq->version >= IMQUIC_MOQ_VERSION_14) {
		/* Object IDs are a delta, starting from v14 */
		object_id += moq_stream->last_object_id;
		if(moq_stream->got_objects)
			object_id++;
	}
	if(!moq_stream->got_objects)
		moq_stream->got_objects = TRUE;
	moq_stream->last_object_id = object_id;
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
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.delivery = IMQUIC_MOQ_USE_SUBGROUP,
		.end_of_stream = complete
	};
#ifdef HAVE_QLOG
	if(moq_stream != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq)
		imquic_moq_qlog_subgroup_object_parsed(moq->conn->qlog, moq_stream->stream_id, &object);
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	/* Move on */
	offset += p_len;
	imquic_moq_buffer_shift(moq_stream->buffer, offset);
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
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
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
	uint8_t flags = 0xFF, lsb = flags & 0x03;
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		flags = bytes[offset];
		offset++;
	}
	if(length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	uint64_t group_id = 0;
	if(flags & 0x08) {
		group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* TODO The group ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		group_id = moq_stream->group_id;
	}
	uint64_t subgroup_id = 0;
	if(lsb == 0x03) {
		subgroup_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* TODO The subgroup ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		if(lsb == 0x01)
			subgroup_id = moq_stream->subgroup_id;
		else if(lsb == 0x02)
			subgroup_id = moq_stream->subgroup_id + 1;
	}
	uint64_t object_id = 0;
	if(flags & 0x08) {
		object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	} else {
		/* The object ID references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		object_id = moq_stream->last_object_id + 1;
	}
	uint8_t priority = 0;
	if(flags & 0x10) {
		priority = bytes[offset];
		offset++;
	} else {
		/* The priority references a previous object */
		IMQUIC_MOQ_CHECK_ERR(!moq_stream->got_objects, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, -1, "Serialization flag references non-existing previous object");
		priority = moq_stream->last_priority;
	}
	size_t ext_offset = 0, ext_len = 0;
	if(flags & 0x20) {
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		if(length == 0 || ext_len >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += ext_len;
	}
	uint64_t p_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_status = 0;
	if(p_len == 0) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
		/* TODO An invalid object status should be a protocol violation error */
		//~ IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
		//~ IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && ext_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions received in object with status 'Does Not Exist'");
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
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.delivery = IMQUIC_MOQ_USE_FETCH,
		.end_of_stream = complete
	};
#ifdef HAVE_QLOG
	if(moq_stream != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq)
		imquic_moq_qlog_fetch_object_parsed(moq->conn->qlog, moq_stream->stream_id, &object);
#endif
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	/* Move on */
	offset += p_len;
	imquic_moq_buffer_shift(moq_stream->buffer, offset);
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
	uint64_t uri_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
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
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("goaway");
		imquic_qlog_event_add_raw(message, "new_session_uri", (uint8_t *)uri_str, uri_len);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, bytes-3, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_goaway)
		moq->conn->socket->callbacks.moq.incoming_goaway(moq->conn, uri_str);
	if(error)
		*error = 0;
	return offset;
}

/* Message building */
size_t imquic_moq_add_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		GList *supported_versions, imquic_moq_setup_parameters *parameters) {
	if(bytes == NULL || blen < 4 || (g_list_length(supported_versions) < 1 &&
			(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_CLIENT_SETUP, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_CLIENT_SETUP);
	/* Version is only negotiated here for versions up to v14 */
	if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
		offset += imquic_write_varint(g_list_length(supported_versions), &bytes[offset], blen-offset);
		GList *temp = supported_versions;
		while(temp) {
			uint32_t version = GPOINTER_TO_UINT(temp->data);
			offset += imquic_write_varint(version, &bytes[offset], blen-offset);
			temp = temp->next;
		}
	}
	uint8_t params_num = 0;
	offset += imquic_moq_setup_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14)) {
			json_object_set_new(message, "number_of_supported_versions", json_integer(g_list_length(supported_versions)));
			json_t *versions = json_array();
			GList *temp = supported_versions;
			temp = supported_versions;
			while(temp) {
				uint32_t version = GPOINTER_TO_UINT(temp->data);
				json_array_append_new(versions, json_integer(version));
				temp = temp->next;
			}
			json_object_set_new(message, "supported_versions", versions);
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, parameters, "setup_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint32_t version, imquic_moq_setup_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SERVER_SETUP, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SERVER_SETUP);
	/* Version is only negotiated here for versions up to v14 */
	if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14))
		offset += imquic_write_varint(version, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_setup_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_14))
			json_object_set_new(message, "selected_version", json_integer(version));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, parameters, "setup_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_max_request_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_MAX_REQUEST_ID, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_MAX_REQUEST_ID);
	offset += imquic_write_varint(max_request_id, &bytes[offset], blen-offset);
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
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUESTS_BLOCKED, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUESTS_BLOCKED);
	offset += imquic_write_varint(max_request_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_request_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUEST_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUEST_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_request_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUEST_ERROR, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_REQUEST_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("request_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH_NAMESPACE);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "publish_namespace_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "publish_namespace_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH_NAMESPACE_DONE);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_done");
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_namespace_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH_NAMESPACE_CANCEL);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_namespace_cancel");
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_PUBLISH);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_PUBLISH);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		bytes[offset] = parameters->largest_object_set;
		offset++;
		if(parameters->largest_object_set) {
			offset += imquic_write_varint(parameters->largest_object.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->largest_object.object, &bytes[offset], blen-offset);
		}
		bytes[offset] = parameters->forward;
		offset++;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters->largest_object_set));
			if(parameters->largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters->largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters->largest_object.object));
			}
			json_object_set_new(message, "forward", json_integer(parameters->forward));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->forward;
		offset++;
		bytes[offset] = parameters->subscriber_priority_set ?
			parameters->subscriber_priority : 128;
		offset++;
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		offset += imquic_write_varint(parameters->subscription_filter.type, &bytes[offset], blen-offset);
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			offset += imquic_write_varint(parameters->subscription_filter.start_location.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->subscription_filter.start_location.object, &bytes[offset], blen-offset);
		}
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
			offset += imquic_write_varint(parameters->subscription_filter.end_group, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "forward", json_integer(parameters->forward));
			json_object_set_new(message, "subscriber_priority", json_integer(parameters->subscriber_priority_set ?
				parameters->subscriber_priority : 128));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "filter_type", json_integer(parameters->subscription_filter.type));
			if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters->subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters->subscription_filter.start_location.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_12)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_SUBSCRIBE);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->subscriber_priority_set ?
			parameters->subscriber_priority : 128;
		offset++;
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		bytes[offset] = parameters->forward;
		offset++;
		offset += imquic_write_varint(parameters->subscription_filter.type, &bytes[offset], blen-offset);
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			offset += imquic_write_varint(parameters->subscription_filter.start_location.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->subscription_filter.start_location.object, &bytes[offset], blen-offset);
		}
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
			offset += imquic_write_varint(parameters->subscription_filter.end_group, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters->subscriber_priority_set ?
				parameters->subscriber_priority : 128));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "forward", json_integer(parameters->forward));
			json_object_set_new(message, "filter_type", json_integer(parameters->subscription_filter.type));
			if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters->subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters->subscription_filter.start_location.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t sub_request_id, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_UPDATE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_UPDATE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_14)
		offset += imquic_write_varint(sub_request_id, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		offset += imquic_write_varint(parameters->subscription_filter.start_location.group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(parameters->subscription_filter.start_location.object, &bytes[offset], blen-offset);
		offset += imquic_write_varint(parameters->subscription_filter.end_group, &bytes[offset], blen-offset);
		bytes[offset] = parameters->subscriber_priority_set ?
			parameters->subscriber_priority : 128;
		offset++;
		bytes[offset] = parameters->forward;
		offset++;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_14)
			json_object_set_new(message, "subscription_request_id", json_integer(sub_request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "start_group", json_integer(parameters->subscription_filter.start_location.group));
			json_object_set_new(message, "start_object", json_integer(parameters->subscription_filter.start_location.object));
			json_object_set_new(message, "end_group", json_integer(parameters->subscription_filter.end_group));
			json_object_set_new(message, "subscriber_priority", json_integer(parameters->subscriber_priority_set ?
				parameters->subscriber_priority : 128));
			json_object_set_new(message, "forward", json_integer(parameters->forward));
		}
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_12)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		offset += imquic_write_varint(parameters->expires, &bytes[offset], blen-offset);
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		bytes[offset] = parameters->largest_object_set;
		offset++;
		if(parameters->largest_object_set) {
			offset += imquic_write_varint(parameters->largest_object.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->largest_object.object, &bytes[offset], blen-offset);
		}
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "expires", json_integer(parameters->expires));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters->largest_object_set));
			if(parameters->largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters->largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters->largest_object.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason, uint64_t track_alias) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_12)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_UNSUBSCRIBE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_publish_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_pub_done_code status, uint64_t streams_count, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_DONE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_PUBLISH_DONE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(status, &bytes[offset], blen-offset);
	offset += imquic_write_varint(streams_count, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_done");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_namespace");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_namespace_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "subscribe_namespace_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_namespace_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "subscribe_namespace_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unsubscribe_namespace(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || (moq->version <= IMQUIC_MOQ_VERSION_14 && track_namespace == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE);
	if(moq->version >= IMQUIC_MOQ_VERSION_15)
		offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_UNSUBSCRIBE_NAMESPACE);
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe_namespace");
		if(moq->version >= IMQUIC_MOQ_VERSION_15)
			json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14)
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_fetch_type type,
		uint64_t request_id, uint64_t joining_request_id, uint64_t preceding_group_offset,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name,
		imquic_moq_location_range *range, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (range == NULL && type == IMQUIC_MOQ_FETCH_STANDALONE)) {
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
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->subscriber_priority_set ?
			parameters->subscriber_priority : 128;
		offset++;
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
	}
	offset += imquic_write_varint(type, &bytes[offset], blen-offset);
	if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
		IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_FETCH);
		IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_FETCH);
		offset += imquic_write_varint(range->start.group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->start.object, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->end.group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->end.object, &bytes[offset], blen-offset);
	} else {
		offset += imquic_write_varint(joining_request_id, &bytes[offset], blen-offset);
		offset += imquic_write_varint(preceding_group_offset, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters->subscriber_priority_set ?
				parameters->subscriber_priority : 128));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
		}
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
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
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_CANCEL, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH_CANCEL);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		uint8_t end_of_track, imquic_moq_location *end_location, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
	}
	bytes[offset] = end_of_track;
	offset++;
	offset += imquic_write_varint(end_location->group, &bytes[offset], blen-offset);
	offset += imquic_write_varint(end_location->object, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
		}
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(end_location->group));
		json_object_set_new(message, "largest_object_id", json_integer(end_location->object));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_FETCH_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "fetch_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_TRACK_STATUS);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	IMQUIC_MOQ_ADD_NAMESPACES(IMQUIC_MOQ_TRACK_STATUS);
	IMQUIC_MOQ_ADD_TRACKNAME(IMQUIC_MOQ_TRACK_STATUS);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		bytes[offset] = parameters->subscriber_priority_set ?
			parameters->subscriber_priority : 128;
		offset++;
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		bytes[offset] = parameters->forward;
		offset++;
		offset += imquic_write_varint(parameters->subscription_filter.type, &bytes[offset], blen-offset);
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			offset += imquic_write_varint(parameters->subscription_filter.start_location.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->subscription_filter.start_location.object, &bytes[offset], blen-offset);
		}
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
			offset += imquic_write_varint(parameters->subscription_filter.end_group, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "subscriber_priority", json_integer(parameters->subscriber_priority_set ?
				parameters->subscriber_priority : 128));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "forward", json_integer(parameters->forward));
			json_object_set_new(message, "filter_type", json_integer(parameters->subscription_filter.type));
			if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START || parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
				json_object_set_new(message, "start_group", json_integer(parameters->subscription_filter.start_location.group));
				json_object_set_new(message, "start_object", json_integer(parameters->subscription_filter.start_location.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_OK, moq->version));
		return 0;
	}
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_TRACK_STATUS_OK);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	if(moq->version <= IMQUIC_MOQ_VERSION_14)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	/* For versions older than v15, we need to add some attributes manually,
	 * but we'll read them from the parameters object the application passed */
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		offset += imquic_write_varint(parameters->expires, &bytes[offset], blen-offset);
		bytes[offset] = parameters->group_order_ascending ?
			IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING;
		offset++;
		bytes[offset] = parameters->largest_object_set;
		offset++;
		if(parameters->largest_object_set) {
			offset += imquic_write_varint(parameters->largest_object.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(parameters->largest_object.object, &bytes[offset], blen-offset);
		}
	}
	uint8_t params_num = 0;
	offset += imquic_moq_request_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_ok" : "track_status_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version <= IMQUIC_MOQ_VERSION_14)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		if(moq->version <= IMQUIC_MOQ_VERSION_14) {
			json_object_set_new(message, "expires", json_integer(parameters->expires));
			json_object_set_new(message, "group_order", json_integer(parameters->group_order_ascending ?
				IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
			json_object_set_new(message, "content_exists", json_integer(parameters->largest_object_set));
			if(parameters->largest_object_set) {
				json_object_set_new(message, "largest_group_id", json_integer(parameters->largest_object.group));
				json_object_set_new(message, "largest_object_id", json_integer(parameters->largest_object.object));
			}
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_request_parameters(message, moq->version, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_request_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_ERROR, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15)
		error = (imquic_moq_request_error_code)imquic_moq_request_error_code_to_legacy(moq->version, error);
	size_t offset = 0, len_offset = 0;
	IMQUIC_MOQ_ADD_MESSAGE_TYPE(IMQUIC_MOQ_TRACK_STATUS_ERROR);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare(moq->version >= IMQUIC_MOQ_VERSION_15 ? "request_error" : "track_status_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, const char *new_session_uri) {
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
	offset += imquic_write_varint(uri_len, &bytes[offset], blen-offset);
	if(uri_len > 0) {
		memcpy(&bytes[offset], new_session_uri, uri_len);
		offset += uri_len;
	}
	IMQUIC_MOQ_ADD_MESSAGE_LENGTH();
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("goaway");
		imquic_qlog_event_add_raw(message, "new_session_uri", (uint8_t *)new_session_uri, uri_len);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, bytes, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t track_alias,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint8_t priority,
		uint8_t *payload, size_t plen, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM, moq->version));
		return 0;
	}
	/* TODO Involve EOG */
	gboolean has_ext = (extensions != NULL && elen > 0), is_eog = FALSE;
	gboolean has_oid = (moq->version < IMQUIC_MOQ_VERSION_14 ||
		(moq->version >= IMQUIC_MOQ_VERSION_14 && object_id != 0));
	gboolean has_priority = TRUE;	/* FIXME */
	imquic_moq_datagram_message_type dtype = imquic_moq_datagram_message_type_return(moq->version,
		TRUE,			/* Payload */
		has_ext,		/* Extensions */
		is_eog,			/* End of Group */
		has_oid,		/* Object ID */
		has_priority);	/* Priority */
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_14 || has_oid)
		offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(has_priority) {
		bytes[offset] = priority;
		offset++;
	}
	if(has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions, elen);
	if(payload != NULL && plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t track_alias, uint64_t group_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version));
		return 0;
	}
	gboolean has_ext = (extensions != NULL && elen > 0);
	gboolean has_oid = (moq->version < IMQUIC_MOQ_VERSION_14 ||
		(moq->version >= IMQUIC_MOQ_VERSION_14 && object_id != 0));
	gboolean has_priority = TRUE;	/* FIXME */
	imquic_moq_datagram_message_type dtype = imquic_moq_datagram_message_type_return(moq->version,
		FALSE,			/* Status */
		has_ext,		/* Extensions */
		FALSE,			/* End of Group */
		has_oid,		/* Object ID */
		has_priority);	/* Priority */
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	if(has_oid)
		offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(has_priority) {
		bytes[offset] = priority;
		offset++;
	}
	if(has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions, elen);
	offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
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
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	if(has_sg)
		offset += imquic_write_varint(subgroup_id, &bytes[offset], blen-offset);
	if(has_sg) {
		bytes[offset] = priority;
		offset++;
	}
	return offset;
}

size_t imquic_moq_add_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t object_id, uint64_t object_status,
		uint8_t *payload, size_t plen, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	/* TODO We can optimize this by only doing it once, when we parse the header */
	/* TODO Involve EOG too */
	gboolean has_ext = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, NULL, NULL, &has_ext, NULL, NULL, NULL);
	if(has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions, elen);
	if(payload == NULL)
		plen = 0;
	offset += imquic_write_varint(plen, &bytes[offset], blen-offset);
	if(plen == 0)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
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
	size_t offset = imquic_write_varint(IMQUIC_MOQ_FETCH_HEADER, bytes, blen);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_fetch_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint8_t flags, uint64_t group_id, uint64_t subgroup_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *payload, size_t plen, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		bytes[offset] = flags;
		offset++;
	}
	uint8_t lsb = (flags & 0x03);
	if(flags & 0x08)
		offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	if(lsb == 0x03)
		offset += imquic_write_varint(subgroup_id, &bytes[offset], blen-offset);
	if(flags & 0x04)
		offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(flags & 0x10) {
		bytes[offset] = priority;
		offset++;
	}
	if(flags & 0x20)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions, elen);
	if(payload == NULL)
		plen = 0;
	offset += imquic_write_varint(plen, &bytes[offset], blen-offset);
	if(plen == 0)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	if(plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_object_extensions(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't serialize MoQ object extensions: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	if(extensions == NULL || elen == 0) {
		extensions = NULL;
		elen = 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(elen, &bytes[offset], blen-offset);
	if(extensions != NULL && elen > 0) {
		memcpy(&bytes[offset], extensions, elen);
		offset += elen;
	}
	return offset;
}

/* Adding parameters to a buffer */
size_t imquic_moq_parameter_add_int(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint64_t number) {
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric parameter %d: invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(param % 2 != 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric parameter %d: type is odd\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	offset += imquic_write_varint(number, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_parameter_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0 || (buflen > 0 && buf == 0) || buflen > UINT16_MAX) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %d: invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(param % 2 != 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %d: type is even\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	offset += imquic_write_varint(buflen, &bytes[offset], blen);
	if(buflen > 0) {
		memcpy(&bytes[offset], buf, buflen);
		offset += buflen;
	}
	return offset;
}

size_t imquic_moq_parse_setup_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_setup_parameters *params, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ setup parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_setup_parameter_type_str(type), type);
	uint64_t len = 0;
	if(type % 2 == 1) {
		len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ setup parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
	}
	/* Update the parsed parameter */
	if(type == IMQUIC_MOQ_SETUP_PARAM_PATH) {
		params->path_set = TRUE;
		if(len > 0)
			g_snprintf(params->path, sizeof(params->path), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->path);
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_MAX_REQUEST_ID) {
		params->max_request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_request_id_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		len = length;
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE) {
		params->max_auth_token_cache_size = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_auth_token_cache_size_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		len = length;
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_AUTHORIZATION_TOKEN && moq->version >= IMQUIC_MOQ_VERSION_12) {
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
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_AUTHORITY && moq->version >= IMQUIC_MOQ_VERSION_14) {
		params->authority_set = TRUE;
		if(len > 0)
			g_snprintf(params->authority, sizeof(params->authority), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->authority);
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_MOQT_IMPLEMENTATION && moq->version >= IMQUIC_MOQ_VERSION_14) {
		params->moqt_implementation_set = TRUE;
		if(len > 0)
			g_snprintf(params->moqt_implementation, sizeof(params->moqt_implementation), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->moqt_implementation);
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

size_t imquic_moq_parse_request_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_request_parameters *params, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ subscribe parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_request_parameter_type_str(type, moq->version), type);
	uint64_t len = 0;
	if(type % 2 == 1) {
		len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ request parameter");
	}
	/* Update the parsed parameter */
	if((moq->version >= IMQUIC_MOQ_VERSION_12 && type == IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN) ||
			(moq->version == IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_REQUEST_PARAM_AUTHORIZATION_TOKEN_v11)) {
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
		params->delivery_timeout = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->delivery_timeout_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->delivery_timeout);
		len = length;
	} else if(type == IMQUIC_MOQ_REQUEST_PARAM_MAX_CACHE_DURATION) {
		params->max_cache_duration = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->max_cache_duration_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_cache_duration);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_PUBLISHER_PRIORITY) {
		uint64_t publisher_priority = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || publisher_priority > 255, NULL, 0, 0, "Broken MoQ request parameter");
		params->publisher_priority = publisher_priority;
		params->publisher_priority_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->publisher_priority);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIBER_PRIORITY) {
		uint64_t subscriber_priority = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || subscriber_priority > 255, NULL, 0, 0, "Broken MoQ request parameter");
		params->subscriber_priority = subscriber_priority;
		params->subscriber_priority_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->subscriber_priority);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_GROUP_ORDER) {
		uint64_t group_order = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || group_order > IMQUIC_MOQ_ORDERING_DESCENDING, NULL, 0, 0, "Broken MoQ request parameter");
		params->group_order_ascending = (group_order == IMQUIC_MOQ_ORDERING_ASCENDING);
		params->group_order_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), group_order);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_SUBSCRIPTION_FILTER) {
		uint8_t *tmp = &bytes[offset];
		size_t toffset = 0, tlen = len;
		params->subscription_filter.type = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		toffset += length;
		if(params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
				params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			params->subscription_filter.start_location.group = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			toffset += length;
			params->subscription_filter.start_location.object = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
			toffset += length;
		}
		if(params->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			params->subscription_filter.end_group = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		}
		params->subscription_filter_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %d\n",
			imquic_get_connection_name(moq->conn), params->subscription_filter.type);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_EXPIRES) {
		params->expires = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->expires_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->expires);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_LARGEST_OBJECT) {
		uint8_t *tmp = &bytes[offset];
		size_t toffset = 0, tlen = len;
		params->largest_object.group = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		toffset += length;
		params->largest_object.object = imquic_read_varint(&tmp[toffset], tlen-toffset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->largest_object_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64" / %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->largest_object.group, params->largest_object.object);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_FORWARD) {
		uint64_t forward = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || forward > 1, NULL, 0, 0, "Broken MoQ request parameter");
		params->forward = (forward > 0);
		params->forward_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->forward);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_DYNAMIC_GROUPS) {
		uint64_t dynamic_groups = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || dynamic_groups > 2, NULL, 0, 0, "Broken MoQ request parameter");
		params->dynamic_groups = (dynamic_groups > 0);
		params->dynamic_groups_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), params->dynamic_groups);
		len = length;
	} else if(moq->version >= IMQUIC_MOQ_VERSION_15 && type == IMQUIC_MOQ_REQUEST_PARAM_NEW_GROUP_REQUEST) {
		params->new_group_request = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ request parameter");
		params->new_group_request_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->new_group_request);
		len = length;
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), type);
		if(type % 2 == 0)
			len = length;
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
	if(moq == NULL || max_request_id == 0 || moq->local_max_request_id >= max_request_id) {
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
			buffer, moq->control_stream_offset, ms_len, FALSE);
		moq->control_stream_offset += ms_len;
		imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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

/* Object extensions management */
GList *imquic_moq_parse_object_extensions(uint8_t *extensions, size_t elen) {
	if(extensions == NULL || elen == 0)
		return NULL;
	GList *exts = NULL;
	size_t offset = 0;
	uint8_t length = 0;
	/* Parse extensions */
	while(elen-offset > 0) {
		uint64_t ext_type = imquic_read_varint(&extensions[offset], elen-offset, &length);
		if(length == 0 || length >= elen-offset) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken object extensions\n");
			g_list_free_full(exts, (GDestroyNotify)imquic_moq_object_extension_free);
			return 0;
		}
		offset += length;
		if(ext_type % 2 == 0) {
			/* Even types are followed by a numeric value */
			uint64_t ext_val = imquic_read_varint(&extensions[offset], elen-offset, &length);
			if(length == 0 || length > elen-offset) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken object extensions\n");
				g_list_free_full(exts, (GDestroyNotify)imquic_moq_object_extension_free);
				return 0;
			}
			offset += length;
			imquic_moq_object_extension *extension = g_malloc0(sizeof(imquic_moq_object_extension));
			extension->id = ext_type;
			extension->value.number = ext_val;
			exts = g_list_prepend(exts, extension);
		} else {
			/* Odd typed are followed by a length and a value */
			uint64_t ext_len = imquic_read_varint(&extensions[offset], elen-offset, &length);
			if(length == 0 || length >= elen-offset || ext_len >= elen-offset) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Broken object extensions\n");
				g_list_free_full(exts, (GDestroyNotify)imquic_moq_object_extension_free);
				return 0;
			}
			/* TODO A length larger than UINT16_MAX should be a protocol violation error */
			//~ IMQUIC_MOQ_CHECK_ERR(ext_len > UINT16_MAX, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Key-Value-Pair length");
			offset += length;
			imquic_moq_object_extension *extension = g_malloc0(sizeof(imquic_moq_object_extension));
			extension->id = ext_type;
			if(ext_len > 0) {
				extension->value.data.length = ext_len;
				extension->value.data.buffer = g_malloc(ext_len);
				memcpy(extension->value.data.buffer, &extensions[offset], ext_len);
			}
			exts = g_list_prepend(exts, extension);
			offset += ext_len;
		}
	}
	return g_list_reverse(exts);
}

size_t imquic_moq_build_object_extensions(GList *extensions, uint8_t *bytes, size_t blen) {
	if(extensions == NULL || bytes == NULL || blen == 0)
		return 0;
	size_t offset = 0;
	GList *temp = extensions;
	while(temp) {
		imquic_moq_object_extension *ext = (imquic_moq_object_extension *)temp->data;
		offset += imquic_write_varint(ext->id, &bytes[offset], blen-offset);
		if(ext->id % 2 == 0) {
			offset += imquic_write_varint(ext->value.number, &bytes[offset], blen-offset);
		} else {
			offset += imquic_write_varint(ext->value.data.length, &bytes[offset], blen-offset);
			if(ext->value.data.length > 0) {
				memcpy(&bytes[offset], ext->value.data.buffer, ext->value.data.length);
				offset += ext->value.data.length;
			}
		}
		temp = temp->next;
	}
	return offset;
}

/* Auth token management */
int imquic_moq_parse_auth_token(uint8_t *bytes, size_t blen, imquic_moq_auth_token *token) {
	if(bytes == NULL || blen == 0 || token == NULL)
		return -1;
	memset(token, 0, sizeof(*token));
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t alias_type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
	offset += length;
	if(alias_type != IMQUIC_MOQ_AUTH_TOKEN_DELETE && alias_type != IMQUIC_MOQ_AUTH_TOKEN_REGISTER &&
			alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_ALIAS && alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid alias type %"SCNu64"\n", alias_type);
		return -1;
	}
	token->alias_type = alias_type;
	if(alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		uint64_t token_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
		offset += length;
		token->token_alias_set = TRUE;
		token->token_alias = token_alias;
	}
	if(alias_type == IMQUIC_MOQ_AUTH_TOKEN_REGISTER || alias_type == IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		uint64_t token_type = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, -1, "Broken auth token");
		offset += length;
		token->token_type_set = TRUE;
		token->token_type = token_type;
		token->token_value.length = blen-offset;
		token->token_value.buffer = (token->token_value.length > 0 ? &bytes[offset] : NULL);
	}
	return 0;
}

size_t imquic_moq_build_auth_token(imquic_moq_auth_token *token, uint8_t *bytes, size_t blen) {
	if(token == NULL || bytes == NULL || blen == 0)
		return 0;
	if(token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_DELETE && token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_REGISTER &&
			token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_ALIAS && token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid alias type %d\n", token->alias_type);
		return 0;
	}
	size_t offset = imquic_write_varint(token->alias_type, bytes, blen);
	if(token->alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		if(!token->token_alias_set) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Token alias is required when using %s\n", imquic_moq_auth_token_alias_type_str(token->alias_type));
			return 0;
		}
		offset += imquic_write_varint(token->token_alias, &bytes[offset], blen-offset);
	}
	if(token->alias_type == IMQUIC_MOQ_AUTH_TOKEN_REGISTER || token->alias_type == IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
		if(!token->token_type_set) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Token type is required when using %s\n", imquic_moq_auth_token_alias_type_str(token->alias_type));
			return 0;
		}
		offset += imquic_write_varint(token->token_type, &bytes[offset], blen-offset);
		if(token->token_value.buffer && token->token_value.length > 0) {
			memcpy(&bytes[offset], token->token_value.buffer, token->token_value.length);
			offset += token->token_value.length;
		}
	}
	return offset;
}

/* Namespaces and subscriptions */
int imquic_moq_publish_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns,
		imquic_moq_request_parameters *parameters) {
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
	/* TODO Check if this namespace exists and was publish_namespaced here */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_PUBLISH_NAMESPACE));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_publish_namespace(moq, buffer, blen, request_id, tns, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	/* TODO Check if the request ID exists */
	/* TODO Check if this namespace exists and was publish_namespaced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		ann_len = imquic_moq_add_publish_namespace_ok(moq, buffer, blen, request_id);
	} else {
		ann_len = imquic_moq_add_request_ok(moq, buffer, blen, request_id, parameters);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_publish_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
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
	/* TODO Check if the request ID exists */
	/* TODO Check if this namespace exists and was publish_namespaced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		ann_len = imquic_moq_add_publish_namespace_error(moq, buffer, blen, request_id, error_code, reason);
	} else {
		ann_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish_namespace_done(imquic_connection *conn, imquic_moq_namespace *tns) {
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
	/* TODO Check if this namespace exists and was publish_namespaced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t ann_len = imquic_moq_add_publish_namespace_done(moq, buffer, blen, tns);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn,
		uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Publishing not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
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
	/* Send the request */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_PUBLISH));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_publish(moq, buffer, blen,
		request_id, tns, tn, track_alias, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->forward_set) {
		/* Force some defaults */
		parameters->forward_set = TRUE;
		parameters->forward = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscription_filter_set) {
		/* Force some defaults */
		parameters->subscription_filter_set = TRUE;
		parameters->subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Publishing not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	if(parameters && parameters->subscription_filter_set && parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE &&
			parameters->subscription_filter.end_group > 0 && parameters->subscription_filter.start_location.group > parameters->subscription_filter.end_group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn),
			parameters->subscription_filter.end_group,
			parameters->subscription_filter.start_location.group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_publish_ok(moq, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
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
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Publishing not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		sb_len = imquic_moq_add_publish_error(moq, buffer, blen, request_id, error_code, reason);
	} else {
		sb_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
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
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->forward_set) {
		/* Force some defaults */
		parameters->forward_set = TRUE;
		parameters->forward = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscription_filter_set) {
		/* Force some defaults */
		parameters->subscription_filter_set = TRUE;
		parameters->subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
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
	/* Send the request */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_SUBSCRIBE));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_subscribe(moq, buffer, blen,
		request_id, track_alias, tns, tn, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->expires_set) {
		/* Force some defaults */
		parameters->expires_set = TRUE;
		parameters->expires = 0;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	if(moq->version >= IMQUIC_MOQ_VERSION_12) {
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &request_id);
		if(moq_sub != NULL) {
		/* Track this subscription */
			moq_sub->track_alias = track_alias;
			g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
		}
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_subscribe_ok(moq, buffer, blen,
		request_id, track_alias, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias) {
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
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		sb_len = imquic_moq_add_subscribe_error(moq, buffer, blen, request_id, error_code, reason, track_alias);
	} else {
		sb_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_update_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t sub_request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->forward_set) {
		/* Force some defaults */
		parameters->forward_set = TRUE;
		parameters->forward = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscription_filter_set) {
		/* Force some defaults */
		parameters->subscription_filter_set = TRUE;
		parameters->subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
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
	/* TODO Check if we were subscribed */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_SUBSCRIBE_UPDATE));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t su_len = imquic_moq_add_subscribe_update(moq, buffer, blen,
		request_id, sub_request_id, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, su_len, FALSE);
	moq->control_stream_offset += su_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe_update(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s acknowledgements on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_UPDATE, moq->version),
			imquic_moq_version_str(moq->version));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if the request ID exists */
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_ok(moq, buffer, blen, request_id, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe_update(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_15) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s errors on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_UPDATE, moq->version),
			imquic_moq_version_str(moq->version));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_unsubscribe(moq, buffer, blen, request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	/* TODO Compute streams count */
	size_t sd_len = imquic_moq_add_publish_done(moq, buffer, blen,
		request_id, status_code, streams_count, reason);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sd_len, FALSE);
	moq->control_stream_offset += sd_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters) {
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
	/* Send the request */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_SUBSCRIBE_NAMESPACE));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_subscribe_namespace(moq, buffer, blen, request_id, tns, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	/* TODO Check if the request ID exists */
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		sb_len = imquic_moq_add_subscribe_namespace_ok(moq, buffer, blen, request_id);
	} else {
		sb_len = imquic_moq_add_request_ok(moq, buffer, blen, request_id, parameters);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
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
	/* TODO Check if the request ID exists */
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		sb_len = imquic_moq_add_subscribe_namespace_error(moq, buffer, blen, request_id, error_code, reason);
	} else {
		sb_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unsubscribe_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
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
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = imquic_moq_add_unsubscribe_namespace(moq, buffer, blen, request_id, tns);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_standalone_fetch(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_location_range *range, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tn == NULL || range == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
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
	/* TODO Check if this namespace exists and was publish_namespaced here */
	/* TODO Track subscription and track alias */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_FETCH));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = 0;
	f_len = imquic_moq_add_fetch(moq, buffer, blen,
		IMQUIC_MOQ_FETCH_STANDALONE,
		request_id,
		0, 0,	/* Ignored, as they're only used for Joining Fetch */
		tns, tn,
		range, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_joining_fetch(imquic_connection *conn, uint64_t request_id, uint64_t joining_request_id,
		gboolean absolute, uint64_t joining_start, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
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
	/* TODO Check if this namespace exists and was publish_namespaced here */
	/* TODO Track subscription and track alias */
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_FETCH));
		imquic_mutex_unlock(&moq->mutex);
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = 0;
	f_len = imquic_moq_add_fetch(moq, buffer, blen,
		(absolute ? IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE : IMQUIC_MOQ_FETCH_JOINING_RELATIVE),
		request_id, joining_request_id, joining_start,
		NULL, NULL,	/* Ignored, as namespaces/track are only used for Standalone Fetch */
		NULL,	/* Ignored, as the fetch range is only used for Standalone Fetch */
		parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_fetch(imquic_connection *conn, uint64_t request_id, imquic_moq_location *largest, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || largest == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	/* TODO Make other properties configurable */
	size_t f_len = imquic_moq_add_fetch_ok(moq, buffer, blen,
		request_id,
		0,	/* TODO End of track */
		largest,	/* Largest location */
		parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_fetch(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
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
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t f_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		f_len = imquic_moq_add_fetch_error(moq, buffer, blen, request_id, error_code, reason);
	} else {
		f_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
		buffer, moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
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
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && parameters == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->forward_set) {
		/* Force some defaults */
		parameters->forward_set = TRUE;
		parameters->forward = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscriber_priority_set) {
		/* Force some defaults */
		parameters->subscriber_priority_set = TRUE;
		parameters->subscriber_priority = 128;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->subscription_filter_set) {
		/* Force some defaults */
		parameters->subscription_filter_set = TRUE;
		parameters->subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_13) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS, moq->version),
			imquic_moq_version_str(moq->version));
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
	if(moq->version >= IMQUIC_MOQ_VERSION_15) {
		/* Map this request ID to this message type, so that we can trigger
		 * the right application callbac if/when we get a response later on */
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->requests, imquic_dup_uint64(request_id), GUINT_TO_POINTER(IMQUIC_MOQ_TRACK_STATUS));
		imquic_mutex_unlock(&moq->mutex);
	}
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t sb_len = 0;
	sb_len = imquic_moq_add_track_status(moq, buffer, blen,
		request_id, tns, tn, parameters);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_track_status(imquic_connection *conn, uint64_t request_id,
		uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && (parameters == NULL || !parameters->expires_set ||
			!parameters->group_order_set || !parameters->largest_object_set)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments (missing mandatory parameters)\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->expires_set) {
		/* Force some defaults */
		parameters->expires_set = TRUE;
		parameters->expires = 0;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->group_order_set) {
		/* Force some defaults */
		parameters->group_order_set = TRUE;
		parameters->group_order_ascending = TRUE;
	}
	if(moq->version <= IMQUIC_MOQ_VERSION_14 && !parameters->largest_object_set) {
		/* Force some defaults */
		parameters->largest_object_set = TRUE;
		parameters->largest_object.group = 0;
		parameters->largest_object.object = 0;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(moq->version < IMQUIC_MOQ_VERSION_13) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_OK, moq->version),
			imquic_moq_version_str(moq->version));
		return -1;
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t tso_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		tso_len = imquic_moq_add_track_status_ok(moq, buffer, blen,
			request_id, track_alias, parameters);
	} else {
		tso_len = imquic_moq_add_request_ok(moq, buffer, blen, request_id, parameters);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, tso_len, FALSE);
	moq->control_stream_offset += tso_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_track_status(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
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
	if(moq->version < IMQUIC_MOQ_VERSION_13) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_ERROR, moq->version),
			imquic_moq_version_str(moq->version));
		return -1;
	}
	uint8_t buffer[200];
	size_t blen = sizeof(buffer);
	size_t tsr_len = 0;
	if(moq->version <= IMQUIC_MOQ_VERSION_14) {
		tsr_len = imquic_moq_add_track_status_error(moq, buffer, blen, request_id, error_code, reason);
	} else {
		tsr_len = imquic_moq_add_request_error(moq, buffer, blen, request_id, error_code, reason);
	}
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, tsr_len, FALSE);
	moq->control_stream_offset += tsr_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_requests_blocked(imquic_connection *conn) {
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
	size_t r_len = imquic_moq_add_requests_blocked(moq, buffer, blen, moq->max_request_id);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, r_len, FALSE);
	moq->control_stream_offset += r_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_goaway(imquic_connection *conn, const char *uri) {
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
	size_t g_len = imquic_moq_add_goaway(moq, buffer, blen, uri);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		buffer, moq->control_stream_offset, g_len, FALSE);
	moq->control_stream_offset += g_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_send_object(imquic_connection *conn, imquic_moq_object *object) {
	if(object == NULL || object->object_status > IMQUIC_MOQ_END_OF_TRACK ||
			(object->object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && object->extensions_len > 0)) {
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
	/* Check how we should send this */
	size_t bufsize = object->extensions_len + object->payload_len + 100;
	uint8_t *buffer = g_malloc(bufsize);	/* FIXME */
	if(object->delivery == IMQUIC_MOQ_USE_DATAGRAM) {
		/* Use a datagram */
		if(has_payload) {
			size_t dg_len = imquic_moq_add_object_datagram(moq, buffer, bufsize,
				object->request_id, object->track_alias, object->group_id, object->object_id, object->object_status,
				object->priority, object->payload, object->payload_len,
				object->extensions, object->extensions_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_object_datagram_created(conn->qlog, object);
#endif
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
		} else {
			size_t dg_len = imquic_moq_add_object_datagram_status(moq, buffer, bufsize,
				object->track_alias, object->group_id, object->object_id, object->priority,
				object->object_status, object->extensions, object->extensions_len);
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
			/* TODO Change the type depending on whether extensions/subgroup will be set:
			 * since we don't have an API for that, for now we always set the type
			 * that will allow us to dynamically use them all. This also means we
			 * currently don't have a way to specify an End-of-Group flag */
			moq_stream->type = imquic_moq_data_message_type_from_subgroup_header(moq->version,
				TRUE,	/* We'll explicitly specify the Subgroup ID */
				FALSE,	/* Whether the default Subgroup ID is 0 (ignored, since we set it) */
				TRUE,	/* We'll add the extensions block, whether there are extensions or not */
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
				buffer, moq_stream->stream_offset, shg_len, FALSE);
			moq_stream->stream_offset += shg_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shgo_len = 0;
		if(valid_pkt) {
			uint64_t object_id = object->object_id;
			if(moq->version >= IMQUIC_MOQ_VERSION_14) {
				/* Object IDs are a delta, starting from v14 */
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
			}
			shgo_len = imquic_moq_add_subgroup_header_object(moq, moq_stream, buffer, bufsize,
				object_id, object->object_status, object->payload, object->payload_len,
				object->extensions, object->extensions_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_subgroup_object_created(conn->qlog, moq_stream->stream_id, object);
#endif
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shgo_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_GROUP));
		moq_stream->stream_offset += shgo_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
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
				buffer, moq_stream->stream_offset, sht_len, FALSE);
			moq_stream->stream_offset += sht_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shto_len = 0;
		if(valid_pkt) {
			/* TODO Check what flags we should add */
			uint8_t flags = 0x03 | 0x04 | 0x08 | 0x10 | 0x20;
			shto_len = imquic_moq_add_fetch_header_object(moq, buffer, bufsize, flags,
				object->group_id, object->subgroup_id, object->object_id, object->priority,
				object->object_status, object->payload, object->payload_len,
				object->extensions, object->extensions_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_fetch_object_created(conn->qlog, moq_stream->stream_id, object);
#endif
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shto_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP));
		moq_stream->stream_offset += shto_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP) {
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

#ifdef HAVE_QLOG
/* QLOG support */
json_t *imquic_qlog_moq_message_prepare(const char *type) {
	if(type == NULL)
		return NULL;
	json_t *message = json_object();
	json_object_set_new(message, "type", json_string(type));
	return message;
}

void imquic_qlog_moq_message_add_namespace(json_t *message, imquic_moq_namespace *track_namespace) {
	if(message == NULL)
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
	json_object_set_new(message, "track_namespace", tns_list);
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

void imquic_qlog_moq_message_add_setup_parameters(json_t *message, imquic_moq_setup_parameters *parameters, const char *name) {
	if(message == NULL || parameters == NULL || name == NULL)
		return;
	json_t *params = json_array();
	if(parameters->path_set) {
		json_t *path = json_object();
		json_object_set_new(path, "name", json_string("path"));
		json_object_set_new(path, "value", json_string(parameters->path));
		json_array_append_new(params, path);
	}
	if(parameters->max_request_id_set) {
		json_t *max_request_id = json_object();
		json_object_set_new(max_request_id, "name", json_string("max_request_id"));
		json_object_set_new(max_request_id, "value", json_integer(parameters->max_request_id));
		json_array_append_new(params, max_request_id);
	}
	if(parameters->max_auth_token_cache_size_set) {
		json_t *max_auth_token_cache_size = json_object();
		json_object_set_new(max_auth_token_cache_size, "name", json_string("max_auth_token_cache_size"));
		json_object_set_new(max_auth_token_cache_size, "value", json_integer(parameters->max_auth_token_cache_size));
		json_array_append_new(params, max_auth_token_cache_size);
	}
	if(parameters->auth_token_set && parameters->auth_token_len > 0) {
		json_t *auth_token = json_object();
		json_object_set_new(auth_token, "name", json_string("authorization_token"));
		char ai_str[513];
		json_object_set_new(auth_token, "value", json_string(imquic_hex_str(parameters->auth_token, parameters->auth_token_len, ai_str, sizeof(ai_str))));
		json_array_append_new(params, auth_token);
	}
	if(parameters->authority_set) {
		json_t *authority = json_object();
		json_object_set_new(authority, "name", json_string("authority"));
		json_object_set_new(authority, "value", json_string(parameters->authority));
		json_array_append_new(params, authority);
	}
	if(parameters->moqt_implementation_set) {
		json_t *moqt_implementation = json_object();
		json_object_set_new(moqt_implementation, "name", json_string("moqt_implementation"));
		json_object_set_new(moqt_implementation, "value", json_string(parameters->moqt_implementation));
		json_array_append_new(params, moqt_implementation);
	}
	if(parameters->unknown) {
		json_t *unknown = json_object();
		json_object_set_new(unknown, "name", json_string("unknown"));
		json_array_append_new(params, unknown);
	}
	json_object_set_new(message, name, params);
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
	if(parameters->max_cache_duration_set) {
		json_t *max_cache_duration = json_object();
		json_object_set_new(max_cache_duration, "name", json_string("max_cache_duration"));
		json_object_set_new(max_cache_duration, "value", json_integer(parameters->max_cache_duration));
		json_array_append_new(params, max_cache_duration);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->publisher_priority_set) {
		json_t *publisher_priority = json_object();
		json_object_set_new(publisher_priority, "name", json_string("publisher_priority"));
		json_object_set_new(publisher_priority, "value", json_integer(parameters->publisher_priority));
		json_array_append_new(params, publisher_priority);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->subscriber_priority_set) {
		json_t *subscriber_priority = json_object();
		json_object_set_new(subscriber_priority, "name", json_string("subscriber_priority"));
		json_object_set_new(subscriber_priority, "value", json_integer(parameters->subscriber_priority));
		json_array_append_new(params, subscriber_priority);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->group_order_set) {
		json_t *group_order = json_object();
		json_object_set_new(group_order, "name", json_string("group_order"));
		json_object_set_new(group_order, "value", json_integer(parameters->group_order_ascending ? IMQUIC_MOQ_ORDERING_ASCENDING : IMQUIC_MOQ_ORDERING_DESCENDING));
		json_array_append_new(params, group_order);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->subscription_filter_set) {
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
		if(parameters->subscription_filter.type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE)
			json_object_set_new(sf, "end_group", json_integer(parameters->subscription_filter.end_group));
		json_object_set_new(subscription_filter, "value", sf);
		json_array_append_new(params, subscription_filter);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->expires_set) {
		json_t *expires = json_object();
		json_object_set_new(expires, "name", json_string("expires"));
		json_object_set_new(expires, "value", json_integer(parameters->expires));
		json_array_append_new(params, expires);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->largest_object_set) {
		json_t *largest_object = json_object();
		json_object_set_new(largest_object, "name", json_string("largest_object"));
		/* FIXME */
		json_t *lo = json_object();
		json_object_set_new(lo, "group", json_integer(parameters->largest_object.group));
		json_object_set_new(lo, "object", json_integer(parameters->largest_object.object));
		json_object_set_new(largest_object, "value", lo);
		json_array_append_new(params, largest_object);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->forward_set) {
		json_t *forward = json_object();
		json_object_set_new(forward, "name", json_string("forward"));
		json_object_set_new(forward, "value", json_integer(parameters->forward));
		json_array_append_new(params, forward);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->dynamic_groups_set) {
		json_t *dynamic_groups = json_object();
		json_object_set_new(dynamic_groups, "name", json_string("dynamic_groups"));
		json_object_set_new(dynamic_groups, "value", json_integer(parameters->dynamic_groups));
		json_array_append_new(params, dynamic_groups);
	}
	if(version >= IMQUIC_MOQ_VERSION_15 && parameters->new_group_request_set) {
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
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
	json_object_set_new(data, "extension_headers_length", json_integer(object->extensions_len));
	json_object_set_new(data, "object_payload_length", json_integer(object->payload_len));
	json_object_set_new(data, "object_status", json_integer(object->object_status));
	if(object->payload_len > 0) {
		imquic_qlog_event_add_raw(data, "object_payload",
			(qlog->moq_objects ? object->payload : NULL), object->payload_len);
	}
	imquic_qlog_append_event(qlog, event);
}

#endif
