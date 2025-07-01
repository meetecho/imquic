/*! \file   moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Media Over QUIC (MoQ) stack
 * \details Implementation of the Media Over QUIC (MoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) versions from -06 to to -12 of the protocol.
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
#include "imquic/debug.h"

/* Logging */
#define IMQUIC_MOQ_LOG_VERB	IMQUIC_LOG_HUGE
#define IMQUIC_MOQ_LOG_HUGE	IMQUIC_LOG_VERB
//~ #define IMQUIC_MOQ_LOG_VERB	IMQUIC_LOG_INFO
//~ #define IMQUIC_MOQ_LOG_HUGE	IMQUIC_LOG_INFO

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

/* Callbacks */
void imquic_moq_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_refcount_increase(&conn->ref);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s][MoQ] New connection %p\n", imquic_get_connection_name(conn), conn);
	imquic_moq_context *moq = g_malloc0(sizeof(imquic_moq_context));
	moq->conn = conn;
	moq->is_server = conn->is_server;
	moq->version = IMQUIC_MOQ_VERSION_ANY;
	moq->streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	moq->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	moq->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_subscription_destroy);
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
		if(!moq->role_set) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] No role set by the MoQ client, unable to send CLIENT_SETUP...\n",
				imquic_get_connection_name(conn));
			return;
		}
		moq->version_set = TRUE;
		/* Generate a CLIENT_SETUP */
		imquic_moq_setup_parameters parameters = { 0 };
		if(moq->version < IMQUIC_MOQ_VERSION_08) {
			parameters.role_set = TRUE;
			parameters.role = moq->type;
		}
		if(moq->local_max_request_id > 0) {
			parameters.max_request_id_set = TRUE;
			parameters.max_request_id = moq->local_max_request_id;
		}
		if(((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
				moq->version == IMQUIC_MOQ_VERSION_ANY) &&
				moq->local_max_auth_token_cache_size > 0) {
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
		GList *versions = NULL;
		if(moq->version == IMQUIC_MOQ_VERSION_ANY) {
			/* Offer all newer supported versions */
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_12));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_11));
		} else if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
			/* Offer all supported versions from -06 to -10 */
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_10));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_09));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_08));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_07));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_06));
		} else {
			/* Offer a specific version */
			versions = g_list_append(versions, GUINT_TO_POINTER(moq->version));
		}
		uint8_t buffer[200];
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t cs_len = imquic_moq_add_client_setup(moq, &buffer[poffset], blen-poffset, versions, &parameters);
		if((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
				moq->version == IMQUIC_MOQ_VERSION_ANY) {
			cs_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_CLIENT_SETUP, buffer, blen, poffset, cs_len, &start);
		} else {
			cs_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_CLIENT_SETUP_LEGACY, buffer, blen, poffset, cs_len, &start);
		}
		g_list_free(versions);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			&buffer[start], moq->control_stream_offset, cs_len, FALSE);
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
	if(moq == NULL)
		return;
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
	g_list_free(moq->supported_versions);
	if(moq->streams)
		g_hash_table_unref(moq->streams);
	if(moq->subscriptions)
		g_hash_table_unref(moq->subscriptions);
	if(moq->subscriptions_by_id)
		g_hash_table_unref(moq->subscriptions_by_id);
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
		case IMQUIC_MOQ_UNKNOWN_ERROR:
			return "Unknown Error";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_announce_error_code_str(imquic_moq_announce_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_ANNCERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_ANNCERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_ANNCERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_ANNCERR_NOT_SUPPORTED:
			return "Not Supported";
		case IMQUIC_MOQ_ANNCERR_UNINTERESTED:
			return "Uninterested";
		case IMQUIC_MOQ_ANNCERR_MALFORMED_AUTH_TOKEN:
			return "Malformed Auth Token";
		case IMQUIC_MOQ_ANNCERR_UNKNOWN_AUTH_TOKEN_ALIAS:
			return "Unknown Auth Token Alias";
		case IMQUIC_MOQ_ANNCERR_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_pub_error_code_str(imquic_moq_pub_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_PUBERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_PUBERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_PUBERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_PUBERR_NOT_SUPPORTED:
			return "Not Supported";
		case IMQUIC_MOQ_PUBERR_UNINTERESTED:
			return "Uninterested";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_sub_error_code_str(imquic_moq_sub_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_SUBERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_SUBERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_SUBERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_SUBERR_NOT_SUPPORTED:
			return "Not Supported";
		case IMQUIC_MOQ_SUBERR_TRACK_DOES_NOT_EXIST:
			return "Track Does Not Exist";
		case IMQUIC_MOQ_SUBERR_INVALID_RANGE:
			return "Invalid Range";
		case IMQUIC_MOQ_SUBERR_RETRY_TRACK_ALIAS:
			return "Retry Track Alias";
		case IMQUIC_MOQ_SUBERR_MALFORMED_AUTH_TOKEN:
			return "Malformed Auth Token";
		case IMQUIC_MOQ_SUBERR_UNKNOWN_AUTH_TOKEN_ALIAS:
			return "Unknown Auth Token Alias";
		case IMQUIC_MOQ_SUBERR_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_subannc_error_code_str(imquic_moq_subannc_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_SUBANNCERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_SUBANNCERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_SUBANNCERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_SUBANNCERR_NOT_SUPPORTED:
			return "Not Supported";
		case IMQUIC_MOQ_SUBANNCERR_NAMESPACE_PREFIX_UNKNOWN:
			return "Namespace Prefix Unknown";
		case IMQUIC_MOQ_SUBANNCERR_MALFORMED_AUTH_TOKEN:
			return "Malformed Auth Token";
		case IMQUIC_MOQ_SUBANNCERR_UNKNOWN_AUTH_TOKEN_ALIAS:
			return "Unknown Auth Token Alias";
		case IMQUIC_MOQ_SUBANNCERR_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_fetch_error_code_str(imquic_moq_fetch_error_code code) {
	switch(code) {
		case IMQUIC_MOQ_FETCHERR_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_FETCHERR_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_FETCHERR_TIMEOUT:
			return "Timeout";
		case IMQUIC_MOQ_FETCHERR_NOT_SUPPORTED:
			return "Not Supported";
		case IMQUIC_MOQ_FETCHERR_TRACK_DOES_NOT_EXIST:
			return "Track Does Not Exist";
		case IMQUIC_MOQ_FETCHERR_INVALID_RANGE:
			return "Invalid Range";
		case IMQUIC_MOQ_FETCHERR_NO_OBJECTS:
			return "No Objects";
		case IMQUIC_MOQ_FETCHERR_INVALID_JOINING_REQUEST_ID:
			return "Invalid Joining Request ID";
		case IMQUIC_MOQ_FETCHERR_UNKNOWN_STATUS_IN_RANGE:
			return "Unknown Status in Range";
		case IMQUIC_MOQ_FETCHERR_MALFORMED_TRACK:
			return "Malformed Track";
		case IMQUIC_MOQ_FETCHERR_UNKNOWN_AUTH_TOKEN_ALIAS:
			return "Unknown Auth Token Alias";
		case IMQUIC_MOQ_FETCHERR_EXPIRED_AUTH_TOKEN:
			return "Expired Auth Token";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_sub_done_code_str(imquic_moq_sub_done_code code) {
	switch(code) {
		case IMQUIC_MOQ_SUBDONE_INTERNAL_ERROR:
			return "Internal Error";
		case IMQUIC_MOQ_SUBDONE_UNAUTHORIZED:
			return "Unauthorized";
		case IMQUIC_MOQ_SUBDONE_TRACK_ENDED:
			return "Track Ended";
		case IMQUIC_MOQ_SUBDONE_SUBSCRIPTION_ENDED:
			return "Subscription Ended";
		case IMQUIC_MOQ_SUBDONE_GOING_AWAY:
			return "Going Away";
		case IMQUIC_MOQ_SUBDONE_EXPIRED:
			return "Expired";
		case IMQUIC_MOQ_SUBDONE_TOO_FAR_BEHIND:
			return "Too Far Behind";
		case IMQUIC_MOQ_SUBDONE_MALFORMED_TRACK:
			return "Malformed Track";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_track_status_code_str(imquic_moq_track_status_code code) {
	switch(code) {
		case IMQUIC_MOQ_STATUS_PROGRESS:
			return "Track is in progress";
		case IMQUIC_MOQ_STATUS_DOES_NOT_EXIST:
			return "Track does not exist";
		case IMQUIC_MOQ_STATUS_NOT_YET_BEGUN:
			return "Track has not yet begun";
		case IMQUIC_MOQ_STATUS_FINISHED:
			return "Track has finished";
		case IMQUIC_MOQ_STATUS_CANNOT_OBTAIN:
			return "Cannot obtain track status from upstream";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_message_type_str(imquic_moq_message_type type) {
	switch(type) {
		case IMQUIC_MOQ_SUBSCRIBE:
			return "SUBSCRIBE";
		case IMQUIC_MOQ_SUBSCRIBE_OK:
			return "SUBSCRIBE_OK";
		case IMQUIC_MOQ_SUBSCRIBE_ERROR:
			return "SUBSCRIBE_ERROR";
		case IMQUIC_MOQ_ANNOUNCE:
			return "ANNOUNCE";
		case IMQUIC_MOQ_ANNOUNCE_OK:
			return "ANNOUNCE_OK";
		case IMQUIC_MOQ_ANNOUNCE_ERROR:
			return "ANNOUNCE_ERROR";
		case IMQUIC_MOQ_UNANNOUNCE:
			return "UNANNOUNCE";
		case IMQUIC_MOQ_UNSUBSCRIBE:
			return "UNSUBSCRIBE";
		case IMQUIC_MOQ_SUBSCRIBE_DONE:
			return "SUBSCRIBE_DONE";
		case IMQUIC_MOQ_ANNOUNCE_CANCEL:
			return "ANNOUNCE_CANCEL";
		case IMQUIC_MOQ_TRACK_STATUS_REQUEST:
			return "TRACK_STATUS_REQUEST";
		case IMQUIC_MOQ_TRACK_STATUS:
			return "TRACK_STATUS";
		case IMQUIC_MOQ_GOAWAY:
			return "GOAWAY";
		case IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES:
			return "SUBSCRIBE_ANNOUNCES";
		case IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK:
			return "SUBSCRIBE_ANNOUNCES_OK";
		case IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR:
			return "SUBSCRIBE_ANNOUNCES_ERROR";
		case IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES:
			return "UNSUBSCRIBE_ANNOUNCES";
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
		case IMQUIC_MOQ_CLIENT_SETUP_LEGACY:
			return "CLIENT_SETUP";
		case IMQUIC_MOQ_SERVER_SETUP:
		case IMQUIC_MOQ_SERVER_SETUP_LEGACY:
			return "SERVER_SETUP";
		case IMQUIC_MOQ_PUBLISH:
			return "PUBLISH";
		case IMQUIC_MOQ_PUBLISH_OK:
			return "PUBLISH_OK";
		case IMQUIC_MOQ_PUBLISH_ERROR:
			return "PUBLISH_ERROR";
		default: break;
	}
	return NULL;
}

imquic_moq_datagram_message_type imquic_moq_datagram_message_type_return(imquic_moq_version version, gboolean ext, gboolean eog) {
	if(version < IMQUIC_MOQ_VERSION_11)
		return IMQUIC_MOQ_OBJECT_DATAGRAM;
	if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		return ext ? IMQUIC_MOQ_OBJECT_DATAGRAM : IMQUIC_MOQ_OBJECT_DATAGRAM_NOEXT;
	}
	/* If we're here, we're on v12 or later */
	if(!ext && !eog)
		return IMQUIC_MOQ_OBJECT_DATAGRAM_NOEXT;
	else if(ext && !eog)
		return IMQUIC_MOQ_OBJECT_DATAGRAM;
	else if(!ext && eog)
		return IMQUIC_MOQ_OBJECT_DATAGRAM_EOG_NOEXT;
	return IMQUIC_MOQ_OBJECT_DATAGRAM_EOG;
}

void imquic_moq_datagram_message_type_parse(imquic_moq_version version, imquic_moq_datagram_message_type type, gboolean *ext, gboolean *eog) {
	if(version < IMQUIC_MOQ_VERSION_11) {
		return;
	} else if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(ext)
			*ext = (type == IMQUIC_MOQ_OBJECT_DATAGRAM);
	} else {
		/* v12 and later */
		if(ext)
			*ext = (type == IMQUIC_MOQ_OBJECT_DATAGRAM || type == IMQUIC_MOQ_OBJECT_DATAGRAM_EOG);
		if(eog)
			*eog = (type == IMQUIC_MOQ_OBJECT_DATAGRAM_EOG_NOEXT || type == IMQUIC_MOQ_OBJECT_DATAGRAM_EOG);
	}
}

const char *imquic_moq_datagram_message_type_str(imquic_moq_datagram_message_type type, imquic_moq_version version) {
	if(version < IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_OBJECT_DATAGRAM:
				return "OBJECT_DATAGRAM";
			case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_v11:
				return "OBJECT_DATAGRAM_STATUS";
			default: break;
		}
	} else if(version == IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_OBJECT_DATAGRAM_NOEXT:
			case IMQUIC_MOQ_OBJECT_DATAGRAM:
				return "OBJECT_DATAGRAM";
			case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT_v11:
			case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_v11:
				return "OBJECT_DATAGRAM_STATUS";
			default: break;
		}
	} else {
		switch(type) {
			case IMQUIC_MOQ_OBJECT_DATAGRAM_NOEXT:
			case IMQUIC_MOQ_OBJECT_DATAGRAM:
			case IMQUIC_MOQ_OBJECT_DATAGRAM_EOG_NOEXT:
			case IMQUIC_MOQ_OBJECT_DATAGRAM_EOG:
				return "OBJECT_DATAGRAM";
			case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT:
			case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS:
				return "OBJECT_DATAGRAM_STATUS";
			default: break;
		}
	}
	return NULL;
}

imquic_moq_data_message_type imquic_moq_data_message_type_from_subgroup_header(imquic_moq_version version, gboolean subgroup, gboolean sgid0, gboolean ext, gboolean eog) {
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
	if(!subgroup && sgid0 && !ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT;
	else if(!subgroup && sgid0 && ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0;
	else if(!subgroup && !sgid0 && !ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT;
	else if(!subgroup && !sgid0 && ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID;
	else if(subgroup && !ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT;
	else if(subgroup && ext && !eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER;
	else if(!subgroup && sgid0 && !ext && eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_EOG;
	else if(!subgroup && sgid0 && ext && eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG;
	else if(!subgroup && !sgid0 && !ext && eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_EOG;
	else if(!subgroup && !sgid0 && ext && eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_EOG;
	else if(subgroup && !ext && eog)
		return IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_EOG;
	return IMQUIC_MOQ_SUBGROUP_HEADER_EOG;
}

void imquic_moq_data_message_type_to_subgroup_header(imquic_moq_version version, imquic_moq_data_message_type type, gboolean *subgroup, gboolean *sgid0, gboolean *ext, gboolean *eog) {
	if(version < IMQUIC_MOQ_VERSION_11) {
		if(subgroup)
			*subgroup = TRUE;
		if(ext)
			*ext = (version >= IMQUIC_MOQ_VERSION_08);
		return;
	} else if(version == IMQUIC_MOQ_VERSION_11) {
		/* v11 */
		if(subgroup)
			*subgroup = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_v11);
		if(sgid0)
			*sgid0 = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11);
		if(ext)
			*ext = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_v11 || type == IMQUIC_MOQ_SUBGROUP_HEADER_v11);
	} else {
		/* v12 and later */
		if(subgroup) {
			*subgroup = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT || type == IMQUIC_MOQ_SUBGROUP_HEADER ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_EOG);
		}
		if(sgid0) {
			*sgid0 = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0 ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG);
		}
		if(ext) {
			*ext = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0 || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_EOG);
		}
		if(eog) {
			*eog = (type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_EOG ||
				type == IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_EOG || type == IMQUIC_MOQ_SUBGROUP_HEADER_EOG);
		}
	}
}

const char *imquic_moq_data_message_type_str(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_06 && type == IMQUIC_MOQ_STREAM_HEADER_TRACK)
		return "STREAM_HEADER_TRACK";
	if(version < IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY:
				return "SUBGROUP_HEADER";
			case IMQUIC_MOQ_FETCH_HEADER:
				return "FETCH_HEADER";
			default: break;
		}
	} else if(version == IMQUIC_MOQ_VERSION_11) {
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
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_EOG:
				return "SUBGROUP_HEADER";
			case IMQUIC_MOQ_FETCH_HEADER:
				return "FETCH_HEADER";
			default: break;
		}
	}
	return NULL;
}

imquic_moq_delivery imquic_moq_data_message_type_to_delivery(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_06 && type == IMQUIC_MOQ_STREAM_HEADER_TRACK)
		return IMQUIC_MOQ_USE_TRACK;
	if(version < IMQUIC_MOQ_VERSION_11) {
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY:
				return IMQUIC_MOQ_USE_SUBGROUP;
			case IMQUIC_MOQ_FETCH_HEADER:
				return IMQUIC_MOQ_USE_FETCH;
			default: break;
		}
	} else if(version == IMQUIC_MOQ_VERSION_11) {
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
		switch(type) {
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT:
			case IMQUIC_MOQ_SUBGROUP_HEADER:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_NOEXT_EOG:
			case IMQUIC_MOQ_SUBGROUP_HEADER_EOG:
				return IMQUIC_MOQ_USE_SUBGROUP;
			case IMQUIC_MOQ_FETCH_HEADER:
				return IMQUIC_MOQ_USE_FETCH;
			default: break;
		}
	}
	return -1;
}

const char *imquic_moq_setup_parameter_type_str(imquic_moq_setup_parameter_type type) {
	switch(type) {
		case IMQUIC_MOQ_SETUP_PARAM_ROLE:
			return "ROLE";
		case IMQUIC_MOQ_SETUP_PARAM_PATH:
			return "PATH";
		case IMQUIC_MOQ_SETUP_PARAM_MAX_REQUEST_ID:
			return "MAX_REQUEST_ID";
		case IMQUIC_MOQ_SETUP_PARAM_AUTHORIZATION_TOKEN:
			return "AUTHORIZATION_TOKEN";
		case IMQUIC_MOQ_SETUP_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE:
			return "MAX_AUTH_TOKEN_CACHE_SIZE";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_subscribe_parameter_type_str(imquic_moq_subscribe_parameter_type type, imquic_moq_version version) {
	switch(type) {
		case IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN_v11:
			if(version < IMQUIC_MOQ_VERSION_12)
				return "AUTHORIZATION_TOKEN";
			break;
		case IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT:
		/* Also IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_INFO, before v11 */
			if(version < IMQUIC_MOQ_VERSION_11)
				return "AUTHORIZATION_INFO";
			return "DELIVERY_TIMEOUT";
		case IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN:
		/* Also IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT_LEGACY, before v11 */
			if(version < IMQUIC_MOQ_VERSION_11)
				return "DELIVERY_TIMEOUT";
			else if(version >= IMQUIC_MOQ_VERSION_12)
				return "AUTHORIZATION_TOKEN";
			break;
		case IMQUIC_MOQ_SUB_PARAM_MAX_CACHE_DURATION:
			return "MAX_CACHE_DURATION";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_role_type_str(imquic_moq_role_type type) {
	switch(type) {
		case IMQUIC_MOQ_ROLE_ENDPOINT:
			return "Endpoint";
		case IMQUIC_MOQ_ROLE_PUBLISHER:
			return "Publisher";
		case IMQUIC_MOQ_ROLE_SUBSCRIBER:
			return "Subscriber";
		case IMQUIC_MOQ_ROLE_PUBSUB:
			return "PubSub";
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
		if(parameters->role_set)
			*params_num = *params_num + 1;
		if(parameters->path_set)
			*params_num = *params_num + 1;
		if(parameters->max_request_id_set)
			*params_num = *params_num + 1;
		if(parameters->max_auth_token_cache_size_set)
			*params_num = *params_num + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_12 && parameters->auth_token_set)
			*params_num = *params_num + 1;
		offset += imquic_write_varint(*params_num, &bytes[offset], blen-offset);
		if(*params_num > 0) {
			if(parameters->role_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SETUP_PARAM_ROLE, parameters->role);
			}
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
		}
	}
	return offset;
}

size_t imquic_moq_subscribe_parameters_serialize(imquic_moq_context *moq,
		imquic_moq_subscribe_parameters *parameters,
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
		offset += imquic_write_varint(*params_num, &bytes[offset], blen-offset);
		if(*params_num > 0) {
			if(parameters->auth_token_set) {
				int param = IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_INFO;
				if(moq->version >= IMQUIC_MOQ_VERSION_11)
					param = (moq->version >= IMQUIC_MOQ_VERSION_12 ? IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN : IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN_v11);
				offset += imquic_moq_parameter_add_data(moq, &bytes[offset], blen-offset,
					param, parameters->auth_token, parameters->auth_token_len);
			}
			if(parameters->delivery_timeout_set) {
				int param = (moq->version >= IMQUIC_MOQ_VERSION_11 ? IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT : IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT_LEGACY);
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					param, parameters->delivery_timeout);
			}
			if(parameters->max_cache_duration_set) {
				offset += imquic_moq_parameter_add_int(moq, &bytes[offset], blen-offset,
					IMQUIC_MOQ_SUB_PARAM_MAX_CACHE_DURATION, parameters->max_cache_duration);
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

/* FIXME Message parsing */
#define IMQUIC_MOQ_CHECK_ERR(cond, error, code, res, reason) \
	if(cond) { \
		IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", reason); \
		if(error) \
			*(uint8_t *)error = code; \
		return res; \
	}

int imquic_moq_parse_message(imquic_moq_context *moq, uint64_t stream_id, uint8_t *bytes, size_t blen, gboolean complete, gboolean datagram) {
	size_t offset = 0, parsed = 0, parsed_prev = 0;
	uint8_t tlen = 0, error = 0;
	/* If this is a datagram, it can only be OBJECT_DATAGRAM or OBJECT_DATAGRAM_STATUS */
	if(datagram) {
		imquic_moq_datagram_message_type dtype = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
		offset += tlen;
		if(dtype == IMQUIC_MOQ_OBJECT_DATAGRAM || (moq->version >= IMQUIC_MOQ_VERSION_11 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_NOEXT) ||
				(moq->version >= IMQUIC_MOQ_VERSION_12 && (dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_EOG || dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_EOG_NOEXT))) {
			/* Parse this OBJECT_DATAGRAM message */
			parsed = imquic_moq_parse_object_datagram(moq, &bytes[offset], blen-offset, dtype, &error);
			IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
		} else if(moq->version >= IMQUIC_MOQ_VERSION_08 &&
				((moq->version <= IMQUIC_MOQ_VERSION_11 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_v11) ||
				(moq->version == IMQUIC_MOQ_VERSION_11 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT_v11) ||
				(moq->version >= IMQUIC_MOQ_VERSION_12 && (dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS ||
					dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT)))) {
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
			imquic_get_connection_name(moq->conn), offset, imquic_moq_message_type_str(type), type, tlen);
		if(stream_id != moq->control_stream_id) {
			/* Not the control stream, make sure it's a supported message */
			imquic_moq_data_message_type dtype = (imquic_moq_data_message_type)type;
			if((moq->version == IMQUIC_MOQ_VERSION_06 && dtype == IMQUIC_MOQ_STREAM_HEADER_TRACK) ||
					dtype == IMQUIC_MOQ_FETCH_HEADER || (moq->version < IMQUIC_MOQ_VERSION_11 && dtype == IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY) ||
					(moq->version == IMQUIC_MOQ_VERSION_11 && (dtype >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 && dtype <= IMQUIC_MOQ_SUBGROUP_HEADER_v11)) ||
					(moq->version >= IMQUIC_MOQ_VERSION_12 && (dtype >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT && dtype <= IMQUIC_MOQ_SUBGROUP_HEADER_EOG))) {
				/* Create a new MoQ stream and track it */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Stream %"SCNu64" will be used for %s\n",
					imquic_get_connection_name(moq->conn), stream_id, imquic_moq_data_message_type_str(dtype, moq->version));
				moq_stream = g_malloc0(sizeof(imquic_moq_stream));
				moq_stream->stream_id = stream_id;
				moq_stream->type = dtype;
				g_hash_table_insert(moq->streams, imquic_dup_uint64(stream_id), moq_stream);
			} else {
				/* TODO Handle failure */
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] MoQ message '%s' (%02x) is not allowed on media streams\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(type), type);
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
				/* Versions later than 06 require a payload length before the payload */
				if((moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_10) ||
						moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
					/* Versions between 06 and 10 require a varint */
					plen = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
				} else if((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
						moq->version == IMQUIC_MOQ_VERSION_ANY) {
					/* Versions 11 and beyond require a 16 bit integer */
					if(type == IMQUIC_MOQ_CLIENT_SETUP_LEGACY || type == IMQUIC_MOQ_SERVER_SETUP_LEGACY) {
						/* TODO Handle failure */
						IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Got a legacy '%s' (%02x) on a %s connection\n",
							imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(type), type,
							imquic_moq_version_str(imquic_moq_get_version(moq->conn)));
							imquic_connection_close(moq->conn, IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED,
								IMQUIC_CONNECTION_CLOSE_APP, imquic_moq_error_code_str(IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED));
						return -1;
					}
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
				}
				IMQUIC_MOQ_CHECK_ERR(tlen == 0, NULL, 0, -1, "Broken MoQ Message");
				offset += tlen;
				if(plen > blen-offset) {
					/* Try again later */
					IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ] Not enough bytes available to parse this message (%zu > %zu), waiting for more data\n",
						imquic_get_connection_name(moq->conn), plen, blen-offset);
					return 0;
				}
			}
			if(type == IMQUIC_MOQ_CLIENT_SETUP || type == IMQUIC_MOQ_CLIENT_SETUP_LEGACY) {
				/* Parse this CLIENT_SETUP message */
				parsed = imquic_moq_parse_client_setup(moq, &bytes[offset], plen, type == IMQUIC_MOQ_CLIENT_SETUP_LEGACY, &error);
			} else if(type == IMQUIC_MOQ_SERVER_SETUP || type == IMQUIC_MOQ_SERVER_SETUP_LEGACY) {
				/* Parse this SERVER_SETUP message */
				parsed = imquic_moq_parse_server_setup(moq, &bytes[offset], plen, type == IMQUIC_MOQ_SERVER_SETUP_LEGACY, &error);
			} else if(type == IMQUIC_MOQ_MAX_REQUEST_ID) {
				/* Parse this MAX_REQUEST_ID message */
				parsed = imquic_moq_parse_max_request_id(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_REQUESTS_BLOCKED) {
				/* Parse this REQUESTS_BLOCKED message */
				parsed = imquic_moq_parse_requests_blocked(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_ANNOUNCE) {
				/* Parse this ANNOUNCE message */
				parsed = imquic_moq_parse_announce(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_ANNOUNCE_OK) {
				/* Parse this ANNOUNCE_OK message */
				parsed = imquic_moq_parse_announce_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_ANNOUNCE_ERROR) {
				/* Parse this ANNOUNCE_ERROR message */
				parsed = imquic_moq_parse_announce_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNANNOUNCE) {
				/* Parse this UNANNOUNCE message */
				parsed = imquic_moq_parse_unannounce(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_ANNOUNCE_CANCEL) {
				/* Parse this ANNOUNCE_CANCEL message */
				parsed = imquic_moq_parse_announce_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH) {
				/* Parse this PUBLISH message */
				parsed = imquic_moq_parse_publish(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_OK) {
				/* Parse this PUBLISH_OK message */
				parsed = imquic_moq_parse_publish_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_PUBLISH_ERROR) {
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
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ERROR) {
				/* Parse this SUBSCRIBE_ERROR message */
				parsed = imquic_moq_parse_subscribe_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE) {
				/* Parse this UNSUBSCRIBE message */
				parsed = imquic_moq_parse_unsubscribe(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_DONE) {
				/* Parse this SUBSCRIBE_DONE message */
				parsed = imquic_moq_parse_subscribe_done(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES) {
				/* Parse this SUBSCRIBE_ANNOUNCES message */
				parsed = imquic_moq_parse_subscribe_announces(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK) {
				/* Parse this SUBSCRIBE_ANNOUNCES_OK message */
				parsed = imquic_moq_parse_subscribe_announces_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR) {
				/* Parse this SUBSCRIBE_ANNOUNCES_ERROR message */
				parsed = imquic_moq_parse_subscribe_announces_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES) {
				/* Parse this UNSUBSCRIBE_ANNOUNCES message */
				parsed = imquic_moq_parse_unsubscribe_announces(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH) {
				/* Parse this FETCH message */
				parsed = imquic_moq_parse_fetch(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_CANCEL) {
				/* Parse this FETCH_CANCEL message */
				parsed = imquic_moq_parse_fetch_cancel(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_OK) {
				/* Parse this FETCH_OK message */
				parsed = imquic_moq_parse_fetch_ok(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_FETCH_ERROR) {
				/* Parse this FETCH_ERROR message */
				parsed = imquic_moq_parse_fetch_error(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS_REQUEST) {
				/* Parse this TRACK_STATUS_REQUEST message */
				parsed = imquic_moq_parse_track_status_request(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_TRACK_STATUS) {
				/* Parse this TRACK_STATUS message */
				parsed = imquic_moq_parse_track_status_request(moq, &bytes[offset], plen, &error);
			} else if(type == IMQUIC_MOQ_GOAWAY) {
				/* Parse this GOAWAY message */
				parsed = imquic_moq_parse_goaway(moq, &bytes[offset], plen, &error);
			} else {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
				imquic_moq_buffer_shift(moq->buffer, plen);
				return -1;
			}
			if(error) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Error parsing MoQ message %s: %s\n",
					imquic_get_connection_name(moq->conn),
					imquic_moq_message_type_str(type),
					imquic_moq_error_code_str(error));
				imquic_moq_buffer_shift(moq->buffer, plen);
				if(error != IMQUIC_MOQ_UNKNOWN_ERROR)
					imquic_connection_close(moq->conn, error, IMQUIC_CONNECTION_CLOSE_APP, imquic_moq_error_code_str(error));
				return -1;
			}
			/* Move to the next message */
			offset += parsed;
			imquic_moq_buffer_shift(moq->buffer, offset);
			bytes = moq->buffer->bytes;
			blen = moq->buffer->length;
			offset = 0;
		} else {
			/* Data message */
			if(moq->version == IMQUIC_MOQ_VERSION_06 && (imquic_moq_data_message_type)type == IMQUIC_MOQ_STREAM_HEADER_TRACK) {
				/* Parse this STREAM_HEADER_TRACK message */
				parsed = imquic_moq_parse_stream_header_track(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((moq->version < IMQUIC_MOQ_VERSION_11 && (imquic_moq_data_message_type)type == IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY) ||
					(moq->version == IMQUIC_MOQ_VERSION_11 &&
						(imquic_moq_data_message_type)type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 && (imquic_moq_data_message_type)type <= IMQUIC_MOQ_SUBGROUP_HEADER_v11) ||
					(moq->version >= IMQUIC_MOQ_VERSION_12 &&
						((imquic_moq_data_message_type)type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT && (imquic_moq_data_message_type)type <= IMQUIC_MOQ_SUBGROUP_HEADER_EOG))) {
				/* Parse this SUBGROUP_HEADER message */
				parsed = imquic_moq_parse_subgroup_header(moq, moq_stream, &bytes[offset], blen-offset, (imquic_moq_data_message_type)type, &error);
				IMQUIC_MOQ_CHECK_ERR(error, NULL, 0, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((imquic_moq_data_message_type)type == IMQUIC_MOQ_FETCH_HEADER) {
				/* Parse this FETCH_HEADER message */
				parsed = imquic_moq_parse_fetch_header(moq, moq_stream, &bytes[offset], blen-offset, &error);
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
			if(moq->version == IMQUIC_MOQ_VERSION_06 && moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_stream_header_track_object(moq, moq_stream, complete) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else if((moq->version < IMQUIC_MOQ_VERSION_11 && moq_stream->type == IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY) ||
					(moq->version == IMQUIC_MOQ_VERSION_11 && (moq_stream->type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 && moq_stream->type <= IMQUIC_MOQ_SUBGROUP_HEADER_v11)) ||
					(moq->version >= IMQUIC_MOQ_VERSION_12 && (moq_stream->type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT && moq_stream->type <= IMQUIC_MOQ_SUBGROUP_HEADER_EOG))) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_subgroup_header_object(moq, moq_stream, complete) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else if(moq_stream->type == IMQUIC_MOQ_FETCH_HEADER) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_fetch_header_object(moq, moq_stream, complete) < 0) {
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
	}
	if(moq_stream != NULL && complete) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Media stream %"SCNu64" is complete\n",
			imquic_get_connection_name(moq->conn), stream_id);
		if(!moq_stream->closed && (moq_stream->type == IMQUIC_MOQ_FETCH_HEADER ||
				(moq->version < IMQUIC_MOQ_VERSION_11 && moq_stream->type == IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY) ||
					(moq->version == IMQUIC_MOQ_VERSION_11 && (moq_stream->type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT_v11 && moq_stream->type <= IMQUIC_MOQ_SUBGROUP_HEADER_v11)) ||
					(moq->version >= IMQUIC_MOQ_VERSION_12 && (moq_stream->type >= IMQUIC_MOQ_SUBGROUP_HEADER_NOSGID0_NOEXT && moq_stream->type <= IMQUIC_MOQ_SUBGROUP_HEADER_EOG)) ||
				(moq->version == IMQUIC_MOQ_VERSION_06 && moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK))) {
			/* FIXME Notify an empty payload to signal the end of the stream */
			imquic_moq_object object = {
				.request_id = moq_stream->request_id,
				.track_alias = moq_stream->track_alias,
				.group_id = moq_stream->group_id,
				.subgroup_id = moq_stream->subgroup_id,
				.object_id = 0,	/* FIXME */
				.object_status = IMQUIC_MOQ_NORMAL_OBJECT,
				.priority = 0,
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

size_t imquic_moq_parse_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, gboolean legacy, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	if(!moq->is_server) {
		/* TODO Got a CLIENT_SETUP but we're a client, do something about it */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Received a CLIENT_SETUP, but we're a client\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	if(legacy && ((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
			moq->version == IMQUIC_MOQ_VERSION_ANY)) {
		/* Got a legacy CLIENT_SETUP on a new (>=11) MoQ connection */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Received a legacy CLIENT_SETUP, but we're using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_version_str(imquic_moq_get_version(moq->conn)));
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t supported_vers = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken CLIENT_SETUP");
	offset += length;
	uint64_t i = 0;
	uint64_t version = 0;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- %"SCNu64" supported versions:\n",
		imquic_get_connection_name(moq->conn), supported_vers);
	g_list_free(moq->supported_versions);
	moq->supported_versions = NULL;
	for(i = 0; i<supported_vers; i++) {
		version = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken CLIENT_SETUP");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
			imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
		if(!moq->version_set) {
			if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
				moq->version_set = TRUE;
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- -- Selected version %"SCNu32"\n",
					imquic_get_connection_name(moq->conn), moq->version);
			} else if(((version >= IMQUIC_MOQ_VERSION_11 && version <= IMQUIC_MOQ_VERSION_MAX) && moq->version == IMQUIC_MOQ_VERSION_ANY) ||
					((version >= IMQUIC_MOQ_VERSION_MIN && version <= IMQUIC_MOQ_VERSION_10) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY)) {
				moq->version = version;
				moq->version_set = TRUE;
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
		if(parameters.role_set) {
			/* TODO Keep track of it and/or validate it */
		} else if(parameters.max_request_id_set) {
			/* Update the value we have */
			moq->max_request_id = parameters.max_request_id;
		} else if(parameters.max_auth_token_cache_size && moq->version >= IMQUIC_MOQ_VERSION_11) {
			/* Update the value we have */
			moq->max_auth_token_cache_size = parameters.max_auth_token_cache_size;
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		json_object_set_new(message, "number_of_supported_versions", json_integer(supported_vers));
		json_t *versions = json_array();
		GList *temp = moq->supported_versions;
		while(temp) {
			json_array_append_new(versions, json_integer(GPOINTER_TO_UINT(temp->data)));
			temp = temp->next;
		}
		json_object_set_new(message, "supported_versions", versions);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, &parameters, "setup_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
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
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		s_parameters.role_set = TRUE;
		s_parameters.role = moq->type;
	}
	if(moq->local_max_request_id > 0) {
		s_parameters.max_request_id_set = TRUE;
		s_parameters.max_request_id = moq->local_max_request_id;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && moq->local_max_auth_token_cache_size > 0) {
		s_parameters.max_auth_token_cache_size_set = TRUE;
		s_parameters.max_auth_token_cache_size = moq->local_max_auth_token_cache_size;
	}
	uint8_t buffer[200];
	size_t buflen = sizeof(buffer), poffset = 5, start = 0;
	size_t ss_len = imquic_moq_add_server_setup(moq, &buffer[poffset], buflen-offset, moq->version, &s_parameters);
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
		ss_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SERVER_SETUP, buffer, buflen, poffset, ss_len, &start);
	} else {
		ss_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SERVER_SETUP_LEGACY, buffer, buflen, poffset, ss_len, &start);
	}
	imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ss_len, FALSE);
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

size_t imquic_moq_parse_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, gboolean legacy, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 5)
		return 0;
	if(legacy && ((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
			moq->version == IMQUIC_MOQ_VERSION_ANY)) {
		/* Got a legacy CLIENT_SETUP on a new (>=11) MoQ connection */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Received a legacy CLIENT_SETUP, but we're using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_version_str(imquic_moq_get_version(moq->conn)));
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Supported version:\n",
		imquic_get_connection_name(moq->conn));
	uint64_t version = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SERVER_SETUP");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
		imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
	if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
		moq->version_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
			imquic_get_connection_name(moq->conn), moq->version);
	} else if(((version >= IMQUIC_MOQ_VERSION_11 && version <= IMQUIC_MOQ_VERSION_MAX) && moq->version == IMQUIC_MOQ_VERSION_ANY) ||
			((version >= IMQUIC_MOQ_VERSION_MIN && version <= IMQUIC_MOQ_VERSION_10) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY)) {
		moq->version = version;
		moq->version_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
			imquic_get_connection_name(moq->conn), moq->version);
	} else {
		IMQUIC_MOQ_CHECK_ERR(version == 0, error, IMQUIC_MOQ_VERSION_NEGOTIATION_FAILED, 0, "No supported version");
	}
	offset += length;
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SERVER_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	imquic_moq_setup_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		offset += imquic_moq_parse_setup_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SERVER_SETUP");
		if(parameters.role_set) {
			/* TODO Keep track of it and/or validate it */
		} else if(parameters.max_request_id_set) {
			/* Update the value we have */
			moq->max_request_id = parameters.max_request_id;
		} else if(parameters.max_auth_token_cache_size_set && moq->version >= IMQUIC_MOQ_VERSION_11) {
			/* Update the value we have */
			moq->max_auth_token_cache_size = parameters.max_auth_token_cache_size;
		}
	}
	if(moq->max_request_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Request ID parameter received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_request_id = 1;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		json_object_set_new(message, "selected_version", json_integer(version));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, &parameters, "setup_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
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
	if(moq->version < IMQUIC_MOQ_VERSION_08)
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.requests_blocked)
		moq->conn->socket->callbacks.moq.requests_blocked(moq->conn, max);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* Make sure this is in line with the expected request ID */
		IMQUIC_MOQ_CHECK_ERR(request_id < moq->expected_request_id, error, IMQUIC_MOQ_TOO_MANY_REQUESTS, 0, "Too many requests");
		uint64_t request_id_increment = (imquic_moq_get_version(moq->conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
		moq->expected_request_id = request_id + request_id_increment;
		IMQUIC_MOQ_CHECK_ERR(request_id >= moq->local_max_request_id, error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	}
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken ANNOUNCE");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken ANNOUNCE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_subscribe_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken ANNOUNCE");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken ANNOUNCE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_announce) {
		moq->conn->socket->callbacks.moq.incoming_announce(moq->conn, request_id, &tns[0]);
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_announce(moq->conn, request_id, &tns[0], IMQUIC_MOQ_ANNCERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_OK");
		IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken ANNOUNCE_OK");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_OK");
			offset += length;
			if(i == tns_num - 1) {
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_OK");
			} else {
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_OK");
			}
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce_ok");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.announce_accepted) {
		moq->conn->socket->callbacks.moq.announce_accepted(moq->conn, request_id,
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tns[0] : NULL));
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
		IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
	}
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare("announce_error");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.announce_error) {
		moq->conn->socket->callbacks.moq.announce_error(moq->conn, request_id,
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tns[0] : NULL), error_code, reason_str);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken UNANNOUNCE");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken UNANNOUNCE");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken UNANNOUNCE");
		offset += length;
		if(i == tns_num - 1) {
			IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, NULL, 0, 0, "Broken UNANNOUNCE");
		} else {
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken UNANNOUNCE");
		}
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unannounce");
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unannounce)
		moq->conn->socket->callbacks.moq.incoming_unannounce(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t error_code = 0;
	char reason[1024], *reason_str = NULL;
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
	offset += length;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken ANNOUNCE_CANCEL");
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
		json_t *message = imquic_qlog_moq_message_prepare("announce_cancel");
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_announce_cancel)
		moq->conn->socket->callbacks.moq.incoming_announce_cancel(moq->conn, &tns[0], error_code, reason);
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
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(moq->version < IMQUIC_MOQ_VERSION_11) {
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH");
	} else {
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	}
	IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len > blen-offset, NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
		imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	imquic_moq_name tn = {
		.length = tn_len,
		.buffer = tn_len ? &bytes[offset] : NULL
	};
	offset += tn_len;
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), group_order);
	if(group_order != IMQUIC_MOQ_ORDERING_ASCENDING && group_order != IMQUIC_MOQ_ORDERING_DESCENDING) {
		IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Group Order value");
	}
	IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
	uint8_t content_exists = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), content_exists);
	imquic_moq_location largest = { 0 };
	if(content_exists > 0) {
		largest.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), largest.group);
		largest.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), largest.object);
	}
	gboolean forward = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), forward);
	uint64_t params_num = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
	params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken PUBLISH");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "content_exists", json_integer(content_exists));
		if(content_exists > 0) {
			json_object_set_new(message, "largest_group_id", json_integer(largest.group));
			json_object_set_new(message, "largest_object_id", json_integer(largest.object));
		}
		json_object_set_new(message, "forward", json_integer(forward));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "publish_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_publish) {
		moq->conn->socket->callbacks.moq.incoming_publish(moq->conn,
			request_id, &tns[0], &tn, track_alias,
			(group_order == IMQUIC_MOQ_ORDERING_DESCENDING),
			&largest, forward,
			(parameters.auth_token_set ? parameters.auth_token : NULL),
			(parameters.auth_token_set ? parameters.auth_token_len : 0));
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_publish(moq->conn, request_id, IMQUIC_MOQ_PUBERR_NOT_SUPPORTED, "Not handled");
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
	gboolean forward = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), forward);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), priority);
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken PUBLISH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), group_order);
	uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
	imquic_moq_location start = { 0 };
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), start.group);
		start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), start.object);
	}
	imquic_moq_location end = { 0 };
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), end.group);
		if(moq->version < IMQUIC_MOQ_VERSION_08) {
			end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), end.object);
		}
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken PUBLISH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_subscribe_parameters parameters = { 0 };
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "forward", json_integer(forward));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.publish_accepted) {
		moq->conn->socket->callbacks.moq.publish_accepted(moq->conn,
			request_id, forward, priority, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING),
			filter, &start, &end,
			(parameters.auth_token_set ? parameters.auth_token : NULL),
			(parameters.auth_token_set ? parameters.auth_token_len : 0));
	}
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
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken PUBLISH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_error_code_str(error_code), error_code);
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
		json_t *message = imquic_qlog_moq_message_prepare("publish_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
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
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(request_id < moq->expected_request_id, error, IMQUIC_MOQ_TOO_MANY_REQUESTS, 0, "Too many requests");
	uint64_t request_id_increment = (imquic_moq_get_version(moq->conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
	moq->expected_request_id = request_id + request_id_increment;
	IMQUIC_MOQ_CHECK_ERR(request_id >= moq->local_max_request_id, error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	/* Move on */
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	if(tn_len > 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	}
	IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
	imquic_moq_name tn = {
		.length = tn_len,
		.buffer = tn_len ? &bytes[offset] : NULL
	};
	offset += tn_len;
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), priority);
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), group_order);
	gboolean forward = TRUE;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		forward = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), forward);
	}
	uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
	imquic_moq_location start = { 0 };
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), start.group);
		start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), start.object);
	}
	imquic_moq_location end = { 0 };
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), end.group);
		if(moq->version < IMQUIC_MOQ_VERSION_08) {
			end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), end.object);
		}
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_subscribe_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "forward", json_integer(forward));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Track this subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, track_alias);
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe) {
		moq->conn->socket->callbacks.moq.incoming_subscribe(moq->conn,
			request_id, track_alias, &tns[0], &tn,
			priority, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), forward,
			filter, &start, &end,
			(parameters.auth_token_set ? parameters.auth_token : NULL),
			(parameters.auth_token_set ? parameters.auth_token_len : 0));
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe(moq->conn, request_id, IMQUIC_MOQ_SUBERR_NOT_SUPPORTED, "Not handled", track_alias);
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
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	imquic_moq_location start = { 0 };
	start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), start.group);
	start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), start.object);
	uint64_t end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), end_group);
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		uint64_t end_object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), end_object);
	}
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), priority);
	gboolean forward = TRUE;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Forward value");
		forward = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Forward: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), forward);
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "start_group", json_integer(start.group));
		json_object_set_new(message, "start_object", json_integer(start.object));
		json_object_set_new(message, "end_group", json_integer(end_group));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_updated) {
		moq->conn->socket->callbacks.moq.subscribe_updated(moq->conn,
			request_id, &start, end_group, priority, forward);
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
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t track_alias = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_12) {
		track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), track_alias);
	}
	uint64_t expires = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Expires: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), expires);
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8" (%s)\n",
		imquic_get_connection_name(moq->conn), group_order, imquic_moq_group_order_str(group_order));
	if(group_order != IMQUIC_MOQ_ORDERING_ASCENDING && group_order != IMQUIC_MOQ_ORDERING_DESCENDING) {
		/* TODO This should be treated as an error */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Invalid Group Order %02x\n",
			imquic_get_connection_name(moq->conn), group_order);
	}
	IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
	uint8_t content_exists = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), content_exists);
	imquic_moq_location largest = { 0 };
	if(content_exists > 0) {
		largest.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), largest.group);
		largest.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), largest.object);
	}
	uint64_t params_num = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_OK");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "expires", json_integer(expires));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "content_exists", json_integer(content_exists));
		if(content_exists > 0) {
			json_object_set_new(message, "largest_group_id", json_integer(largest.group));
			json_object_set_new(message, "largest_object_id", json_integer(largest.object));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_accepted)
		moq->conn->socket->callbacks.moq.subscribe_accepted(moq->conn, request_id, track_alias,
			expires, group_order == IMQUIC_MOQ_ORDERING_DESCENDING, content_exists ? &largest : NULL);
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
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_error_code_str(error_code), error_code);
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
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_error)
		moq->conn->socket->callbacks.moq.subscribe_error(moq->conn, request_id, error_code, reason_str, track_alias);
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe(moq->conn, request_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t status_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_done_code_str(status_code), status_code);
	uint64_t streams_count = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_08) {
		streams_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Streams Count: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), streams_count);
	}
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || (moq->version < IMQUIC_MOQ_VERSION_08 && length >= blen-offset) ||
		(moq->version >= IMQUIC_MOQ_VERSION_08 && length > blen-offset), NULL, 0, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(((moq->version < IMQUIC_MOQ_VERSION_08 && rs_len >= blen-offset) ||
			(moq->version >= IMQUIC_MOQ_VERSION_08 && rs_len > blen-offset)), NULL, 0, 0, "Broken SUBSCRIBE_DONE");
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
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		IMQUIC_MOQ_CHECK_ERR(bytes[offset] > 1, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Content Exists value");
		uint8_t content_exists = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), content_exists);
		if(content_exists > 0) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
			uint64_t fg_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Final Group ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), fg_id);
			uint64_t fo_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_DONE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Final Object ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), fo_id);
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_done");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status_code));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_done)
		moq->conn->socket->callbacks.moq.subscribe_done(moq->conn, request_id, status_code, streams_count, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* Make sure this is in line with the expected request ID */
		IMQUIC_MOQ_CHECK_ERR(request_id < moq->expected_request_id, error, IMQUIC_MOQ_TOO_MANY_REQUESTS, 0, "Too many requests");
		uint64_t request_id_increment = (imquic_moq_get_version(moq->conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
		moq->expected_request_id = request_id + request_id_increment;
		IMQUIC_MOQ_CHECK_ERR(request_id >= moq->local_max_request_id, error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	}
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_subscribe_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe_announces) {
		moq->conn->socket->callbacks.moq.incoming_subscribe_announces(moq->conn, request_id, &tns[0],
			(parameters.auth_token_set ? parameters.auth_token : NULL),
			(parameters.auth_token_set ? parameters.auth_token_len : 0));
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe_announces(moq->conn, request_id, &tns[0], IMQUIC_MOQ_SUBANNCERR_NOT_SUPPORTED, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	} else {
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
			offset += length;
			if(i == tns_num - 1) {
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
			} else {
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
			}
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces_ok");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_announces_accepted) {
		moq->conn->socket->callbacks.moq.subscribe_announces_accepted(moq->conn, request_id,
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tns[0] : NULL));
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	} else {
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
	}
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
	offset += length;
	char reason[1024], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, NULL, 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
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
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces_error");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_announces_error) {
		moq->conn->socket->callbacks.moq.subscribe_announces_error(moq->conn, request_id,
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tns[0] : NULL), error_code, reason_str);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		offset += length;
		if(i == tns_num - 1) {
			IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		} else {
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		}
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe_announces");
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe_announces)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe_announces(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* Make sure this is in line with the expected request ID */
	IMQUIC_MOQ_CHECK_ERR(request_id < moq->expected_request_id, error, IMQUIC_MOQ_TOO_MANY_REQUESTS, 0, "Too many requests");
	uint64_t request_id_increment = (imquic_moq_get_version(moq->conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
	moq->expected_request_id = request_id + request_id_increment;
	IMQUIC_MOQ_CHECK_ERR(request_id >= moq->local_max_request_id, error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	/* Move on */
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	imquic_moq_name tn = { 0 };
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken FETCH");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
		uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, NULL, 0, 0, "Broken FETCH");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tn_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
		tn.length = tn_len;
		tn.buffer = tn_len ? &bytes[offset] : NULL;
		offset += tn_len;
	}
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), priority);
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %s (%"SCNu8"))\n",
		imquic_get_connection_name(moq->conn), imquic_moq_group_order_str(group_order), group_order);
	imquic_moq_fetch_type type = IMQUIC_MOQ_FETCH_STANDALONE;
	imquic_moq_fetch_range range = { 0 };
	uint64_t joining_request_id = 0, joining_start = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_08) {
		type = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
			offset += length;
			/* Iterate on all namespaces */
			uint64_t i = 0;
			for(i = 0; i < tns_num; i++) {
				IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
				uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
				IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
				offset += length;
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken FETCH");
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
					imquic_get_connection_name(moq->conn), tns_len);
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
					imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
				tns[i].length = tns_len;
				tns[i].buffer = tns_len ? &bytes[offset] : NULL;
				tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
				offset += tns_len;
			}
			uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
			IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, NULL, 0, 0, "Broken FETCH");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tn_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
			tn.length = tn_len;
			tn.buffer = tn_len ? &bytes[offset] : NULL;
			offset += tn_len;
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
			if(type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE && moq->version < IMQUIC_MOQ_VERSION_11) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Broken FETCH, invalid type '%d'\n",
					imquic_get_connection_name(moq->conn), type);
				return 0;
			}
			joining_request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
			offset += length;
			/* FIXME Should check if this request ID exists, or do we leave it to the application? */
			joining_start = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
			offset += length;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Broken FETCH, invalid type '%d'\n",
				imquic_get_connection_name(moq->conn), type);
			return 0;
		}
	} else {
		range.start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.start.group);
		range.start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.start.object);
		range.end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.end.group);
		range.end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.end.object);
	}
	uint64_t params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	imquic_moq_subscribe_parameters parameters = { 0 };
	uint64_t i = 0;
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken FETCH");
	}
	/* Track this fetch subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, 0);
	moq_sub->fetch = TRUE;
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "fetch_type", json_integer(type));
		if(moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE) {
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
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE) {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_standalone_fetch) {
			moq->conn->socket->callbacks.moq.incoming_standalone_fetch(moq->conn,
				request_id, &tns[0], &tn, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), &range,
				(parameters.auth_token_set ? parameters.auth_token : NULL),
				(parameters.auth_token_set ? parameters.auth_token_len : 0));
		} else {
			/* FIXME No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_FETCHERR_NOT_SUPPORTED, "Not handled");
		}
	} else {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_joining_fetch) {
			moq->conn->socket->callbacks.moq.incoming_joining_fetch(moq->conn,
				request_id, joining_request_id,
				(type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE), joining_start,
				(group_order == IMQUIC_MOQ_ORDERING_DESCENDING),
				(parameters.auth_token_set ? parameters.auth_token : NULL),
				(parameters.auth_token_set ? parameters.auth_token_len : 0));
		} else {
			/* FIXME No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, request_id, IMQUIC_MOQ_FETCHERR_NOT_SUPPORTED, "Not handled");
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
	if(moq->version < IMQUIC_MOQ_VERSION_07)
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
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
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), group_order);
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
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params_num);
	uint64_t i = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	for(i = 0; i<params_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken FETCH_OK");
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken FETCH_OK");
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(largest.group));
		json_object_set_new(message, "largest_object_id", json_integer(largest.object));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_accepted)
		moq->conn->socket->callbacks.moq.fetch_accepted(moq->conn, request_id, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), &largest);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken FETCH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_error_code_str(error_code), error_code);
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
		json_t *message = imquic_qlog_moq_message_prepare("fetch_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error_code));
		if(reason_str != NULL)
			json_object_set_new(message, "reason", json_string(reason_str));
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_error)
		moq->conn->socket->callbacks.moq.fetch_error(moq->conn, request_id, error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* Make sure this is in line with the expected request ID */
		IMQUIC_MOQ_CHECK_ERR(request_id < moq->expected_request_id, error, IMQUIC_MOQ_TOO_MANY_REQUESTS, 0, "Too many requests");
		uint64_t request_id_increment = (imquic_moq_get_version(moq->conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
		moq->expected_request_id = request_id + request_id_increment;
		IMQUIC_MOQ_CHECK_ERR(request_id >= moq->local_max_request_id, error, IMQUIC_MOQ_INVALID_REQUEST_ID, 0, "Invalid Request ID");
	}
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
	IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(moq->version < IMQUIC_MOQ_VERSION_11) {
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
	} else {
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
	}
	IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
		imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	imquic_moq_name tn = {
		.length = tn_len,
		.buffer = tn_len ? &bytes[offset] : NULL
	};
	offset += tn_len;
	uint64_t params_num = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
			imquic_get_connection_name(moq->conn), params_num);
		uint64_t i = 0;
		for(i = 0; i<params_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
			offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
			IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken TRACK_STATUS_REQUEST");
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status_request");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, &tns[0]);
		imquic_qlog_moq_message_add_track(message, &tn);
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "number_of_parameters", json_integer(params_num));
			imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "parameters");
		}
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status_request)
		moq->conn->socket->callbacks.moq.incoming_track_status_request(moq->conn, request_id, &tns[0], &tn);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	imquic_moq_name tn = { 0 };
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_MOQ_CHECK_ERR(tns_num == 0 || tns_num > 32, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid number of namespaces");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tns_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
			tns[i].length = tns_len;
			tns[i].buffer = tns_len ? &bytes[offset] : NULL;
			tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
			offset += tns_len;
		}
		uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_MOQ_CHECK_ERR(tn_len > 4096, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid track name length");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tn_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
		tn.length = tn_len;
		tn.buffer = tn_len ? &bytes[offset] : NULL;
		offset += tn_len;
	}
	uint64_t status_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), status_code);
	imquic_moq_location largest = { 0 };
	largest.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID:  %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.group);
	largest.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.object);
	uint64_t params_num = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		params_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken TRACK_STATUS");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
			imquic_get_connection_name(moq->conn), params_num);
		uint64_t i = 0;
		for(i = 0; i<params_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, NULL, 0, 0, "Broken TRACK_STATUS");
			offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &parameters, error);
			IMQUIC_MOQ_CHECK_ERR(error && *error, NULL, 0, 0, "Broken TRACK_STATUS");
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "request_id", json_integer(request_id));
		} else {
			imquic_qlog_moq_message_add_namespace(message, &tns[0]);
			imquic_qlog_moq_message_add_track(message, &tn);
		}
		json_object_set_new(message, "status_code", json_integer(status_code));
		json_object_set_new(message, "last_group_id", json_integer(largest.group));
		json_object_set_new(message, "last_object_id", json_integer(largest.object));
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "number_of_parameters", json_integer(params_num));
			imquic_qlog_moq_message_add_subscribe_parameters(message, &parameters, "parameters");
		}
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status) {
		moq->conn->socket->callbacks.moq.incoming_track_status(moq->conn, request_id,
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tns[0] : NULL),
			(moq->version < IMQUIC_MOQ_VERSION_11 ? &tn : NULL),
			status_code, &largest);
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
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	}
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
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	/* TODO Check EOG too */
	gboolean has_ext = FALSE;
	imquic_moq_datagram_message_type_parse(moq->version, dtype, &has_ext, NULL);
	if(has_ext) {
		/* The object contains extensions */
		if(moq->version > IMQUIC_MOQ_VERSION_08) {
			ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
			IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_11 && ext_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions length is 0 but type is OBJECT_DATAGRAM");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), ext_len);
			ext_offset = offset;
			IMQUIC_MOQ_CHECK_ERR(length == 0 || ext_len >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
			offset += ext_len;
		} else if(moq->version == IMQUIC_MOQ_VERSION_08) {
			ext_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Count:   %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), ext_count);
			ext_offset = offset;
			if(ext_count > 0) {
				/* Parse extensions */
				uint64_t i = 0;
				for(i=0; i<ext_count; i++) {
					uint64_t ext_type = imquic_read_varint(&bytes[offset], blen-offset, &length);
					if(length == 0 || length >= blen-offset) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", "Broken OBJECT_DATAGRAM");
						return 0;
					}
					offset += length;
					if(ext_type % 2 == 0) {
						/* Even types are followed by a numeric value */
						uint64_t ext_val = imquic_read_varint(&bytes[offset], blen-offset, &length);
						if(length == 0 || length >= blen-offset) {
							IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", "Broken OBJECT_DATAGRAM");
							return 0;
						}
						IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": %"SCNu64"\n",
							imquic_get_connection_name(moq->conn), i, ext_val);
						offset += length;
					} else {
						/* Odd typed are followed by a length and a value */
						uint64_t ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
						if(length == 0 || length >= blen-offset || ext_len >= blen-offset) {
							IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", "Broken OBJECT_DATAGRAM");
							return 0;
						}
						IMQUIC_MOQ_CHECK_ERR(ext_len > UINT16_MAX, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Key-Value-Pair length");
						offset += length;
						IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": (%"SCNu64" bytes)\n",
							imquic_get_connection_name(moq->conn), i, ext_len);
						imquic_print_hex(IMQUIC_MOQ_LOG_HUGE, &bytes[offset], ext_len);
						offset += ext_len;
					}
				}
				ext_len = offset - ext_offset;
			}
		}
	}
	uint64_t object_status = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", "Broken OBJECT_DATAGRAM");
			return 0;
		}
		IMQUIC_MOQ_CHECK_ERR(object_status > IMQUIC_MOQ_END_OF_TRACK, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid object status");
		IMQUIC_MOQ_CHECK_ERR(object_status == IMQUIC_MOQ_OBJECT_DOESNT_EXIST && ext_len > 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions received in object with status 'Does Not Exist'");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:     %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), blen-offset);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.request_id = request_id,
		.track_alias = track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.priority = priority,
		.payload = (blen-offset > 0 ? &bytes[offset] : NULL),
		.payload_len = blen-offset,
		.extensions = (ext_len > 0 ? &bytes[ext_offset] : NULL),
		.extensions_len = ext_len,
		.extensions_count = ext_count,
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
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		return 0;
	if(bytes == NULL || blen < 5)
		return 0;
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
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	if(moq->version > IMQUIC_MOQ_VERSION_08 &&
			((moq->version <= IMQUIC_MOQ_VERSION_11 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_v11) ||
			(moq->version >= IMQUIC_MOQ_VERSION_12 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS))) {
		/* The object contains extensions */
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken OBJECT_DATAGRAM_STATUS");
		IMQUIC_MOQ_CHECK_ERR(moq->version >= IMQUIC_MOQ_VERSION_11 && ext_len == 0, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Extensions length is 0 but type is OBJECT_DATAGRAM_STATUS");
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
		.request_id = 0,
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
		.extensions_count = ext_count,
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

size_t imquic_moq_parse_stream_header_track(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 3)
		return 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken STREAM_HEADER_TRACK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken STREAM_HEADER_TRACK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->track_alias = track_alias;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_stream_header_track_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete) {
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	if(moq->version >= IMQUIC_MOQ_VERSION_07)
		return -1;
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
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
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), p_len);
	if(p_len == 0)
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.request_id = moq_stream->request_id,
		.track_alias = moq_stream->track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.priority = moq_stream->priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.extensions = NULL,
		.extensions_len = 0,
		.extensions_count = 0,
		.delivery = IMQUIC_MOQ_USE_TRACK,
		.end_of_stream = complete
	};
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

size_t imquic_moq_parse_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, imquic_moq_data_message_type dtype, uint8_t *error) {
	if(error)
		*error = IMQUIC_MOQ_UNKNOWN_ERROR;
	if(bytes == NULL || blen < 4)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), request_id);
		/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	}
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
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_ext = FALSE, is_eog = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, dtype, &has_subgroup, &is_sgid0, &has_ext, &is_eog);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][MoQ] SUBGROUP_HEADER type %02x: sg=%d, sgid0=%d, ext=%d, eog=%d\n",
		imquic_get_connection_name(moq->conn), dtype, has_subgroup, is_sgid0, has_ext, is_eog);
	if(has_subgroup) {
		subgroup_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken SUBGROUP_HEADER");
		offset += length;
	} else {
		/* TODO The subgroup ID may need to be set to the first object ID, in some cases */
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subgroup ID:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subgroup_id);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->subgroup_id = subgroup_id;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
#ifdef HAVE_QLOG
		if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "subgroup_header");
			imquic_moq_qlog_subgroup_header_parsed(moq->conn->qlog, moq_stream);
		}
#endif
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete) {
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	/* TODO We can optimize this by only doing it once, when we parse the header */
	/* TODO Check EOG too */
	gboolean has_subgroup = FALSE, is_sgid0 = FALSE, has_ext = FALSE;
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, &has_subgroup, &is_sgid0, &has_ext, NULL);
	if(has_ext) {
		/* The object contains extensions */
		if(moq->version > IMQUIC_MOQ_VERSION_08) {
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
		} else if(moq->version == IMQUIC_MOQ_VERSION_08) {
			ext_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
			if(length == 0 || length >= blen-offset)
				return -1;	/* Not enough data, try again later */
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Count:   %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), ext_count);
			ext_offset = offset;
			if(ext_count > 0) {
				/* Parse extensions */
				uint64_t i = 0;
				for(i=0; i<ext_count; i++) {
					uint64_t ext_type = imquic_read_varint(&bytes[offset], blen-offset, &length);
					if(length == 0 || length >= blen-offset)
						return -1;	/* Not enough data, try again later */
					offset += length;
					if(ext_type % 2 == 0) {
						/* Even types are followed by a numeric value */
						uint64_t ext_val = imquic_read_varint(&bytes[offset], blen-offset, &length);
						if(length == 0 || length >= blen-offset)
							return -1;	/* Not enough data, try again later */
						IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": %"SCNu64"\n",
							imquic_get_connection_name(moq->conn), i, ext_val);
						offset += length;
					} else {
						/* Odd typed are followed by a length and a value */
						uint64_t ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
						if(length == 0 || length >= blen-offset || ext_len >= blen-offset)
							return -1;	/* Not enough data, try again later */
						/* TODO A length larger than UINT16_MAX should be a protocol violation error */
						//~ IMQUIC_MOQ_CHECK_ERR(ext_len > UINT16_MAX, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Key-Value-Pair length");
						offset += length;
						IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": (%"SCNu64" bytes)\n",
							imquic_get_connection_name(moq->conn), i, ext_len);
						imquic_print_hex(IMQUIC_MOQ_LOG_HUGE, &bytes[offset], ext_len);
						offset += ext_len;
					}
				}
				ext_len = offset - ext_offset;
			}
		}
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
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && !moq_stream->got_objects && !has_subgroup && !is_sgid0) {
		/* Starting from v11, there are cases where the subgroup ID
		 * is set to the first object we receive in the sequence */
		moq_stream->subgroup_id = object_id;
	}
	if(!moq_stream->got_objects)
		moq_stream->got_objects = TRUE;
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
		.extensions_count = ext_count,
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
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, NULL, 0, 0, "Broken FETCH_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Request ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), request_id);
	/* FIXME Should check if this request ID exists, or do we leave it to the application? */
	/* Track these properties */
	if(moq_stream != NULL) {
		moq_stream->request_id = request_id;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
#ifdef HAVE_QLOG
		if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
			imquic_moq_qlog_stream_type_set(moq->conn->qlog, FALSE, moq_stream->stream_id, "fetch_header");
			imquic_moq_qlog_fetch_header_parsed(moq->conn->qlog, moq_stream);
		}
#endif
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_fetch_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete) {
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return -1;
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t subgroup_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint8_t priority = bytes[offset];
	offset++;
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	if(moq->version > IMQUIC_MOQ_VERSION_08) {
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
	} else if(moq->version == IMQUIC_MOQ_VERSION_08) {
		ext_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length >= blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Count:   %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_count);
		ext_offset = offset;
		if(ext_count > 0) {
			/* Parse extensions */
			uint64_t i = 0;
			for(i=0; i<ext_count; i++) {
				uint64_t ext_type = imquic_read_varint(&bytes[offset], blen-offset, &length);
				if(length == 0 || length >= blen-offset)
					return -1;	/* Not enough data, try again later */
				offset += length;
				if(ext_type % 2 == 0) {
					/* Even types are followed by a numeric value */
					uint64_t ext_val = imquic_read_varint(&bytes[offset], blen-offset, &length);
					if(length == 0 || length >= blen-offset)
						return -1;	/* Not enough data, try again later */
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": %"SCNu64"\n",
						imquic_get_connection_name(moq->conn), i, ext_val);
					offset += length;
				} else {
					/* Odd typed are followed by a length and a value */
					uint64_t ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
					if(length == 0 || length >= blen-offset || ext_len >= blen-offset)
						return -1;	/* Not enough data, try again later */
					/* TODO A length larger than UINT16_MAX should be a protocol violation error */
					//~ IMQUIC_MOQ_CHECK_ERR(ext_len > UINT16_MAX, error, IMQUIC_MOQ_PROTOCOL_VIOLATION, 0, "Invalid Key-Value-Pair length");
					offset += length;
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- #%"SCNu64": (%"SCNu64" bytes)\n",
						imquic_get_connection_name(moq->conn), i, ext_len);
					imquic_print_hex(IMQUIC_MOQ_LOG_HUGE, &bytes[offset], ext_len);
					offset += ext_len;
				}
			}
			ext_len = offset - ext_offset;
		}
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
		.extensions_count = ext_count,
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
		imquic_moq_qlog_control_message_parsed(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_goaway)
		moq->conn->socket->callbacks.moq.incoming_goaway(moq->conn, uri_str);
	if(error)
		*error = 0;
	return offset;
}

/* FIXME Message building */
size_t imquic_moq_add_control_message(imquic_moq_context *moq, imquic_moq_message_type type,
		uint8_t *bytes, size_t blen, size_t poffset, size_t plen, size_t *start) {
	if(bytes == NULL || blen == 0 || poffset < 2 || (poffset + plen) > blen || start == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ control message: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	/* Write the type to a temporary buffer first */
	uint8_t header[8];
	size_t hlen = sizeof(header);
	size_t offset = imquic_write_varint(type, header, hlen);
	if((moq->version >= IMQUIC_MOQ_VERSION_MIN && moq->version <= IMQUIC_MOQ_VERSION_10) ||
			moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
		/* Versions between 06 and 10 require a varint */
		offset += imquic_write_varint(plen, &header[offset], hlen-offset);
	} else if((moq->version >= IMQUIC_MOQ_VERSION_11 && moq->version <= IMQUIC_MOQ_VERSION_MAX) ||
			moq->version == IMQUIC_MOQ_VERSION_ANY) {
		/* Versions 11 and beyond require a 16 bit integer */
		uint16_t clen = plen;
		clen = htons(clen);
		memcpy(&header[offset], &clen, 2);
		offset += 2;
	}
	if(offset > poffset) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ control message: header size overflows payload offset\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	/* Put ths header right before the payload */
	*start = poffset - offset;
	memcpy(&bytes[*start], header, offset);
	return plen + offset;
}

size_t imquic_moq_add_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		GList *supported_versions, imquic_moq_setup_parameters *parameters) {
	if(bytes == NULL || blen < 1 || g_list_length(supported_versions) < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_CLIENT_SETUP));
		return 0;
	}
	size_t offset = imquic_write_varint(g_list_length(supported_versions), bytes, blen);
	GList *temp = supported_versions;
	while(temp) {
		uint32_t version = GPOINTER_TO_UINT(temp->data);
		offset += imquic_write_varint(version, &bytes[offset], blen-offset);
		temp = temp->next;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_setup_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("client_setup");
		json_object_set_new(message, "number_of_supported_versions", json_integer(g_list_length(supported_versions)));
		json_t *versions = json_array();
		temp = supported_versions;
		while(temp) {
			uint32_t version = GPOINTER_TO_UINT(temp->data);
			json_array_append_new(versions, json_integer(version));
			temp = temp->next;
		}
		json_object_set_new(message, "supported_versions", versions);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, parameters, "setup_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint32_t version, imquic_moq_setup_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SERVER_SETUP));
		return 0;
	}
	size_t offset = imquic_write_varint(version, bytes, blen);
	uint8_t params_num = 0;
	offset += imquic_moq_setup_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("server_setup");
		json_object_set_new(message, "selected_version", json_integer(version));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_setup_parameters(message, parameters, "setup_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_max_request_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_MAX_REQUEST_ID));
		return 0;
	}
	size_t offset = imquic_write_varint(max_request_id, bytes, blen);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("max_request_id");
		json_object_set_new(message, "request_id", json_integer(max_request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_requests_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUESTS_BLOCKED));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_REQUESTS_BLOCKED),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(max_request_id, bytes, blen);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("requests_blocked");
		json_object_set_new(message, "maximum_request_id", json_integer(max_request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11)
		offset += imquic_write_varint(request_id, bytes, blen);
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || (moq->version < IMQUIC_MOQ_VERSION_11 && track_namespace == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_OK));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		offset += imquic_write_varint(request_id, bytes, blen);
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = 0;
		imquic_moq_namespace *temp = track_namespace;
		while(temp) {
			if(temp->length > 0 && temp->buffer == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_OK));
				return 0;
			}
			tns_num++;
			temp = temp->next;
		}
		if(tns_num == 0 || tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_OK));
			return 0;
		}
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce_ok");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_announce_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (moq->version < IMQUIC_MOQ_VERSION_11 && track_namespace == NULL) || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_ERROR));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		offset += imquic_write_varint(request_id, bytes, blen);
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = 0;
		imquic_moq_namespace *temp = track_namespace;
		while(temp) {
			if(temp->length > 0 && temp->buffer == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_ERROR));
				return 0;
			}
			tns_num++;
			temp = temp->next;
		}
		if(tns_num == 0 || tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_ERROR));
			return 0;
		}
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
	}
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce_error");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNANNOUNCE));
		return 0;
	}
	size_t offset = 0;
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNANNOUNCE));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNANNOUNCE));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unannounce");
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_announce_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_CANCEL));
		return 0;
	}
	size_t offset = 0;
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_CANCEL));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_CANCEL));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("announce_cancel");
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint64_t track_alias, uint8_t group_order,
		gboolean content_exists, uint64_t largest_group_id, uint64_t largest_object_id, gboolean forward, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	if(track_name->length > 4096) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	bytes[offset] = group_order;
	offset++;
	bytes[offset] = content_exists;
	offset++;
	if(content_exists) {
		offset += imquic_write_varint(largest_group_id, &bytes[offset], blen-offset);
		offset += imquic_write_varint(largest_object_id, &bytes[offset], blen-offset);
	}
	bytes[offset] = forward;
	offset++;
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "content_exists", json_integer(content_exists));
		if(content_exists > 0) {
			json_object_set_new(message, "largest_group_id", json_integer(largest_group_id));
			json_object_set_new(message, "largest_object_id", json_integer(largest_object_id));
		}
		json_object_set_new(message, "forward", json_integer(forward));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		gboolean forward, uint8_t priority, uint8_t group_order,
		imquic_moq_filter_type filter, uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object,
		imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	bytes[offset] = forward;
	offset++;
	bytes[offset] = priority;
	offset++;
	bytes[offset] = group_order;
	offset++;
	offset += imquic_write_varint(filter, &bytes[offset], blen-offset);
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
	}
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
		if(moq->version < IMQUIC_MOQ_VERSION_08)
			offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("publish_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "forward", json_integer(forward));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "filter_type", json_integer(filter));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_publish_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_pub_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_PUBLISH_ERROR));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn != NULL && moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, uint8_t group_order, gboolean forward,
		imquic_moq_filter_type filter, uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_11 && !forward) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Ignoring forward=false on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_version_str(moq->version));
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	if(track_name->length > 4096) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	bytes[offset] = priority;
	offset++;
	bytes[offset] = group_order;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		bytes[offset] = forward;
		offset++;
	}
	offset += imquic_write_varint(filter, &bytes[offset], blen-offset);
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
	}
	if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
		if(moq->version < IMQUIC_MOQ_VERSION_08)
			offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "track_alias", json_integer(track_alias));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "filter_type", json_integer(filter));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, uint8_t priority,
		gboolean forward, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_UPDATE));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_11 && !forward) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Ignoring forward=false on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_version_str(moq->version));
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
	offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
	offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		bytes[offset] = forward;
		offset++;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_update");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "start_group", json_integer(start_group));
		json_object_set_new(message, "start_object", json_integer(start_object));
		json_object_set_new(message, "end_group", json_integer(end_group));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		uint64_t track_alias, uint64_t expires, imquic_moq_group_order group_order, gboolean content_exists,
		uint64_t largest_group_id, uint64_t largest_object_id, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_OK));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	if(moq->version >= IMQUIC_MOQ_VERSION_12)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(expires, &bytes[offset], blen-offset);
	bytes[offset] = group_order;
	offset++;
	bytes[offset] = content_exists;
	offset++;
	if(content_exists) {
		offset += imquic_write_varint(largest_group_id, &bytes[offset], blen-offset);
		offset += imquic_write_varint(largest_object_id, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "expires", json_integer(expires));
		if(moq->version >= IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "content_exists", json_integer(content_exists));
		if(content_exists > 0) {
			json_object_set_new(message, "largest_group_id", json_integer(largest_group_id));
			json_object_set_new(message, "largest_object_id", json_integer(largest_object_id));
		}
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_sub_error_code error, const char *reason, uint64_t track_alias) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ERROR));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_12)
		offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		if(moq->version < IMQUIC_MOQ_VERSION_12)
			json_object_set_new(message, "track_alias", json_integer(track_alias));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id,
		imquic_moq_sub_done_code status, uint64_t streams_count, const char *reason, gboolean content_exists, uint64_t final_group, uint64_t final_object) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_DONE));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(status, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_08)
		offset += imquic_write_varint(streams_count, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		bytes[offset] = content_exists;
		offset++;
		if(content_exists) {
			offset += imquic_write_varint(final_group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(final_object, &bytes[offset], blen-offset);
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_done");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "status_code", json_integer(status));
		json_object_set_new(message, "streams_count", json_integer(streams_count));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11)
		offset += imquic_write_varint(request_id, bytes, blen);
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || (moq->version < IMQUIC_MOQ_VERSION_11 && track_namespace == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		offset += imquic_write_varint(request_id, bytes, blen);
	} else {
		uint64_t tns_num = 0;
		imquic_moq_namespace *temp = track_namespace;
		while(temp) {
			if(temp->length > 0 && temp->buffer == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK));
				return 0;
			}
			tns_num++;
			temp = temp->next;
		}
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces_ok");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_subannc_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (moq->version < IMQUIC_MOQ_VERSION_11 && track_namespace == NULL) || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		offset += imquic_write_varint(request_id, bytes, blen);
	} else {
		uint64_t tns_num = 0;
		imquic_moq_namespace *temp = track_namespace;
		while(temp) {
			if(temp->length > 0 && temp->buffer == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR));
				return 0;
			}
			tns_num++;
			temp = temp->next;
		}
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
	}
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("subscribe_announces_error");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		else
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES));
		return 0;
	}
	size_t offset = 0;
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("unsubscribe_announces");
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_fetch_type type,
		uint64_t request_id, uint64_t joining_request_id, uint64_t preceding_group_offset,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, imquic_moq_group_order group_order,
		imquic_moq_fetch_range *range, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (range == NULL && (moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	if((moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE) &&
			(track_namespace == NULL || track_name == NULL || (track_name->buffer == NULL && track_name->length > 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_08 && type != IMQUIC_MOQ_FETCH_STANDALONE && type != IMQUIC_MOQ_FETCH_JOINING_RELATIVE && type != IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
		if(track_name->length > 4096) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
			return 0;
		}
		offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
		if(track_name->length > 0) {
			memcpy(&bytes[offset], track_name->buffer, track_name->length);
			offset += track_name->length;
		}
	}
	bytes[offset] = priority;
	offset++;
	bytes[offset] = group_order;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_08) {
		offset += imquic_write_varint(type, &bytes[offset], blen-offset);
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
			temp = track_namespace;
			while(temp) {
				offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
				if(temp->length > 0) {
					memcpy(&bytes[offset], temp->buffer, temp->length);
					offset += temp->length;
				}
				temp = temp->next;
			}
			offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
			if(track_name->length > 0) {
				memcpy(&bytes[offset], track_name->buffer, track_name->length);
				offset += track_name->length;
			}
			offset += imquic_write_varint(range->start.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(range->start.object, &bytes[offset], blen-offset);
			offset += imquic_write_varint(range->end.group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(range->end.object, &bytes[offset], blen-offset);
		} else {
			offset += imquic_write_varint(joining_request_id, &bytes[offset], blen-offset);
			offset += imquic_write_varint(preceding_group_offset, &bytes[offset], blen-offset);
		}
	} else {
		offset += imquic_write_varint(range->start.group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->start.object, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->end.group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(range->end.object, &bytes[offset], blen-offset);
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "subscriber_priority", json_integer(priority));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "fetch_type", json_integer(type));
		if(moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE) {
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
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_CANCEL));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_CANCEL),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_cancel");
		json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint8_t group_order,
		uint8_t end_of_track, uint64_t largest_group_id, uint64_t largest_object_id, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_OK));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_OK),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	bytes[offset] = group_order;
	offset++;
	bytes[offset] = end_of_track;
	offset++;
	offset += imquic_write_varint(largest_group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(largest_object_id, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_ok");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "group_order", json_integer(group_order));
		json_object_set_new(message, "end_of_track", json_integer(end_of_track));
		json_object_set_new(message, "largest_group_id", json_integer(largest_group_id));
		json_object_set_new(message, "largest_object_id", json_integer(largest_object_id));
		json_object_set_new(message, "number_of_parameters", json_integer(params_num));
		imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "subscribe_parameters");
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_fetch_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || (reason && strlen(reason) > 1024)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_ERROR));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH_ERROR),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(request_id, bytes, blen);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("fetch_error");
		json_object_set_new(message, "request_id", json_integer(request_id));
		json_object_set_new(message, "error_code", json_integer(error));
		if(reason != NULL)
			json_object_set_new(message, "reason", json_string(reason));
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11)
		offset += imquic_write_varint(request_id, bytes, blen);
	/* Potentially multiple namespaces (tuple) */
	uint64_t tns_num = 0;
	imquic_moq_namespace *temp = track_namespace;
	while(temp) {
		if(temp->length > 0 && temp->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
			return 0;
		}
		tns_num++;
		temp = temp->next;
	}
	if(tns_num == 0 || tns_num > 32) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
		return 0;
	}
	offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
	temp = track_namespace;
	while(temp) {
		offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
		if(temp->length > 0) {
			memcpy(&bytes[offset], temp->buffer, temp->length);
			offset += temp->length;
		}
		temp = temp->next;
	}
	if(track_name->length > 4096) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
		return 0;
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status_request");
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			json_object_set_new(message, "request_id", json_integer(request_id));
		imquic_qlog_moq_message_add_namespace(message, track_namespace);
		imquic_qlog_moq_message_add_track(message, track_name);
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "number_of_parameters", json_integer(params_num));
			imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "parameters");
		}
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, imquic_moq_namespace *track_namespace, imquic_moq_name *track_name,
		uint64_t status_code, uint64_t last_group_id, uint64_t last_object_id, imquic_moq_subscribe_parameters *parameters) {
	if(bytes == NULL || blen < 1 || (moq->version < IMQUIC_MOQ_VERSION_11 &&
			(track_namespace == NULL || track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS));
		return 0;
	}
	size_t offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		offset += imquic_write_varint(request_id, bytes, blen);
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = 0;
		imquic_moq_namespace *temp = track_namespace;
		while(temp) {
			if(temp->length > 0 && temp->buffer == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
					imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS));
				return 0;
			}
			tns_num++;
			temp = temp->next;
		}
		if(tns_num == 0 || tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid number of tuples\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS));
			return 0;
		}
		offset += imquic_write_varint(tns_num, &bytes[offset], blen-offset);
		temp = track_namespace;
		while(temp) {
			offset += imquic_write_varint(temp->length, &bytes[offset], blen-offset);
			if(temp->length > 0) {
				memcpy(&bytes[offset], temp->buffer, temp->length);
				offset += temp->length;
			}
			temp = temp->next;
		}
		if(track_name->length > 4096) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid track name length\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
			return 0;
		}
		offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
		if(track_name->length > 0) {
			memcpy(&bytes[offset], track_name->buffer, track_name->length);
			offset += track_name->length;
		}
	}
	offset += imquic_write_varint(status_code, &bytes[offset], blen-offset);
	offset += imquic_write_varint(last_group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(last_object_id, &bytes[offset], blen-offset);
	uint8_t params_num = 0;
	offset += imquic_moq_subscribe_parameters_serialize(moq, parameters, &bytes[offset], blen-offset, &params_num);
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("track_status");
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "request_id", json_integer(request_id));
		} else {
			imquic_qlog_moq_message_add_namespace(message, track_namespace);
			imquic_qlog_moq_message_add_track(message, track_name);
		}
		json_object_set_new(message, "status_code", json_integer(status_code));
		json_object_set_new(message, "last_group_id", json_integer(last_group_id));
		json_object_set_new(message, "last_object_id", json_integer(last_object_id));
		if(moq->version >= IMQUIC_MOQ_VERSION_11) {
			json_object_set_new(message, "number_of_parameters", json_integer(params_num));
			imquic_qlog_moq_message_add_subscribe_parameters(message, parameters, "parameters");
		}
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t request_id, uint64_t track_alias,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint8_t priority,
		uint8_t *payload, size_t plen, size_t extensions_count, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM, moq->version));
		return 0;
	}
	imquic_moq_datagram_message_type dtype = IMQUIC_MOQ_OBJECT_DATAGRAM;
	/* TODO Involve EOG */
	gboolean has_ext = (extensions != NULL && elen > 0), is_eog = FALSE;
	dtype = imquic_moq_datagram_message_type_return(moq->version, has_ext, is_eog);
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_08 && has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions_count, extensions, elen);
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	if(payload != NULL && plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t track_alias, uint64_t group_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *extensions, size_t elen) {
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_datagram_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version));
		return 0;
	}
	imquic_moq_datagram_message_type dtype = (moq->version >= IMQUIC_MOQ_VERSION_12 ? IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS : IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_v11);
	gboolean has_ext = (extensions != NULL && elen > 0);
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && has_ext)
		dtype = (moq->version >= IMQUIC_MOQ_VERSION_12 ? IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT : IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS_NOEXT_v11);
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_08 && has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, 0, extensions, elen);
	offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_stream_header_track(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t track_alias, uint8_t priority) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_TRACK, moq->version));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_TRACK, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_STREAM_HEADER_TRACK, bytes, blen);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	return offset;
}

size_t imquic_moq_add_stream_header_track_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_TRACK, moq->version));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s object on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_TRACK, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen,
		uint64_t request_id, uint64_t track_alias, uint64_t group_id, uint64_t subgroup_id, uint8_t priority) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	imquic_moq_data_message_type dtype = moq_stream->type;
	if(moq->version < IMQUIC_MOQ_VERSION_11) {
		/* Whatever was passed, ignore it and use the legacy type */
		dtype = IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY;
	}
	size_t offset = imquic_write_varint(dtype, bytes, blen);
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(subgroup_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	return offset;
}

size_t imquic_moq_add_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream,
		uint8_t *bytes, size_t blen, uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen,
		size_t extensions_count, uint8_t *extensions, size_t elen) {
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
	imquic_moq_data_message_type_to_subgroup_header(moq->version, moq_stream->type, NULL, NULL, &has_ext, NULL);
	if(has_ext)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions_count, extensions, elen);
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
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_FETCH_HEADER, bytes, blen);
	offset += imquic_write_varint(request_id, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_fetch_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t group_id, uint64_t subgroup_id, uint64_t object_id, uint8_t priority,
		uint64_t object_status, uint8_t *payload, size_t plen,
		size_t extensions_count, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s object on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_FETCH_HEADER, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(subgroup_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_08)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions_count, extensions, elen);
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

size_t imquic_moq_add_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, const char *new_session_uri) {
	if(bytes == NULL || blen < 1 || (new_session_uri && strlen(new_session_uri) > 8192)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_GOAWAY));
		return 0;
	}
	if(!moq->is_server && new_session_uri != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: clients can't send a new session URI\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_GOAWAY));
		return 0;
	}
	size_t uri_len = new_session_uri ? strlen(new_session_uri) : 0;
	size_t offset = imquic_write_varint(uri_len, bytes, blen);
	if(uri_len > 0) {
		memcpy(&bytes[offset], new_session_uri, uri_len);
		offset += uri_len;
	}
#ifdef HAVE_QLOG
	if(moq->conn->qlog != NULL && moq->conn->qlog->moq) {
		json_t *message = imquic_qlog_moq_message_prepare("goaway");
		imquic_qlog_event_add_raw(message, "new_session_uri", (uint8_t *)new_session_uri, uri_len);
		imquic_moq_qlog_control_message_created(moq->conn->qlog, moq->control_stream_id, offset, message);
	}
#endif
	return offset;
}

size_t imquic_moq_add_object_extensions(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		size_t extensions_count, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't serialize MoQ object extensions: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		return 0;
	if(extensions == NULL || elen == 0 || (moq->version == IMQUIC_MOQ_VERSION_08 && extensions_count == 0)) {
		extensions_count = 0;
		extensions = NULL;
		elen = 0;
	}
	size_t offset = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_08)
		offset += imquic_write_varint(extensions_count, &bytes[offset], blen-offset);
	else
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
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && (param % 2 != 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric parameter %d: type is odd\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	if(moq->version < IMQUIC_MOQ_VERSION_11) {
		/* Old way of serializing a numeric parameter, by prefixing a length property */
		uint8_t buffer[8];
		uint8_t length = imquic_write_varint(number, buffer, sizeof(buffer));
		offset += imquic_write_varint(length, &bytes[offset], blen-offset);
		if(length > blen-offset) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Insufficient buffer (%"SCNu8" > %zu), truncating...\n",
				imquic_get_connection_name(moq->conn), length, blen-offset);
			length = blen-offset;
		}
		memcpy(&bytes[offset], buffer, length);
		offset += length;
	} else {
		/* New way of serializing a numeric parameter, by writing the number as varint right away */
		offset += imquic_write_varint(number, &bytes[offset], blen-offset);
	}
	return offset;
}

size_t imquic_moq_parameter_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0 || (buflen > 0 && buf == 0) || buflen > UINT16_MAX) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter %d: invalid arguments\n",
			imquic_get_connection_name(moq->conn), param);
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_11 && (param % 2 != 1)) {
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
	if(moq->version < IMQUIC_MOQ_VERSION_11 || (moq->version >= IMQUIC_MOQ_VERSION_11 && (type % 2 == 1))) {
		len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ setup parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
	}
	/* Update the parsed parameter */
	if(type == IMQUIC_MOQ_SETUP_PARAM_ROLE && moq->version < IMQUIC_MOQ_VERSION_08 && len > 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_role_type_str(bytes[offset]));
		params->role_set = TRUE;
		params->role = bytes[offset];
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_PATH) {
		params->path_set = TRUE;
		if(len > 0)
			g_snprintf(params->path, sizeof(params->path), "%.*s", (int)len, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- '%s'\n",
			imquic_get_connection_name(moq->conn), params->path);
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_MAX_REQUEST_ID && (moq->version >= IMQUIC_MOQ_VERSION_11 || len > 0)) {
		params->max_request_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_request_id_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			len = length;
	} else if(type == IMQUIC_MOQ_SETUP_PARAM_MAX_AUTH_TOKEN_CACHE_SIZE && (moq->version >= IMQUIC_MOQ_VERSION_11 || len > 0)) {
		params->max_auth_token_cache_size = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, NULL, 0, 0, "Broken MoQ setup parameter");
		params->max_auth_token_cache_size_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_request_id);
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
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
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter '%"SCNu64"'\n",
			imquic_get_connection_name(moq->conn), type);
		params->unknown = TRUE;
		if(moq->version >= IMQUIC_MOQ_VERSION_11 && (type % 2 == 0))
			len = length;
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_subscribe_parameters *params, uint8_t *error) {
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
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ subscribe parameter");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_subscribe_parameter_type_str(type, moq->version), type);
	uint64_t len = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_11 || (moq->version >= IMQUIC_MOQ_VERSION_11 && (type % 2 == 1))) {
		len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, NULL, 0, 0, "Broken MoQ subscribe parameter");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(len > blen-offset, NULL, 0, 0, "Broken MoQ subscribe parameter");
	}
	/* Update the parsed parameter */
	if((moq->version >= IMQUIC_MOQ_VERSION_12 && type == IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN) ||
			(moq->version == IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_TOKEN_v11) ||
			(moq->version < IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_SUB_PARAM_AUTHORIZATION_INFO)) {
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
	} else if(((moq->version >= IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT) ||
			(moq->version < IMQUIC_MOQ_VERSION_11 && type == IMQUIC_MOQ_SUB_PARAM_DELIVERY_TIMEOUT_LEGACY)) && (moq->version >= IMQUIC_MOQ_VERSION_11 || len > 0)) {
		params->delivery_timeout = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ subscribe parameter");
		params->delivery_timeout_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->delivery_timeout);
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			len = length;
	} else if(type == IMQUIC_MOQ_SUB_PARAM_MAX_CACHE_DURATION && (moq->version >= IMQUIC_MOQ_VERSION_11 || len > 0)) {
		params->max_cache_duration = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, NULL, 0, 0, "Broken MoQ subscribe parameter");
		params->max_cache_duration_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), params->max_cache_duration);
		if(moq->version >= IMQUIC_MOQ_VERSION_11)
			len = length;
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter\n",
			imquic_get_connection_name(moq->conn));
		if(moq->version >= IMQUIC_MOQ_VERSION_11 && (type % 2 == 0))
			len = length;
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

/* Roles management */
int imquic_moq_set_role(imquic_connection *conn, imquic_moq_role role) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	imquic_mutex_lock(&moq->mutex);
	if(!moq->role_set) {
		imquic_mutex_unlock(&moq->mutex);
		return -1;
	}
	switch(role) {
		case IMQUIC_MOQ_ENDPOINT:
			moq->role_set = TRUE;
			moq->type = IMQUIC_MOQ_ROLE_ENDPOINT;
			break;
		case IMQUIC_MOQ_PUBLISHER:
			moq->role_set = TRUE;
			moq->type = IMQUIC_MOQ_ROLE_PUBLISHER;
			break;
		case IMQUIC_MOQ_SUBSCRIBER:
			moq->role_set = TRUE;
			moq->type = IMQUIC_MOQ_ROLE_SUBSCRIBER;
			break;
		case IMQUIC_MOQ_PUBSUB:
			moq->role_set = TRUE;
			moq->type = IMQUIC_MOQ_ROLE_PUBSUB;
			break;
		default:
			imquic_mutex_unlock(&moq->mutex);
			return -1;
	}
	/* Done */
	imquic_mutex_unlock(&moq->mutex);
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

imquic_moq_role imquic_moq_get_role(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	imquic_mutex_lock(&moq->mutex);
	if(!moq->role_set) {
		imquic_mutex_unlock(&moq->mutex);
		return -1;
	}
	imquic_moq_role role = -1;
	switch(moq->type) {
		case IMQUIC_MOQ_ROLE_ENDPOINT:
			role = IMQUIC_MOQ_ENDPOINT;
			break;
		case IMQUIC_MOQ_ROLE_PUBLISHER:
			role = IMQUIC_MOQ_PUBLISHER;
			break;
		case IMQUIC_MOQ_ROLE_SUBSCRIBER:
			role = IMQUIC_MOQ_SUBSCRIBER;
			break;
		case IMQUIC_MOQ_ROLE_PUBSUB:
			role = IMQUIC_MOQ_PUBSUB;
			break;
		default:
			break;
	}
	/* Done */
	imquic_mutex_unlock(&moq->mutex);
	imquic_refcount_decrease(&moq->ref);
	return role;
}

/* Version management */
int imquic_moq_set_version(imquic_connection *conn, imquic_moq_version version) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->version_set) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	imquic_mutex_lock(&moq->mutex);
	switch(version) {
		case IMQUIC_MOQ_VERSION_06:
		case IMQUIC_MOQ_VERSION_07:
		case IMQUIC_MOQ_VERSION_08:
		case IMQUIC_MOQ_VERSION_09:
		case IMQUIC_MOQ_VERSION_10:
		case IMQUIC_MOQ_VERSION_11:
		case IMQUIC_MOQ_VERSION_12:
		case IMQUIC_MOQ_VERSION_ANY:
		case IMQUIC_MOQ_VERSION_ANY_LEGACY:
			moq->version = version;
			break;
		default:
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Unsupported version '%"SCNu32"'\n",
				imquic_get_connection_name(conn), version);
			return -1;
	}
	if(!moq->role_set && moq->version >= IMQUIC_MOQ_VERSION_08) {
		moq->role_set = TRUE;
		moq->type = IMQUIC_MOQ_ROLE_ENDPOINT;
	}
	/* Done */
	imquic_mutex_unlock(&moq->mutex);
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

imquic_moq_version imquic_moq_get_version(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || !moq->version_set) {
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
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t ms_len = imquic_moq_add_max_request_id(moq, &buffer[poffset], blen-poffset, max_request_id);
		ms_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_MAX_REQUEST_ID, buffer, blen, poffset, ms_len, &start);
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
int imquic_moq_announce(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
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
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		/* Make sure we can send this */
		if(request_id < moq->next_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
				imquic_get_connection_name(conn), request_id, moq->next_request_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		if(request_id >= moq->max_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Reached the Maximum Request ID (%"SCNu64")\n",
				imquic_get_connection_name(conn), moq->max_request_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq->next_request_id = request_id + 2;
	}
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce(moq, &buffer[poffset], blen-poffset, request_id, tns, NULL);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_ANNOUNCE, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_announce(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (moq->version < IMQUIC_MOQ_VERSION_11 && (tns == NULL || tns->buffer == 0 || tns->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if the request ID exists */
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce_ok(moq, &buffer[poffset], blen-poffset, request_id, tns);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_ANNOUNCE_OK, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_announce(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_announce_error_code error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024) ||
			(moq->version < IMQUIC_MOQ_VERSION_11 && (tns == NULL || tns->buffer == 0 || tns->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if the request ID exists */
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce_error(moq, &buffer[poffset], blen-poffset, request_id, tns, error_code, reason);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_ANNOUNCE_ERROR, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unannounce(imquic_connection *conn, imquic_moq_namespace *tns) {
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
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_unannounce(moq, &buffer[poffset], blen-poffset, tns);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_UNANNOUNCE, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn, uint64_t track_alias,
		gboolean descending, imquic_moq_location *largest, gboolean forward, uint8_t *auth, size_t authlen) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
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
	/* Make sure we can send this */
	if(request_id < moq->next_request_id) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), request_id, moq->next_request_id);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	if(request_id >= moq->max_request_id) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Reached the Maximum Request ID (%"SCNu64")\n",
			imquic_get_connection_name(conn), moq->max_request_id);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	uint64_t request_id_increment = (imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
	moq->next_request_id = request_id + request_id_increment;
	/* Track this subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(request_id, track_alias);
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(request_id), moq_sub);
	g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(auth && authlen > 0) {
		parameters.auth_token_set = TRUE;
		if(authlen > sizeof(parameters.auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), authlen, sizeof(parameters.auth_token));
			authlen = sizeof(parameters.auth_token);
		}
		memcpy(parameters.auth_token, auth, authlen);
		parameters.auth_token_len = authlen;
	}
	sb_len = imquic_moq_add_publish(moq, &buffer[poffset], blen-poffset,
		request_id, tns, tn, track_alias,
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		(largest != NULL), (largest ? largest->group : 0), (largest ? largest->object : 0),	/* FIXME Should we validate the location? */
		forward, &parameters);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_PUBLISH, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_publish(imquic_connection *conn, uint64_t request_id, gboolean forward, uint8_t priority, gboolean descending,
		imquic_moq_filter_type filter_type, imquic_moq_location *start_location, imquic_moq_location *end_location) {
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
	if(moq->version < IMQUIC_MOQ_VERSION_12) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Publishing not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	gboolean content_exists = (start_location && end_location);
	if(content_exists && end_location->group > 0 && start_location->group > end_location->group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), end_location->group, start_location->group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	sb_len = imquic_moq_add_publish_ok(moq, &buffer[poffset], blen-poffset,
		request_id, forward, priority, descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		filter_type,
			(content_exists ? start_location->group : 0), (content_exists ? start_location->object : 0),
			(content_exists ? end_location->group : 0), (content_exists ? end_location->object : 0),
		NULL);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_PUBLISH_OK, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_error_code error_code, const char *reason) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_publish_error(moq, &buffer[poffset], blen-poffset, request_id, error_code, reason);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_PUBLISH_ERROR, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *tns, imquic_moq_name *tn, uint8_t priority, gboolean descending, gboolean forward,
		imquic_moq_filter_type filter_type, imquic_moq_location *start_location, imquic_moq_location *end_location, uint8_t *auth, size_t authlen) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	gboolean content_exists = (start_location && end_location);
	if(content_exists && end_location->group > 0 && start_location->group > end_location->group) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), end_location->group, start_location->group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* Make sure we can send this */
	if(request_id < moq->next_request_id) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), request_id, moq->next_request_id);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	if(request_id >= moq->max_request_id) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Reached the Maximum Request ID (%"SCNu64")\n",
			imquic_get_connection_name(conn), moq->max_request_id);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	uint64_t request_id_increment = (imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_11) ? 2 : 1;
	moq->next_request_id = request_id + request_id_increment;
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(auth && authlen > 0) {
		parameters.auth_token_set = TRUE;
		if(authlen > sizeof(parameters.auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), authlen, sizeof(parameters.auth_token));
			authlen = sizeof(parameters.auth_token);
		}
		memcpy(parameters.auth_token, auth, authlen);
		parameters.auth_token_len = authlen;
	}
	sb_len = imquic_moq_add_subscribe(moq, &buffer[poffset], blen-poffset,
		request_id, track_alias, tns, tn,
		priority, descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING, forward,
		filter_type,
			(content_exists ? start_location->group : 0), (content_exists ? start_location->object : 0),
			(content_exists ? end_location->group : 0), (content_exists ? end_location->object : 0),
		&parameters);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, uint64_t expires, gboolean descending, imquic_moq_location *largest) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_ok(moq, &buffer[poffset], blen-poffset,
		request_id, track_alias,
		expires,
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		(largest != NULL), (largest ? largest->group : 0), (largest ? largest->object : 0),	/* FIXME Should we validate the location? */
		NULL);	/* FIXME Parameters */
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_OK, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe(imquic_connection *conn, uint64_t request_id, imquic_moq_sub_error_code error_code, const char *reason, uint64_t track_alias) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_error(moq, &buffer[poffset], blen-poffset, request_id, error_code, reason, track_alias);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ERROR, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_update_subscribe(imquic_connection *conn, uint64_t request_id, imquic_moq_location *start_location, uint64_t end_group, uint8_t priority, gboolean forward) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || start_location == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO We should also ensure that we're not widening a subscription here */
	if(end_group > 0 && start_location->group > end_group) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] End group is lower than start location group (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), end_group, start_location->group);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t su_len = imquic_moq_add_subscribe_update(moq, &buffer[poffset], blen-poffset, request_id,
		start_location->group, start_location->object, end_group, 0, priority, forward,
		NULL);	/* TODO Parameters */
	su_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_UPDATE, buffer, blen, poffset, su_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, su_len, FALSE);
	moq->control_stream_offset += su_len;
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_unsubscribe(moq, &buffer[poffset], blen-poffset, request_id);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_UNSUBSCRIBE, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe_done(imquic_connection *conn, uint64_t request_id, imquic_moq_sub_done_code status_code, const char *reason) {
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
		imquic_mutex_unlock(&moq->mutex);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
			imquic_get_connection_name(conn), request_id);
		return -1;
	}
	uint64_t streams_count = moq_sub->streams_count;
	imquic_mutex_unlock(&moq->mutex);
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	/* TODO Compute streams count */
	size_t sd_len = imquic_moq_add_subscribe_done(moq, &buffer[poffset], blen-poffset,
		request_id, status_code, streams_count, reason, FALSE, 0, 0);
	sd_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_DONE, buffer, blen, poffset, sd_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sd_len, FALSE);
	moq->control_stream_offset += sd_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe_announces(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, uint8_t *auth, size_t authlen) {
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
	if(moq->version >= IMQUIC_MOQ_VERSION_11) {
		/* Make sure we can send this */
		if(request_id < moq->next_request_id) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Request ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
				imquic_get_connection_name(conn), request_id, moq->next_request_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		if(request_id >= moq->max_request_id) {
			/* TODO Whis should be a failure */
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Reached the Maximum Request ID (%"SCNu64")\n",
				imquic_get_connection_name(conn), moq->max_request_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		moq->next_request_id = request_id + 2;
	}
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(auth && authlen > 0) {
		parameters.auth_token_set = TRUE;
		if(authlen > sizeof(parameters.auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), authlen, sizeof(parameters.auth_token));
			authlen = sizeof(parameters.auth_token);
		}
		memcpy(parameters.auth_token, auth, authlen);
		parameters.auth_token_len = authlen;
	}
	sb_len = imquic_moq_add_subscribe_announces(moq, &buffer[poffset], blen-poffset, request_id, tns, &parameters);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe_announces(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (moq->version < IMQUIC_MOQ_VERSION_11 && (tns == NULL || tns->buffer == 0 || tns->length == 0))) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_announces_ok(moq, &buffer[poffset], blen-poffset, request_id, tns);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe_announces(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_subannc_error_code error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (reason && strlen(reason) > 1024) ||
			(moq->version < IMQUIC_MOQ_VERSION_11 && (tns == NULL || tns->buffer == 0 || tns->length == 0))) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_announces_error(moq, &buffer[poffset], blen-poffset, request_id, tns, error_code, reason);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unsubscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_unsubscribe_announces(moq, &buffer[poffset], blen-poffset, tns);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_standalone_fetch(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, gboolean descending, imquic_moq_fetch_range *range, uint8_t *auth, size_t authlen) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tn == NULL || range == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if this namespace exists and was announced here */
	/* TODO Track subscription and track alias */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(auth && authlen > 0) {
		parameters.auth_token_set = TRUE;
		if(authlen > sizeof(parameters.auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), authlen, sizeof(parameters.auth_token));
			authlen = sizeof(parameters.auth_token);
		}
		memcpy(parameters.auth_token, auth, authlen);
		parameters.auth_token_len = authlen;
	}
	/* FIXME WE should make start/end group/object configurable */
	f_len = imquic_moq_add_fetch(moq, &buffer[poffset], blen-poffset,
		IMQUIC_MOQ_FETCH_STANDALONE,
		request_id,
		0, 0,	/* Ignored, as they're only used for Joining Fetch */
		tns, tn,
		0,	/* TODO Priority */
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		range, &parameters);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_joining_fetch(imquic_connection *conn, uint64_t request_id, uint64_t joining_request_id,
		gboolean absolute, uint64_t joining_start, gboolean descending, uint8_t *auth, size_t authlen) {
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
	if(absolute && moq->version < IMQUIC_MOQ_VERSION_11) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Absolute Joining Fetch not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	/* TODO Check if this namespace exists and was announced here */
	/* TODO Track subscription and track alias */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = 0;
	imquic_moq_subscribe_parameters parameters = { 0 };
	if(auth && authlen > 0) {
		parameters.auth_token_set = TRUE;
		if(authlen > sizeof(parameters.auth_token)) {
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] Auth token too large (%zu > %zu), it will be truncated\n",
				imquic_get_connection_name(moq->conn), authlen, sizeof(parameters.auth_token));
			authlen = sizeof(parameters.auth_token);
		}
		memcpy(parameters.auth_token, auth, authlen);
		parameters.auth_token_len = authlen;
	}
	/* FIXME WE should make start/end group/object configurable */
	f_len = imquic_moq_add_fetch(moq, &buffer[poffset], blen-poffset,
		(absolute ? IMQUIC_MOQ_FETCH_JOINING_ABSOLUTE : IMQUIC_MOQ_FETCH_JOINING_RELATIVE),
		request_id, joining_request_id, joining_start,
		NULL, NULL,	/* Ignored, as namespaces/track are only used for Standalone Fetch */
		0,	/* TODO Priority */
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		NULL,	/* Ignored, as the fetch range is only used for Standalone Fetch */
		&parameters);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_fetch(imquic_connection *conn, uint64_t request_id, gboolean descending, imquic_moq_location *largest) {
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
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	/* TODO Make other properties configurable */
	size_t f_len = imquic_moq_add_fetch_ok(moq, &buffer[poffset], blen-poffset,
		request_id,
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,	/* FIXME Group order */
		0,	/* TODO End of track */
		largest->group,		/* Largest group */
		largest->object,	/* Largest Object */
		NULL);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_OK, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_fetch(imquic_connection *conn, uint64_t request_id, imquic_moq_fetch_error_code error_code, const char *reason) {
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = imquic_moq_add_fetch_error(moq, &buffer[poffset], blen-poffset, request_id, error_code, reason);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_ERROR, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = imquic_moq_add_fetch_cancel(moq, &buffer[poffset], blen-poffset, request_id);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_CANCEL, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_track_status_request(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tn == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Add support for parameters */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t t_len = imquic_moq_add_track_status_request(moq, &buffer[poffset], blen-poffset, request_id, tns, tn, NULL);
	t_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_TRACK_STATUS_REQUEST, buffer, blen, poffset, t_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, t_len, FALSE);
	moq->control_stream_offset += t_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_track_status(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_track_status_code status_code, imquic_moq_location *largest) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || (moq->version < IMQUIC_MOQ_VERSION_11 && (tns == NULL || tn == NULL))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Invalid arguments\n",
			imquic_get_connection_name(conn));
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Add support for parameters */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t t_len = imquic_moq_add_track_status(moq, &buffer[poffset], blen-poffset, request_id, tns, tn,
		status_code, (largest ? largest->group : 0), (largest ? largest->object : 0), NULL);
	t_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_TRACK_STATUS, buffer, blen, poffset, t_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, t_len, FALSE);
	moq->control_stream_offset += t_len;
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t r_len = imquic_moq_add_requests_blocked(moq, &buffer[poffset], blen-poffset, moq->max_request_id);
	r_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_REQUESTS_BLOCKED, buffer, blen, poffset, r_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, r_len, FALSE);
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
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t g_len = imquic_moq_add_goaway(moq, &buffer[poffset], blen-poffset, uri);
	g_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_GOAWAY, buffer, blen, poffset, g_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, g_len, FALSE);
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
		if(has_payload || moq->version < IMQUIC_MOQ_VERSION_08) {
			size_t dg_len = imquic_moq_add_object_datagram(moq, buffer, bufsize,
				object->request_id, object->track_alias, object->group_id, object->object_id, object->object_status,
				object->priority, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->moq)
				imquic_moq_qlog_object_datagram_created(conn->qlog, object);
#endif
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
		} else if(!has_payload && moq->version >= IMQUIC_MOQ_VERSION_08) {
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
			if(moq->version < IMQUIC_MOQ_VERSION_11) {
				moq_stream->type = IMQUIC_MOQ_SUBGROUP_HEADER_LEGACY;
			} else {
				/* TODO Change the type depending on whether extensions/subgroup will be set:
				 * since we don't have an API for that, for now we always set the type
				 * that will allow us to dynamically use them all. This also means we
				 * currently don't have a way to specify an End-of-Group flag */
				moq_stream->type = (moq->version == IMQUIC_MOQ_VERSION_11 ? IMQUIC_MOQ_SUBGROUP_HEADER_v11 : IMQUIC_MOQ_SUBGROUP_HEADER_EOG);
			}
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
				imquic_moq_qlog_subgroup_header_created(conn->qlog, moq_stream);
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
			shgo_len = imquic_moq_add_subgroup_header_object(moq, moq_stream, buffer, bufsize,
				object->object_id, object->object_status, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
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
	} else if(object->delivery == IMQUIC_MOQ_USE_TRACK && (valid_pkt || object->end_of_stream)) {
		/* Use STREAM_HEADER_TRACK */
		if(moq->version >= IMQUIC_MOQ_VERSION_07) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't send STREAM_HEADER_TRACK on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			g_free(buffer);
			return -1;
		}
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
			moq_stream->type = IMQUIC_MOQ_STREAM_HEADER_TRACK;
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			moq_sub->stream = moq_stream;
			moq_sub->streams_count++;
			imquic_mutex_unlock(&moq->mutex);
			/* Send a STREAM_HEADER_TRACK */
			size_t sht_len = imquic_moq_add_stream_header_track(moq, buffer, bufsize,
				object->request_id, object->track_alias, object->priority);
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, moq_stream->stream_offset, sht_len, FALSE);
			moq_stream->stream_offset += sht_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shto_len = 0;
		if(valid_pkt) {
			shto_len = imquic_moq_add_stream_header_track_object(moq, buffer, bufsize,
				object->group_id, object->object_id, object->object_status, object->payload, object->payload_len);
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shto_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP));
		moq_stream->stream_offset += shto_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq->subscriptions_by_id, &object->request_id);
			g_hash_table_remove(moq->subscriptions, &object->track_alias);
			imquic_mutex_unlock(&moq->mutex);
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_FETCH && (valid_pkt || object->end_of_stream)) {
		/* Use FETCH_HEADER */
		if(moq->version < IMQUIC_MOQ_VERSION_07) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't send FETCH_HEADER on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			g_free(buffer);
			return -1;
		}
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
				imquic_moq_qlog_fetch_header_created(conn->qlog, moq_stream);
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
			shto_len = imquic_moq_add_fetch_header_object(moq, buffer, bufsize,
				object->group_id, object->subgroup_id, object->object_id, object->priority,
				object->object_status, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
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
	if(parameters->role_set) {
		json_t *role = json_object();
		json_object_set_new(role, "name", json_string("role"));
		json_object_set_new(role, "value", json_integer(parameters->role));
		json_array_append_new(params, role);
	}
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
	if(parameters->unknown) {
		json_t *unknown = json_object();
		json_object_set_new(unknown, "name", json_string("unknown"));
		json_array_append_new(params, unknown);
	}
	json_object_set_new(message, name, params);
}

void imquic_qlog_moq_message_add_subscribe_parameters(json_t *message, imquic_moq_subscribe_parameters *parameters, const char *name) {
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
	if(parameters->unknown) {
		json_t *unknown = json_object();
		json_object_set_new(unknown, "name", json_string("unknown"));
		json_array_append_new(params, unknown);
	}
	json_object_set_new(message, name, params);
}

void imquic_moq_qlog_control_message_created(imquic_qlog *qlog, uint64_t stream_id, size_t length, json_t *message) {
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
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_control_message_parsed(imquic_qlog *qlog, uint64_t stream_id, size_t length, json_t *message) {
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_header_created(imquic_qlog *qlog, imquic_moq_stream *stream) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_header_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "track_alias", json_integer(stream->track_alias));
	json_object_set_new(data, "group_id", json_integer(stream->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(stream->subgroup_id));
	json_object_set_new(data, "publisher_priority", json_integer(stream->priority));
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_subgroup_header_parsed(imquic_qlog *qlog, imquic_moq_stream *stream) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:subgroup_header_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "track_alias", json_integer(stream->track_alias));
	json_object_set_new(data, "group_id", json_integer(stream->group_id));
	json_object_set_new(data, "subgroup_id", json_integer(stream->subgroup_id));
	json_object_set_new(data, "publisher_priority", json_integer(stream->priority));
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_header_created(imquic_qlog *qlog, imquic_moq_stream *stream) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_header_created");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "request_id", json_integer(stream->request_id));
	imquic_qlog_append_event(qlog, event);
}

void imquic_moq_qlog_fetch_header_parsed(imquic_qlog *qlog, imquic_moq_stream *stream) {
	if(qlog == NULL || stream == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("moqt:fetch_header_parsed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(stream->stream_id));
	json_object_set_new(data, "request_id", json_integer(stream->request_id));
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
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
	if(object->payload_len > 0)
		imquic_qlog_event_add_raw(data, "object_payload", object->payload, object->payload_len);
	imquic_qlog_append_event(qlog, event);
}

#endif
