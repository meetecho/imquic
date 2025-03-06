/*! \file   moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Media Over QUIC (MoQ) stack
 * \details Implementation of the Media Over QUIC (MoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) versions -03 and -04 of the protocol.
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
		/* FIXME Generate a CLIENT_SETUP */
		uint8_t parameters[100];
		size_t params_num = 0, params_size = sizeof(parameters), params_len = 0;
		if(moq->version < IMQUIC_MOQ_VERSION_08 || moq->version > IMQUIC_MOQ_VERSION_09) {
			params_num++;
			params_len += imquic_moq_parameter_add_int(moq, parameters, params_size,
				IMQUIC_MOQ_PARAM_ROLE, moq->type);
		}
		if(((moq->version >= IMQUIC_MOQ_VERSION_06 && moq->version <= IMQUIC_MOQ_VERSION_MAX) || moq->version == IMQUIC_MOQ_VERSION_ANY) &&
				moq->local_max_subscribe_id > 0) {
			params_num++;
			params_len += imquic_moq_parameter_add_int(moq, &parameters[params_len], params_size-params_len,
				IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID, moq->local_max_subscribe_id);
		}
		imquic_data data = {
			.buffer = parameters,
			.length = params_len
		};
		GList *versions = NULL;
		if(moq->version == IMQUIC_MOQ_VERSION_ANY) {
			/* Offer all newer supported versions */
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_10));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_09));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_08));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_07));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_06));
		} else if(moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY) {
			/* Offer all supported versions before -06 */
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_05));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_04));
			versions = g_list_append(versions, GUINT_TO_POINTER(IMQUIC_MOQ_VERSION_03));
		} else {
			/* Offer a specific version */
			versions = g_list_append(versions, GUINT_TO_POINTER(moq->version));
		}
		uint8_t buffer[200];
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t cs_len = imquic_moq_add_client_setup(moq, &buffer[poffset], blen-poffset, versions, params_num, &data);
		cs_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_CLIENT_SETUP, buffer, blen, poffset, cs_len, &start);
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
	if(moq->streams)
		g_hash_table_unref(moq->streams);
	if(moq->subscriptions)
		g_hash_table_unref(moq->subscriptions);
	if(moq->subscriptions_by_id)
		g_hash_table_unref(moq->subscriptions_by_id);
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
		case IMQUIC_MOQ_DUPLICATE_TRACK_ALIAS:
			return "Duplicate Track Alias";
		case IMQUIC_MOQ_PARAMETER_LENGTH_MISMATCH:
			return "Parameter Length Mismatch";
		case IMQUIC_MOQ_TOO_MANY_SUBSCRIBES:
			return "Too Many Subscribes";
		case IMQUIC_MOQ_GOAWAY_TIMEOUT:
			return "GOAWAY Timeout";
		case IMQUIC_MOQ_CONTROL_MESSAGE_TIMEOUT:
			return "Control Message Timeout";
		case IMQUIC_MOQ_DATA_STREAM_TIMEOUT:
			return "Data Stream Timeout";
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
			return "SUBSCRIBE_UNNAMESPACE";
		case IMQUIC_MOQ_MAX_SUBSCRIBE_ID:
			return "MAX_SUBSCRIBE_ID";
		case IMQUIC_MOQ_SUBSCRIBES_BLOCKED:
			return "SUBSCRIBES_BLOCKED";
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
		default: break;
	}
	return NULL;
}

const char *imquic_moq_data_message_type_str(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_06 && type == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06)
		return "STREAM_HEADER_TRACK";
	switch(type) {
		case IMQUIC_MOQ_OBJECT_STREAM:
			return "OBJECT_STREAM";
		case IMQUIC_MOQ_OBJECT_DATAGRAM:
			return "OBJECT_DATAGRAM";
		case IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS:
			return "OBJECT_DATAGRAM_STATUS";
		case IMQUIC_MOQ_STREAM_HEADER_TRACK:
			return "STREAM_HEADER_TRACK";
		case IMQUIC_MOQ_STREAM_HEADER_GROUP:
			return "STREAM_HEADER_GROUP";
		case IMQUIC_MOQ_SUBGROUP_HEADER:
			return "SUBGROUP_HEADER";
		case IMQUIC_MOQ_FETCH_HEADER:
			return "FETCH_HEADER";
		default: break;
	}
	return NULL;
}

imquic_moq_delivery imquic_moq_data_message_type_to_delivery(imquic_moq_data_message_type type, imquic_moq_version version) {
	if(version == IMQUIC_MOQ_VERSION_06 && type == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06)
		return IMQUIC_MOQ_USE_TRACK;
	switch(type) {
		case IMQUIC_MOQ_OBJECT_STREAM:
			return IMQUIC_MOQ_USE_STREAM;
		case IMQUIC_MOQ_OBJECT_DATAGRAM:
			return IMQUIC_MOQ_USE_DATAGRAM;
		case IMQUIC_MOQ_STREAM_HEADER_TRACK:
			return IMQUIC_MOQ_USE_TRACK;
		case IMQUIC_MOQ_STREAM_HEADER_GROUP:
			return IMQUIC_MOQ_USE_GROUP;
		case IMQUIC_MOQ_SUBGROUP_HEADER:
			return IMQUIC_MOQ_USE_SUBGROUP;
		case IMQUIC_MOQ_FETCH_HEADER:
			return IMQUIC_MOQ_USE_FETCH;
		default: break;
	}
	return -1;
}

const char *imquic_moq_setup_parameter_type_str(imquic_moq_setup_parameter_type type) {
	switch(type) {
		case IMQUIC_MOQ_PARAM_ROLE:
			return "ROLE";
		case IMQUIC_MOQ_PARAM_PATH:
			return "PATH";
		case IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID:
			return "MAX_SUBSCRIBE_ID";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_subscribe_parameter_type_str(imquic_moq_subscribe_parameter_type type) {
	switch(type) {
		case IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO:
			return "AUTHORIZATION_INFO";
		case IMQUIC_MOQ_PARAM_DELIVERY_TIMEOUT:
			return "DELIVERY_TIMEOUT";
		case IMQUIC_MOQ_PARAM_MAX_CACHE_DURATION:
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

const char *imquic_moq_location_mode_str(imquic_moq_location_mode mode) {
	switch(mode) {
		case IMQUIC_MOQ_LOCATION_NONE:
			return "None";
		case IMQUIC_MOQ_LOCATION_ABSOLUTE:
			return "Absolute";
		case IMQUIC_MOQ_LOCATION_RELATIVEPREVIOUS:
			return "RelativePrevious";
		case IMQUIC_MOQ_LOCATION_RELATIVENEXT:
			return "RelativeNext";
		default: break;
	}
	return NULL;
}

const char *imquic_moq_filter_type_str(imquic_moq_filter_type type) {
	switch(type) {
		case IMQUIC_MOQ_FILTER_LATEST_GROUP:
			return "LatestGroup";
		case IMQUIC_MOQ_FILTER_LATEST_OBJECT:
			return "LatestObject";
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
		case IMQUIC_MOQ_FETCH_JOINING:
			return "Joining Fetch";
		default: break;
	}
	return NULL;
}

/* Moq Buffer */
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

imquic_moq_subscription *imquic_moq_subscription_create(uint64_t subscribe_id, uint64_t track_alias) {
	imquic_moq_subscription *moq_sub = g_malloc(sizeof(imquic_moq_subscription));
	moq_sub->subscribe_id = subscribe_id;
	moq_sub->track_alias = track_alias;
	moq_sub->stream = NULL;
	moq_sub->streams_by_group = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	moq_sub->streams_by_subgroup = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_moq_stream_destroy);
	return moq_sub;
}

void imquic_moq_subscription_destroy(imquic_moq_subscription *moq_sub) {
	if(moq_sub != NULL) {
		if(moq_sub->stream != NULL)
			imquic_moq_stream_destroy(moq_sub->stream);
		g_hash_table_unref(moq_sub->streams_by_group);
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
#define IMQUIC_MOQ_CHECK_ERR(err, res, reason) \
	if(err) { \
		IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", reason); \
		return res; \
	}

int imquic_moq_parse_message(imquic_moq_context *moq, uint64_t stream_id, uint8_t *bytes, size_t blen, gboolean complete, gboolean datagram) {
	size_t offset = 0, parsed = 0, parsed_prev = 0;
	uint8_t tlen = 0, error = 0;
	/* If this is a datagram, it can only be OBJECT_DATAGRAM or OBJECT_DATAGRAM_STATUS */
	if(datagram) {
		imquic_moq_data_message_type dtype = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
		offset += tlen;
		if(dtype == IMQUIC_MOQ_OBJECT_DATAGRAM) {
			/* Parse this OBJECT_DATAGRAM message */
			parsed = imquic_moq_parse_object_datagram(moq, &bytes[offset], blen-offset, &error);
			IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
		} else if(moq->version >= IMQUIC_MOQ_VERSION_08 && dtype == IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS) {
			/* Parse this OBJECT_DATAGRAM_STATUS message */
			parsed = imquic_moq_parse_object_datagram_status(moq, &bytes[offset], blen-offset, &error);
			IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
		} else {
			/* TODO Handle failure */
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] MoQ message '%s' (%02x) is not allowed on datagrams\n",
				imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(dtype, moq->version), dtype);
			return -1;
		}
		/* Done */
		return 0;
	}
	/* Check if this is a media stream */
	imquic_moq_stream *moq_stream = g_hash_table_lookup(moq->streams, &stream_id);
	/* Iterate on all frames */
	while(moq_stream == NULL && blen-offset > 0) {
		/* If we're here, we're either on the control stream, or on a media stream waiting to know what it will be like */
		imquic_moq_message_type type = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_VERB, "[%s][MoQ][%zu] >> %s (%02x, %u)\n",
			imquic_get_connection_name(moq->conn), offset, imquic_moq_message_type_str(type), type, tlen);
		if(stream_id != moq->control_stream_id) {
			/* Not the control stream, make sure it's a supported message */
			imquic_moq_data_message_type dtype = (imquic_moq_data_message_type)type;
			if(dtype == IMQUIC_MOQ_STREAM_HEADER_TRACK ||
					(moq->version == IMQUIC_MOQ_VERSION_06 && dtype == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06) ||
					dtype == IMQUIC_MOQ_STREAM_HEADER_GROUP || dtype == IMQUIC_MOQ_SUBGROUP_HEADER ||
					dtype == IMQUIC_MOQ_OBJECT_STREAM || dtype == IMQUIC_MOQ_FETCH_HEADER) {
				/* Create a new MoQ stream and track it */
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Stream %"SCNu64" will be used for %s\n",
					imquic_get_connection_name(moq->conn), stream_id, imquic_moq_data_message_type_str(dtype, moq->version));
				moq_stream = g_malloc0(sizeof(imquic_moq_stream));
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
			if((moq->version >= IMQUIC_MOQ_VERSION_06 && moq->version <= IMQUIC_MOQ_VERSION_MAX) || moq->version == IMQUIC_MOQ_VERSION_ANY) {
				/* Versions later than 06 require a payload length before the payload */
				plen = imquic_read_varint(&bytes[offset], blen-offset, &tlen);
				IMQUIC_MOQ_CHECK_ERR(tlen == 0, -1, "Broken MoQ Message");
				offset += tlen;
				if(plen > blen-offset) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "Not enough data available to parse this message (%zu > %zu)\n",
						plen, blen-offset);
				}
			}
			if(type == IMQUIC_MOQ_CLIENT_SETUP) {
				/* Parse this CLIENT_SETUP message */
				parsed = imquic_moq_parse_client_setup(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SERVER_SETUP) {
				/* Parse this SERVER_SETUP message */
				parsed = imquic_moq_parse_server_setup(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_MAX_SUBSCRIBE_ID) {
				/* Parse this MAX_SUBSCRIBE_ID message */
				parsed = imquic_moq_parse_max_subscribe_id(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBES_BLOCKED) {
				/* Parse this SUBSCRIBES_BLOCKED message */
				parsed = imquic_moq_parse_subscribes_blocked(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_ANNOUNCE) {
				/* Parse this ANNOUNCE message */
				parsed = imquic_moq_parse_announce(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_ANNOUNCE_OK) {
				/* Parse this ANNOUNCE_OK message */
				parsed = imquic_moq_parse_announce_ok(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_ANNOUNCE_ERROR) {
				/* Parse this ANNOUNCE_ERROR message */
				parsed = imquic_moq_parse_announce_error(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_UNANNOUNCE) {
				/* Parse this UNANNOUNCE message */
				parsed = imquic_moq_parse_unannounce(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_ANNOUNCE_CANCEL) {
				/* Parse this ANNOUNCE_CANCEL message */
				parsed = imquic_moq_parse_announce_cancel(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE) {
				/* Parse this SUBSCRIBE message */
				parsed = imquic_moq_parse_subscribe(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_UPDATE) {
				/* Parse this SUBSCRIBE_UPDATE message */
				parsed = imquic_moq_parse_subscribe_update(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_OK) {
				/* Parse this SUBSCRIBE_OK message */
				parsed = imquic_moq_parse_subscribe_ok(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ERROR) {
				/* Parse this SUBSCRIBE_ERROR message */
				parsed = imquic_moq_parse_subscribe_error(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE) {
				/* Parse this UNSUBSCRIBE message */
				parsed = imquic_moq_parse_unsubscribe(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_DONE) {
				/* Parse this SUBSCRIBE_DONE message */
				parsed = imquic_moq_parse_subscribe_done(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES) {
				/* Parse this SUBSCRIBE_ANNOUNCES message */
				parsed = imquic_moq_parse_subscribe_announces(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK) {
				/* Parse this SUBSCRIBE_ANNOUNCES_OK message */
				parsed = imquic_moq_parse_subscribe_announces_ok(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR) {
				/* Parse this SUBSCRIBE_ANNOUNCES_ERROR message */
				parsed = imquic_moq_parse_subscribe_announces_error(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES) {
				/* Parse this UNSUBSCRIBE_ANNOUNCES message */
				parsed = imquic_moq_parse_unsubscribe_announces(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_FETCH) {
				/* Parse this FETCH message */
				parsed = imquic_moq_parse_fetch(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_FETCH_CANCEL) {
				/* Parse this FETCH_CANCEL message */
				parsed = imquic_moq_parse_fetch_cancel(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_FETCH_OK) {
				/* Parse this FETCH_OK message */
				parsed = imquic_moq_parse_fetch_ok(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_FETCH_ERROR) {
				/* Parse this FETCH_ERROR message */
				parsed = imquic_moq_parse_fetch_error(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_TRACK_STATUS_REQUEST) {
				/* Parse this TRACK_STATUS_REQUEST message */
				parsed = imquic_moq_parse_track_status_request(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_TRACK_STATUS) {
				/* Parse this TRACK_STATUS message */
				parsed = imquic_moq_parse_track_status_request(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if(type == IMQUIC_MOQ_GOAWAY) {
				/* Parse this GOAWAY message */
				parsed = imquic_moq_parse_goaway(moq, &bytes[offset], plen, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported message '%02x'\n",
					imquic_get_connection_name(moq->conn), type);
				return -1;
			}
		} else {
			/* Data message */
			if((imquic_moq_data_message_type)type == IMQUIC_MOQ_OBJECT_STREAM) {
				/* Parse this OBJECT_STREAM message */
				parsed = imquic_moq_parse_object_stream(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((imquic_moq_data_message_type)type == IMQUIC_MOQ_STREAM_HEADER_TRACK ||
					(moq->version == IMQUIC_MOQ_VERSION_06 && (imquic_moq_data_message_type)type == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06)) {
				/* Parse this STREAM_HEADER_TRACK message */
				parsed = imquic_moq_parse_stream_header_track(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((imquic_moq_data_message_type)type == IMQUIC_MOQ_STREAM_HEADER_GROUP) {
				/* Parse this STREAM_HEADER_GROUP message */
				parsed = imquic_moq_parse_stream_header_group(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((imquic_moq_data_message_type)type == IMQUIC_MOQ_SUBGROUP_HEADER) {
				/* Parse this SUBGROUP_HEADER message */
				parsed = imquic_moq_parse_subgroup_header(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
				offset += parsed;
			} else if((imquic_moq_data_message_type)type == IMQUIC_MOQ_FETCH_HEADER) {
				/* Parse this FETCH_HEADER message */
				parsed = imquic_moq_parse_fetch_header(moq, moq_stream, &bytes[offset], blen-offset, &error);
				IMQUIC_MOQ_CHECK_ERR(error, -1, "Broken MoQ Message");
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
	if(moq_stream != NULL && blen-offset > 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] MoQ media stream %"SCNu64" (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), stream_id, blen - offset);
		/* Copy the incoming data to the buffer, as we'll use that for parsing */
		imquic_moq_buffer_append(moq_stream->buffer, bytes + offset, blen - offset);
		while(moq_stream->buffer && moq_stream->buffer->length > 0) {
			/* Parse the object we're receiving on that stream */
			if(moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK ||
					(moq->version == IMQUIC_MOQ_VERSION_06 && moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06)) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_stream_header_track_object(moq, moq_stream, complete) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else if(moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_GROUP) {
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ][%zu] >> %s object\n",
					imquic_get_connection_name(moq->conn), offset, imquic_moq_data_message_type_str(moq_stream->type, moq->version));
				if(imquic_moq_parse_stream_header_group_object(moq, moq_stream, complete) < 0) {
					IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- Not enough data, trying again later\n",
						imquic_get_connection_name(moq->conn));
					break;
				}
			} else if(moq_stream->type == IMQUIC_MOQ_SUBGROUP_HEADER) {
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
			} else if(moq_stream->type == IMQUIC_MOQ_OBJECT_STREAM) {
				/* Nothing to do, just keep on adding to the buffer until the stream is complete */
				break;
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
		if(moq_stream->type == IMQUIC_MOQ_OBJECT_STREAM && moq_stream->buffer != NULL) {
			/* Notify the payload at the application layer */
			imquic_moq_object object = {
				.subscribe_id = moq_stream->subscribe_id,
				.track_alias = moq_stream->track_alias,
				.group_id = moq_stream->group_id,
				.subgroup_id = 0,
				.object_id = moq_stream->object_id,
				.object_status = moq_stream->object_status,
				.object_send_order = moq_stream->object_send_order,
				.priority = moq_stream->priority,
				.payload = moq_stream->buffer->bytes,
				.payload_len = moq_stream->buffer->length,
				.delivery = IMQUIC_MOQ_USE_STREAM,
				.end_of_stream = TRUE
			};
			if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
				moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
		} else if(!moq_stream->closed && (moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_GROUP ||
				moq_stream->type == IMQUIC_MOQ_SUBGROUP_HEADER ||
				moq_stream->type == IMQUIC_MOQ_FETCH_HEADER ||
				moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK ||
				(moq->version == IMQUIC_MOQ_VERSION_06 && moq_stream->type == IMQUIC_MOQ_STREAM_HEADER_TRACK_V06))) {
			/* FIXME Notify an empty payload to signal the end of the stream */
			imquic_moq_object object = {
				.subscribe_id = moq_stream->subscribe_id,
				.track_alias = 0,
				.group_id = moq_stream->group_id,
				.subgroup_id = moq_stream->subgroup_id,
				.object_id = IMQUIC_MOQ_NORMAL_OBJECT,
				.object_send_order = 0,
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

size_t imquic_moq_parse_client_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 5)
		return 0;
	if(moq && !moq->is_server) {
		/* TODO Got a CLIENT_SETUP but we're a client, do something about it */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Received a CLIENT_SETUP, but we're a client\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t supported_vers = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken CLIENT_SETUP");
	offset += length;
	uint64_t i = 0;
	uint64_t version = 0;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- %"SCNu64" supported versions:\n",
		imquic_get_connection_name(moq->conn), supported_vers);
	for(i = 0; i<supported_vers; i++) {
		version = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken CLIENT_SETUP");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
			imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
		if(!moq->version_set) {
			if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
				moq->version_set = TRUE;
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]   -- -- -- Selected version %"SCNu32"\n",
					imquic_get_connection_name(moq->conn), moq->version);
			} else if(((version >= IMQUIC_MOQ_VERSION_06 && version <= IMQUIC_MOQ_VERSION_MAX) && moq->version == IMQUIC_MOQ_VERSION_ANY) ||
					((version >= IMQUIC_MOQ_VERSION_MIN && version < IMQUIC_MOQ_VERSION_06) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY)) {
				moq->version = version;
				moq->version_set = TRUE;
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- Selected version %"SCNu32"\n",
					imquic_get_connection_name(moq->conn), moq->version);
			} else {
				/* Keep looking */
				version = 0;
			}
		}
		offset += length;
	}
	IMQUIC_MOQ_CHECK_ERR(version == 0, 0, "Unsupported version");
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(params > 0 && (length == 0 || length >= blen-offset), 0, "Broken CLIENT_SETUP");
	IMQUIC_MOQ_CHECK_ERR(params == 0 && (length == 0 || length > blen-offset), 0, "Broken CLIENT_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	imquic_moq_parsed_setup_parameter param = { 0 };
	for(i = 0; i<params; i++) {
		offset += imquic_moq_parse_setup_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken CLIENT_SETUP");
		if(param.type == IMQUIC_MOQ_PARAM_ROLE) {
			/* TODO Keep track of it and/or validate it */
		} else if(param.type == IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID && moq->version >= IMQUIC_MOQ_VERSION_06) {
			/* Update the value we have */
			moq->max_subscribe_id = param.value.max_subscribe_id;
		}
	}
	/* Generate a SERVER_SETUP to send back */
	if(moq) {
		uint8_t parameters[100];
		size_t params_num = 0, params_size = sizeof(parameters), params_len = 0;
		if(moq->version < IMQUIC_MOQ_VERSION_08) {
			params_num++;
			params_len += imquic_moq_parameter_add_int(moq, parameters, params_size,
				IMQUIC_MOQ_PARAM_ROLE, moq->type);
		}
		if(moq->version >= IMQUIC_MOQ_VERSION_06 && moq->local_max_subscribe_id > 0) {
			params_num++;
			params_len += imquic_moq_parameter_add_int(moq, &parameters[params_len], params_size-params_len,
				IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID, moq->local_max_subscribe_id);
		}
		imquic_data data = {
			.buffer = parameters,
			.length = params_len
		};
		uint8_t buffer[200];
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t ss_len = imquic_moq_add_server_setup(moq, &buffer[poffset], blen-offset,
			moq->version, params_num, &data);
		ss_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SERVER_SETUP, buffer, blen, poffset, ss_len, &start);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			&buffer[start], moq->control_stream_offset, ss_len, FALSE);
		moq->control_stream_offset += ss_len;
		imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
		g_atomic_int_set(&moq->connected, 1);
		/* Notify the application the session is ready */
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.moq_ready)
			moq->conn->socket->callbacks.moq.moq_ready(moq->conn);
	}
	/* Done */
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 5)
		return 0;
	/* FIXME Actually validate the response */
	size_t offset = 0;
	uint8_t length = 0;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Supported version:\n",
		imquic_get_connection_name(moq->conn));
	uint64_t version = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SERVER_SETUP");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64" (expected %"SCNu32" -- %"SCNu32")\n",
		imquic_get_connection_name(moq->conn), version, IMQUIC_MOQ_VERSION_MIN, IMQUIC_MOQ_VERSION_MAX);
	if(version == moq->version && moq->version <= IMQUIC_MOQ_VERSION_MAX) {
		moq->version_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
			imquic_get_connection_name(moq->conn), moq->version);
	} else if(((version >= IMQUIC_MOQ_VERSION_06 && version <= IMQUIC_MOQ_VERSION_MAX) && moq->version == IMQUIC_MOQ_VERSION_ANY) ||
			((version >= IMQUIC_MOQ_VERSION_MIN && version < IMQUIC_MOQ_VERSION_06) && moq->version == IMQUIC_MOQ_VERSION_ANY_LEGACY)) {
		moq->version = version;
		moq->version_set = TRUE;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Selected version %"SCNu32"\n",
			imquic_get_connection_name(moq->conn), moq->version);
	} else {
		IMQUIC_MOQ_CHECK_ERR(version == 0, 0, "Unsupported version");
	}
	offset += length;
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SERVER_SETUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	uint64_t i = 0;
	imquic_moq_parsed_setup_parameter param = { 0 };
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		offset += imquic_moq_parse_setup_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken SERVER_SETUP");
		if(param.type == IMQUIC_MOQ_PARAM_ROLE) {
			/* TODO Keep track of it and/or validate it */
		} else if(param.type == IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID && moq->version >= IMQUIC_MOQ_VERSION_06) {
			/* Update the value we have */
			moq->max_subscribe_id = param.value.max_subscribe_id;
		}
	}
	if(moq->max_subscribe_id == 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ] No Max Subscribe ID parameter received, setting it to 1\n",
			imquic_get_connection_name(moq->conn));
		moq->max_subscribe_id = 1;
	}
	/* Notify the application the session is ready */
	if(moq) {
		g_atomic_int_set(&moq->connected, 1);
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.moq_ready)
			moq->conn->socket->callbacks.moq.moq_ready(moq->conn);
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_max_subscribe_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken MAX_SUBSCRIBE_ID");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Maximum Subscribe ID %"SCNu64":\n",
		imquic_get_connection_name(moq->conn), max);
	/* Update the value we have, unless it's smaller */
	if(max < moq->max_subscribe_id) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Got a smaller Maximum Subscribe ID, ignoring\n",
			imquic_get_connection_name(moq->conn));
	} else {
		moq->max_subscribe_id = max;
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribes_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t max = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBES_BLOCKED");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Maximum Subscribe ID %"SCNu64":\n",
		imquic_get_connection_name(moq->conn), max);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribes_blocked)
		moq->conn->socket->callbacks.moq.subscribes_blocked(moq->conn, max);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken ANNOUNCE");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken ANNOUNCE");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE");
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
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken ANNOUNCE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	uint64_t i = 0;
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken ANNOUNCE");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken ANNOUNCE");
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_announce) {
		moq->conn->socket->callbacks.moq.incoming_announce(moq->conn, &tns[0]);
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_announce(moq->conn, &tns[0], 500, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_OK");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken ANNOUNCE_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken ANNOUNCE_OK");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken ANNOUNCE_OK");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_OK");
			offset += length;
			if(i == tns_num - 1) {
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken ANNOUNCE_OK");
			} else {
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE_OK");
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
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.announce_accepted)
		moq->conn->socket->callbacks.moq.announce_accepted(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_ERROR");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE_ERROR");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken ANNOUNCE_ERROR");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken ANNOUNCE_ERROR");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_ERROR");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE_ERROR");
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
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken ANNOUNCE_ERROR");
	offset += length;
	char reason[200], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, 0, "Broken ANNOUNCE_ERROR");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.announce_error)
		moq->conn->socket->callbacks.moq.announce_error(moq->conn, &tns[0], error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken UNANNOUNCE");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken UNANNOUNCE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken UNANNOUNCE");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken UNANNOUNCE");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken UNANNOUNCE");
			offset += length;
			if(i == tns_num - 1) {
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken UNANNOUNCE");
			} else {
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken UNANNOUNCE");
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
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unannounce)
		moq->conn->socket->callbacks.moq.incoming_unannounce(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_CANCEL");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken ANNOUNCE_CANCEL");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken ANNOUNCE_CANCEL");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken ANNOUNCE_CANCEL");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken ANNOUNCE_CANCEL");
			offset += length;
			if(i == tns_num - 1) {
				IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken ANNOUNCE_CANCEL");
			} else {
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken ANNOUNCE_CANCEL");
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
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_announce_cancel)
		moq->conn->socket->callbacks.moq.incoming_announce_cancel(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken SUBSCRIBE");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken SUBSCRIBE");
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
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, 0, "Broken SUBSCRIBE");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	if(tn_len > 0) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	}
	imquic_moq_name tn = {
		.length = tn_len,
		.buffer = tn_len ? &bytes[offset] : NULL
	};
	offset += tn_len;
	if(moq->version == IMQUIC_MOQ_VERSION_03) {
		/* FIXME v03 */
		imquic_moq_location_mode sg_mode = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- StartGroup (%s)\n",
			imquic_get_connection_name(moq->conn), imquic_moq_location_mode_str(sg_mode));
		if(sg_mode != IMQUIC_MOQ_LOCATION_NONE) {
			uint64_t sg_value = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), sg_value);
		}
		imquic_moq_location_mode so_mode = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- StartObject (%s)\n",
			imquic_get_connection_name(moq->conn), imquic_moq_location_mode_str(so_mode));
		if(so_mode != IMQUIC_MOQ_LOCATION_NONE) {
			uint64_t so_value = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), so_value);
		}
		imquic_moq_location_mode eg_mode = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- EndGroup (%s)\n",
			imquic_get_connection_name(moq->conn), imquic_moq_location_mode_str(eg_mode));
		if(eg_mode != IMQUIC_MOQ_LOCATION_NONE) {
			uint64_t eg_value = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), eg_value);
		}
		imquic_moq_location_mode eo_mode = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- EndObject (%s)\n",
			imquic_get_connection_name(moq->conn), imquic_moq_location_mode_str(eo_mode));
		if(eo_mode != IMQUIC_MOQ_LOCATION_NONE) {
			uint64_t eo_value = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), eo_value);
		}
	} else {
		/* FIXME v04 or v5 */
		if(moq->version >= IMQUIC_MOQ_VERSION_05) {
			uint8_t priority = bytes[offset];
			offset++;
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
				imquic_get_connection_name(moq->conn), priority);
			uint8_t group_order = bytes[offset];
			offset++;
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
				imquic_get_connection_name(moq->conn), group_order);
		}
		uint64_t filter = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Filter type: %s (%"SCNu64")\n",
			imquic_get_connection_name(moq->conn), imquic_moq_filter_type_str(filter), filter);
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_START || filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			uint64_t start_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), start_group);
			uint64_t start_object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), start_object);
		}
		if(filter == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			uint64_t end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), end_group);
			if(moq->version < IMQUIC_MOQ_VERSION_08) {
				uint64_t end_object = imquic_read_varint(&bytes[offset], blen-offset, &length);
				IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE");
				offset += length;
				IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
					imquic_get_connection_name(moq->conn), end_object);
			}
		}
	}
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	uint64_t i = 0;
	imquic_moq_auth_info auth = { 0 };
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken SUBSCRIBE");
		if(param.type == IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO && param.value.auth_info.length > 0 && auth.buffer == NULL) {
			auth.length = param.value.auth_info.length;
			auth.buffer = g_malloc(auth.length);
			memcpy(auth.buffer, param.value.auth_info.buffer, auth.length);
		}
	}
	/* Make sure this is in line with the expected subscribe ID */
	if(subscribe_id < moq->expected_subscribe_id) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Subscribe ID lower than the last we expected (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), subscribe_id, moq->expected_subscribe_id);
		uint8_t buffer[200];
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t sb_len = imquic_moq_add_subscribe_error(moq, &buffer[poffset], blen-poffset, subscribe_id, 400, "Subscribe ID lower than expected", track_alias);
		sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ERROR, buffer, blen, poffset, sb_len, &start);
		imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
			&buffer[start], moq->control_stream_offset, sb_len, FALSE);
		moq->control_stream_offset += sb_len;
		imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	} else {
		/* Check if this is allowed */
		moq->expected_subscribe_id = subscribe_id + 1;
		if(moq->version >= IMQUIC_MOQ_VERSION_06 && subscribe_id >= moq->local_max_subscribe_id) {
			/* TODO Limit exceeded, we should reject this subscription (but don't now */
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] The subscriber reached our Maximum Subscribe ID (%"SCNu64")\n",
				imquic_get_connection_name(moq->conn), moq->local_max_subscribe_id);
			//~ uint8_t buffer[200];
			//~ size_t blen = sizeof(buffer), poffset = 5, start = 0;
			//~ size_t sb_len = imquic_moq_add_subscribe_error(moq, &buffer[poffset], blen-poffset, subscribe_id, 400, "Maximum Subscribe ID exceeded", track_alias);
			//~ sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ERROR, buffer, blen, poffset, sb_len, &start);
			//~ imquic_connection_send_on_stream(moq->conn, moq->control_stream_id,
				//~ &buffer[start], moq->control_stream_offset, sb_len, FALSE);
			//~ moq->control_stream_offset += sb_len;
			//~ imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
		}
		/* Track this subscription */
		imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(subscribe_id, track_alias);
		imquic_mutex_lock(&moq->mutex);
		g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(subscribe_id), moq_sub);
		g_hash_table_insert(moq->subscriptions, imquic_dup_uint64(track_alias), moq_sub);
		imquic_mutex_unlock(&moq->mutex);
		/* Notify the application */
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe) {
			moq->conn->socket->callbacks.moq.incoming_subscribe(moq->conn, subscribe_id, track_alias, &tns[0], &tn, &auth);
		} else {
			/* FIXME No handler for this request, let's reject it ourselves */
			imquic_moq_reject_subscribe(moq->conn, subscribe_id, 500, "Not handled", track_alias);
		}
	}
	g_free(auth.buffer);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t start_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), start_group);
	uint64_t start_object = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), start_object);
	uint64_t end_group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_UPDATE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
		imquic_get_connection_name(moq->conn), end_group);
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		uint64_t end_object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_UPDATE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), end_object);
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		uint8_t priority = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
			imquic_get_connection_name(moq->conn), priority);
	}
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	uint64_t i = 0;
	imquic_moq_auth_info auth = { 0 };
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken SUBSCRIBE");
		if(param.type == IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO && param.value.auth_info.length > 0 && auth.buffer == NULL) {
			auth.length = param.value.auth_info.length;
			auth.buffer = g_malloc(auth.length);
			memcpy(auth.buffer, param.value.auth_info.buffer, auth.length);
		}
	}
	/* TODO Notify the application */
	//~ if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe_update)
		//~ moq->conn->socket->callbacks.moq.incoming_subscribe_update(moq->conn, subscribe_id, track_alias, &tns, &tn, &auth);
	g_free(auth.buffer);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t expires = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Expires: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), expires);
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_OK");
	uint8_t group_order = IMQUIC_MOQ_ORDERING_ASCENDING;
	if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		group_order = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_OK");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8" (%s)\n",
			imquic_get_connection_name(moq->conn), group_order, imquic_moq_group_order_str(group_order));
		if(group_order != IMQUIC_MOQ_ORDERING_ASCENDING && group_order != IMQUIC_MOQ_ORDERING_DESCENDING) {
			/* TODO This should be treated as an error */
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Invalid Group Order %02x\n",
				imquic_get_connection_name(moq->conn), group_order);
		}
	}
	uint8_t content_exists = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, 0, "Broken SUBSCRIBE_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), content_exists);
	if(content_exists > 0) {
		uint64_t lg_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), lg_id);
		uint64_t lo_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), lo_id);
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_OK");
		uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_OK");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
			imquic_get_connection_name(moq->conn), params);
		uint64_t i = 0;
		for(i = 0; i<params; i++) {
			/* TODO Take note of the parsed parameter */
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_OK");
			imquic_moq_parsed_subscribe_parameter param = { 0 };
			offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
			IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken SUBSCRIBE_OK");
		}
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_accepted)
		moq->conn->socket->callbacks.moq.subscribe_accepted(moq->conn, subscribe_id, expires, group_order == IMQUIC_MOQ_ORDERING_DESCENDING);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	char reason[200], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len >= blen-offset, 0, "Broken SUBSCRIBE_ERROR");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_ERROR");
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_error)
		moq->conn->socket->callbacks.moq.subscribe_error(moq->conn, subscribe_id, error_code, reason_str, track_alias);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken UNSUBSCRIBE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	/* Get rid of this subscription */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &subscribe_id);
	if(moq_sub != NULL) {
		g_hash_table_remove(moq->subscriptions, &moq_sub->track_alias);
		g_hash_table_remove(moq->subscriptions_by_id, &subscribe_id);
	}
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe(moq->conn, subscribe_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t streams_count = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_08) {
		uint64_t streams_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Streams Count: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), streams_count);
	}
	uint64_t status_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_done_code_str(status_code), status_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
	offset += length;
	char reason[200], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
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
		uint8_t content_exists = bytes[offset];
		offset++;
		IMQUIC_MOQ_CHECK_ERR(content_exists && blen-offset == 0, 0, "Broken SUBSCRIBE");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Content Exists: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), content_exists);
		if(content_exists > 0) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_DONE");
			uint64_t fg_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_DONE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Final Group ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), fg_id);
			uint64_t fo_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_DONE");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Final Object ID: %"SCNu64"\n",
				imquic_get_connection_name(moq->conn), fo_id);
		}
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_done)
		moq->conn->socket->callbacks.moq.subscribe_done(moq->conn, subscribe_id, status_code, streams_count, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	imquic_moq_auth_info auth = { 0 };
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_ANNOUNCES");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken SUBSCRIBE_ANNOUNCES");
		if(param.type == IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO && param.value.auth_info.length > 0 && auth.buffer == NULL) {
			auth.length = param.value.auth_info.length;
			auth.buffer = g_malloc(auth.length);
			memcpy(auth.buffer, param.value.auth_info.buffer, auth.length);
		}
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_subscribe_announces) {
		moq->conn->socket->callbacks.moq.incoming_subscribe_announces(moq->conn, &tns[0], &auth);
	} else {
		/* FIXME No handler for this request, let's reject it ourselves */
		imquic_moq_reject_subscribe_announces(moq->conn, &tns[0], 500, "Not handled");
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
		offset += length;
		if(i == tns_num - 1) {
			IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
		} else {
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_OK");
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
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_announces_accepted)
		moq->conn->socket->callbacks.moq.subscribe_announces_accepted(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[i].length = tns_len;
		tns[i].buffer = tns_len ? &bytes[offset] : NULL;
		tns[i].next = (i == tns_num - 1) ? NULL : (i < 31 ? &tns[i+1] : NULL);
		offset += tns_len;
	}
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
	offset += length;
	char reason[200], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, 0, "Broken SUBSCRIBE_ANNOUNCES_ERROR");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.subscribe_announces_error)
		moq->conn->socket->callbacks.moq.subscribe_announces_error(moq->conn, &tns[0], error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
	offset += length;
	/* Iterate on all namespaces */
	uint64_t i = 0;
	for(i = 0; i < tns_num; i++) {
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		offset += length;
		if(i == tns_num - 1) {
			IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
		} else {
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken UNSUBSCRIBE_ANNOUNCES");
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
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_unsubscribe_announces)
		moq->conn->socket->callbacks.moq.incoming_unsubscribe_announces(moq->conn, &tns[0]);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	imquic_moq_name tn = { 0 };
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken FETCH");
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
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, 0, "Broken FETCH");
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
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Subscriber Priority: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), priority);
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %s (%"SCNu8"))\n",
		imquic_get_connection_name(moq->conn), imquic_moq_group_order_str(group_order), group_order);
	imquic_moq_fetch_type type = IMQUIC_MOQ_FETCH_STANDALONE;
	imquic_moq_fetch_range range = { 0 };
	uint64_t joining_subscribe_id = 0, preceding_group_offset = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_08) {
		type = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		if(type == IMQUIC_MOQ_FETCH_STANDALONE) {
			uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			/* Iterate on all namespaces */
			uint64_t i = 0;
			for(i = 0; i < tns_num; i++) {
				IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH");
				uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
				IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
				offset += length;
				IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken FETCH");
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
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, 0, "Broken FETCH");
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
				imquic_get_connection_name(moq->conn), tn_len);
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
				imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
			tn.length = tn_len;
			tn.buffer = tn_len ? &bytes[offset] : NULL;
			offset += tn_len;
			range.start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), range.start.group);
			range.start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), range.start.object);
			range.end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), range.end.group);
			range.end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
				imquic_get_connection_name(moq->conn), range.end.object);
		} else if(type == IMQUIC_MOQ_FETCH_JOINING) {
			joining_subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
			preceding_group_offset = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
			offset += length;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Broken FETCH, invalid type '%d'\n",
				imquic_get_connection_name(moq->conn), type);
			return 0;
		}
	} else {
		range.start.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.start.group);
		range.start.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Start Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.start.object);
		range.end.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Group: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.end.group);
		range.end.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Object: %"SCNu64")\n",
			imquic_get_connection_name(moq->conn), range.end.object);
	}
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken FETCH");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	imquic_moq_auth_info auth = { 0 };
	uint64_t i = 0;
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken FETCH");
		if(param.type == IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO && param.value.auth_info.length > 0 && auth.buffer == NULL) {
			auth.length = param.value.auth_info.length;
			auth.buffer = g_malloc(auth.length);
			memcpy(auth.buffer, param.value.auth_info.buffer, auth.length);
		}
	}
	/* Track this fetch subscription */
	imquic_moq_subscription *moq_sub = imquic_moq_subscription_create(subscribe_id, 0);
	moq_sub->fetch = TRUE;
	imquic_mutex_lock(&moq->mutex);
	g_hash_table_insert(moq->subscriptions_by_id, imquic_dup_uint64(subscribe_id), moq_sub);
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->version < IMQUIC_MOQ_VERSION_08 || type == IMQUIC_MOQ_FETCH_STANDALONE) {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_standalone_fetch) {
			moq->conn->socket->callbacks.moq.incoming_standalone_fetch(moq->conn, subscribe_id, &tns[0], &tn, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), &range, &auth);
		} else {
			/* FIXME No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, subscribe_id, 500, "Not handled");
		}
	} else {
		if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_joining_fetch) {
			moq->conn->socket->callbacks.moq.incoming_joining_fetch(moq->conn, subscribe_id, joining_subscribe_id, preceding_group_offset, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), &auth);
		} else {
			/* FIXME No handler for this request, let's reject it ourselves */
			imquic_moq_reject_fetch(moq->conn, subscribe_id, 500, "Not handled");
		}
	}
	g_free(auth.buffer);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken FETCH_CANCEL");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	/* Get rid of this subscription */
	imquic_mutex_lock(&moq->mutex);
	imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &subscribe_id);
	if(moq_sub == NULL || !moq_sub->fetch) {
		/* FIXME Should we not bobble this up to the application? */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't cancel FETCH, subscribe ID %"SCNu64" is not a FETCH\n",
			imquic_get_connection_name(moq->conn), subscribe_id);
	} else {
		g_hash_table_remove(moq->subscriptions_by_id, &subscribe_id);
	}
	imquic_mutex_unlock(&moq->mutex);
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_fetch_cancel)
		moq->conn->socket->callbacks.moq.incoming_fetch_cancel(moq->conn, subscribe_id);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH_OK");
	uint8_t group_order = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- Group Order: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), group_order);
	uint8_t end_of_track = bytes[offset];
	offset++;
	IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH_OK");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- End Of Track: %"SCNu8")\n",
		imquic_get_connection_name(moq->conn), end_of_track);
	imquic_moq_position largest = { 0 };
	largest.group = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Group ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.group);
	largest.object = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Largest Object ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), largest.object);
	uint64_t params = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken FETCH_OK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- %"SCNu64" parameters:\n",
		imquic_get_connection_name(moq->conn), params);
	uint64_t i = 0;
	for(i = 0; i<params; i++) {
		/* TODO Take note of the parsed parameter */
		IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken FETCH_OK");
		imquic_moq_parsed_subscribe_parameter param = { 0 };
		offset += imquic_moq_parse_subscribe_parameter(moq, &bytes[offset], blen-offset, &param, error);
		IMQUIC_MOQ_CHECK_ERR(error && *error, 0, "Broken FETCH_OK");
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_accepted)
		moq->conn->socket->callbacks.moq.fetch_accepted(moq->conn, subscribe_id, (group_order == IMQUIC_MOQ_ORDERING_DESCENDING), &largest);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t error_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_ERROR");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Error Code: %s (%"SCNu64")\n",
		imquic_get_connection_name(moq->conn), imquic_moq_sub_error_code_str(error_code), error_code);
	uint64_t rs_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken FETCH_ERROR");
	offset += length;
	char reason[200], *reason_str = NULL;
	if(rs_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(rs_len > blen-offset, 0, "Broken FETCH_ERROR");
		int reason_len = (int)rs_len;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Reason Phrase: %.*s\n",
			imquic_get_connection_name(moq->conn), reason_len, &bytes[offset]);
		if(reason_len > 0) {
			g_snprintf(reason, sizeof(reason), "%.*s", reason_len, &bytes[offset]);
			reason_str = reason;
		}
		offset += reason_len;
	}
	/* Notify the application */
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.fetch_error)
		moq->conn->socket->callbacks.moq.fetch_error(moq->conn, subscribe_id, error_code, reason_str);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken TRACK_STATUS_REQUEST");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken TRACK_STATUS_REQUEST");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
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
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len > blen-offset, 0, "Broken TRACK_STATUS_REQUEST");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
		imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	//~ imquic_moq_name tn = {
		//~ .length = tn_len,
		//~ .buffer = tn_len ? &bytes[offset] : NULL
	//~ };
	offset += tn_len;
	//~ /* Notify the application */
	//~ if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status_request)
		//~ moq->conn->socket->callbacks.moq.incoming_track_status_request(moq->conn, &tns[0], &tn);
	//~ if(error)
		//~ *error = 0;
	return offset;
}

size_t imquic_moq_parse_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	memset(&tns, 0, sizeof(tns));
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS");
		offset += length;
		IMQUIC_MOQ_CHECK_ERR(tns_len > blen-offset, 0, "Broken TRACK_STATUS");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Namespace (%"SCNu64" bytes)\n",
			imquic_get_connection_name(moq->conn), tns_len);
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)tns_len, &bytes[offset]);
		tns[0].length = tns_len;
		tns[0].buffer = tns_len ? &bytes[offset] : NULL;
		tns[0].next = NULL;
		offset += tns_len;
	} else {
		/* Potentially multiple namespaces (tuple) */
		uint64_t tns_num = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset || tns_num > 32, 0, "Broken TRACK_STATUS");
		offset += length;
		/* Iterate on all namespaces */
		uint64_t i = 0;
		for(i = 0; i < tns_num; i++) {
			IMQUIC_MOQ_CHECK_ERR(blen-offset == 0, 0, "Broken TRACK_STATUS");
			uint64_t tns_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
			IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS");
			offset += length;
			IMQUIC_MOQ_CHECK_ERR(tns_len >= blen-offset, 0, "Broken TRACK_STATUS");
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
	uint64_t tn_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_MOQ_CHECK_ERR(tn_len >= blen-offset, 0, "Broken TRACK_STATUS");
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Name (%"SCNu64" bytes)\n",
		imquic_get_connection_name(moq->conn), tn_len);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %.*s\n",
		imquic_get_connection_name(moq->conn), (int)tn_len, &bytes[offset]);
	//~ imquic_moq_name tn = {
		//~ .length = tn_len,
		//~ .buffer = tn_len ? &bytes[offset] : NULL
	//~ };
	offset += tn_len;
	uint64_t status_code = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Status Code:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), status_code);
	uint64_t last_group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Last Group ID:  %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), last_group_id);
	uint64_t last_object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken TRACK_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Last Object ID: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), last_object_id);
	//~ /* Notify the application */
	//~ if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_track_status)
		//~ moq->conn->socket->callbacks.moq.incoming_track_status(moq->conn, &tns[0], &tn, status_code, last_group_id, last_object_id);
	//~ if(error)
		//~ *error = 0;
	return offset;
}

size_t imquic_moq_parse_object_stream(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 5)
		return 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_STREAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_STREAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_STREAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_STREAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint64_t object_send_order = 0;
	uint8_t priority = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		object_send_order = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken OBJECT_STREAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Send Order: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_send_order);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		priority = bytes[offset];
		offset++;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), priority);
	}
	uint64_t object_status = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_04) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken OBJECT_STREAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:     %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	}
	/* FIXME Track these properties */
	if(moq_stream != NULL) {
		moq_stream->subscribe_id = subscribe_id;
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->object_id = object_id;
		moq_stream->object_status = object_status;
		moq_stream->object_send_order = object_send_order;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
	}
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 5)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), subscribe_id);
	}
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint64_t object_send_order = 0;
	uint8_t priority = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		object_send_order = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Send Order: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_send_order);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		priority = bytes[offset];
		offset++;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), priority);
	}
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	if(moq->version > IMQUIC_MOQ_VERSION_08) {
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || ext_len >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
		offset += ext_len;
	} else if(moq->version == IMQUIC_MOQ_VERSION_08) {
		ext_count = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM");
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
	uint64_t object_status = 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_04) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "%s\n", "Broken OBJECT_DATAGRAM");
			return 0;
		}
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:     %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length:    %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), blen-offset);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.subscribe_id = subscribe_id,
		.track_alias = track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = object_send_order,
		.priority = priority,
		.payload = &bytes[offset],
		.payload_len = blen-offset,
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.extensions_count = ext_count,
		.delivery = IMQUIC_MOQ_USE_DATAGRAM,
		.end_of_stream = FALSE	/* No stream is involved here */
	};
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_object_datagram_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		return 0;
	if(bytes == NULL || blen < 5)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track Alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:         %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	uint8_t priority = priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	uint64_t object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
	offset += length;
	size_t ext_offset = 0, ext_len = 0;
	uint64_t ext_count = 0;
	if(moq->version > IMQUIC_MOQ_VERSION_08) {
		ext_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Extensions Length:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), ext_len);
		ext_offset = offset;
		IMQUIC_MOQ_CHECK_ERR(length == 0 || ext_len >= blen-offset, 0, "Broken OBJECT_DATAGRAM_STATUS");
		offset += ext_len;
	}
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:     %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_status);
	/* Notify this as an object at the application layer */
	imquic_moq_object object = {
		.subscribe_id = 0,
		.track_alias = track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = 0,
		.priority = priority,
		.payload = NULL,
		.payload_len = 0,
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.extensions_count = ext_count,
		.delivery = IMQUIC_MOQ_USE_DATAGRAM,
		.end_of_stream = FALSE	/* No stream is involved here */
	};
	if(moq->conn->socket && moq->conn->socket->callbacks.moq.incoming_object)
		moq->conn->socket->callbacks.moq.incoming_object(moq->conn, &object);
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_stream_header_track(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 3)
		return 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken STREAM_HEADER_TRACK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken STREAM_HEADER_TRACK");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t object_send_order = 0;
	uint8_t priority = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		object_send_order = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken OBJECT_STREAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Send Order: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_send_order);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		priority = bytes[offset];
		offset++;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), priority);
	}
	/* FIXME Track these properties */
	if(moq_stream != NULL) {
		moq_stream->subscribe_id = subscribe_id;
		moq_stream->track_alias = track_alias;
		moq_stream->object_send_order = object_send_order;
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
	if(p_len == 0 && moq->version >= IMQUIC_MOQ_VERSION_04) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
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
	if(p_len == 0 && moq->version >= IMQUIC_MOQ_VERSION_04)
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.subscribe_id = moq_stream->subscribe_id,
		.track_alias = moq_stream->track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = moq_stream->object_send_order,
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

size_t imquic_moq_parse_stream_header_group(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 4)
		return 0;
	if(moq->version >= IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken STREAM_HEADER_GROUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken STREAM_HEADER_GROUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken STREAM_HEADER_GROUP");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t object_send_order = 0;
	uint8_t priority = 0;
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		object_send_order = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken OBJECT_STREAM");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Send Order: %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_send_order);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		priority = bytes[offset];
		offset++;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
			imquic_get_connection_name(moq->conn), priority);
	}
	/* FIXME Track these properties */
	if(moq_stream != NULL) {
		moq_stream->subscribe_id = subscribe_id;
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->object_send_order = object_send_order;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_stream_header_group_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete) {
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	if(moq->version >= IMQUIC_MOQ_VERSION_06)
		return 0;
	uint8_t *bytes = moq_stream->buffer->bytes;
	size_t blen = moq_stream->buffer->length;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t object_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t p_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	if(length == 0 || length >= blen-offset)
		return -1;	/* Not enough data, try again later */
	offset += length;
	uint64_t object_status = 0;
	if(p_len == 0 && moq->version >= IMQUIC_MOQ_VERSION_04) {
		object_status = imquic_read_varint(&bytes[offset], blen-offset, &length);
		if(length == 0 || length > blen-offset)
			return -1;	/* Not enough data, try again later */
		offset += length;
	}
	if(p_len > blen-offset)
		return -1;	/* Not enough data, try again later */
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), object_id);
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Payload Length: %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), p_len);
	if(p_len == 0 && moq->version >= IMQUIC_MOQ_VERSION_04)
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Object Status:  %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), object_status);
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.subscribe_id = moq_stream->subscribe_id,
		.track_alias = moq_stream->track_alias,
		.group_id = moq_stream->group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = moq_stream->object_send_order,
		.priority = moq_stream->priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.extensions = NULL,
		.extensions_len = 0,
		.extensions_count = 0,
		.delivery = IMQUIC_MOQ_USE_GROUP,
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

size_t imquic_moq_parse_subgroup_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 4)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07) {
		subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBGROUP_HEADER");
		offset += length;
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), subscribe_id);
	}
	uint64_t track_alias = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Track alias:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), track_alias);
	uint64_t group_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Group ID:          %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), group_id);
	uint64_t subgroup_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken SUBGROUP_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subgroup ID:       %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subgroup_id);
	uint8_t priority = bytes[offset];
	offset++;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Publisher Priority: %"SCNu8"\n",
		imquic_get_connection_name(moq->conn), priority);
	/* FIXME Track these properties */
	if(moq_stream != NULL) {
		moq_stream->subscribe_id = subscribe_id;
		moq_stream->track_alias = track_alias;
		moq_stream->group_id = group_id;
		moq_stream->subgroup_id = subgroup_id;
		moq_stream->priority = priority;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
	}
	if(error)
		*error = 0;
	return offset;
}

int imquic_moq_parse_subgroup_header_object(imquic_moq_context *moq, imquic_moq_stream *moq_stream, gboolean complete) {
	if(moq_stream == NULL || moq_stream->buffer == NULL || moq_stream->buffer->bytes == NULL || moq_stream->buffer->length < 2)
		return -1;	/* Not enough data, try again later */
	if(moq->version < IMQUIC_MOQ_VERSION_06)
		return 0;
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
	/* Notify the payload at the application layer */
	imquic_moq_object object = {
		.subscribe_id = moq_stream->subscribe_id,
		.track_alias = moq_stream->track_alias,
		.group_id = moq_stream->group_id,
		.subgroup_id = moq_stream->subgroup_id,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = moq_stream->object_send_order,
		.priority = moq_stream->priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.extensions_count = ext_count,
		.delivery = IMQUIC_MOQ_USE_SUBGROUP,
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

size_t imquic_moq_parse_fetch_header(imquic_moq_context *moq, imquic_moq_stream *moq_stream, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken FETCH_HEADER");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- Subscribe ID:      %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), subscribe_id);
	/* FIXME Track these properties */
	if(moq_stream != NULL) {
		moq_stream->subscribe_id = subscribe_id;
		moq_stream->buffer = g_malloc0(sizeof(imquic_moq_buffer));
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
		.subscribe_id = moq_stream->subscribe_id,
		.track_alias = moq_stream->track_alias,
		.group_id = group_id,
		.subgroup_id = subgroup_id,
		.object_id = object_id,
		.object_status = object_status,
		.object_send_order = moq_stream->object_send_order,
		.priority = priority,
		.payload = bytes + offset,
		.payload_len = p_len,
		.extensions = &bytes[ext_offset],
		.extensions_len = ext_len,
		.extensions_count = ext_count,
		.delivery = IMQUIC_MOQ_USE_FETCH,
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

size_t imquic_moq_parse_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint8_t *error) {
	if(error)
		*error = 1;
	if(bytes == NULL || blen < 1)
		return 0;
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t uri_len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length > blen-offset, 0, "Broken GOAWAY");
	offset += length;
	char uri[1024], *uri_str = NULL;
	if(uri_len > 0) {
		IMQUIC_MOQ_CHECK_ERR(uri_len > blen-offset, 0, "Broken GOAWAY");
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
	if((moq->version >= IMQUIC_MOQ_VERSION_06 && moq->version <= IMQUIC_MOQ_VERSION_MAX) || moq->version == IMQUIC_MOQ_VERSION_ANY) {
		/* Starting from version -06, we need to add the payload length too */
		offset += imquic_write_varint(plen, &header[offset], hlen-offset);
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
		GList *supported_versions, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || g_list_length(supported_versions) < 1 ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
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
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_server_setup(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint32_t version, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SERVER_SETUP));
		return 0;
	}
	size_t offset = imquic_write_varint(version, bytes, blen);
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_max_subscribe_id(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_subscribe_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_MAX_SUBSCRIBE_ID));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_MAX_SUBSCRIBE_ID),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(max_subscribe_id, bytes, blen);
	return offset;
}

size_t imquic_moq_add_subscribes_blocked(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t max_subscribe_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBES_BLOCKED));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_08) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBES_BLOCKED),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(max_subscribe_id, bytes, blen);
	return offset;
}

size_t imquic_moq_add_announce(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_announce_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_OK));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_OK));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	return offset;
}

size_t imquic_moq_add_announce_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_announce_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_ERROR));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_ERROR));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	return offset;
}

size_t imquic_moq_add_unannounce(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNANNOUNCE));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNANNOUNCE));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	return offset;
}

size_t imquic_moq_add_announce_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_CANCEL));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_ANNOUNCE_CANCEL));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	return offset;
}

size_t imquic_moq_add_subscribe_v03(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, imquic_moq_location *start_group, imquic_moq_location *start_object,
		imquic_moq_location *end_group, imquic_moq_location *end_object, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			start_group == NULL || start_object == NULL || end_group == NULL || end_object == NULL ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	offset += imquic_write_varint(start_group->mode, &bytes[offset], blen-offset);
	if(start_group->mode != IMQUIC_MOQ_LOCATION_NONE) {
		offset += imquic_write_varint(start_group->value, &bytes[offset], blen-offset);
	}
	offset += imquic_write_varint(start_object->mode, &bytes[offset], blen-offset);
	if(start_object->mode != IMQUIC_MOQ_LOCATION_NONE) {
		offset += imquic_write_varint(start_object->value, &bytes[offset], blen-offset);
	}
	offset += imquic_write_varint(end_group->mode, &bytes[offset], blen-offset);
	if(end_group->mode != IMQUIC_MOQ_LOCATION_NONE) {
		offset += imquic_write_varint(end_group->value, &bytes[offset], blen-offset);
	}
	offset += imquic_write_varint(end_object->mode, &bytes[offset], blen-offset);
	if(end_object->mode != IMQUIC_MOQ_LOCATION_NONE) {
		offset += imquic_write_varint(end_object->value, &bytes[offset], blen-offset);
	}
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_subscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, uint8_t group_order, imquic_moq_filter_type filter,
		uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0) ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
		bytes[offset] = group_order;
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
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_subscribe_update(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
		uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, uint8_t priority,
		size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_UPDATE));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
	offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
	offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
	if(moq->version < IMQUIC_MOQ_VERSION_08)
		offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
	}
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_subscribe_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
		uint64_t expires, imquic_moq_group_order group_order, gboolean content_exists,
		uint64_t largest_group_id, uint64_t largest_object_id, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 ||
			(moq->version >= IMQUIC_MOQ_VERSION_06 && params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_OK));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(expires, &bytes[offset], blen-offset);
	if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = group_order;
		offset++;
	}
	bytes[offset] = content_exists;
	offset++;
	if(content_exists) {
		offset += imquic_write_varint(largest_group_id, &bytes[offset], blen-offset);
		offset += imquic_write_varint(largest_object_id, &bytes[offset], blen-offset);
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06) {
		offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
		if(params_num > 0) {
			memcpy(&bytes[offset], parameters->buffer, parameters->length);
			offset += parameters->length;
		}
	}
	return offset;
}

size_t imquic_moq_add_subscribe_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t subscribe_id, imquic_moq_sub_error_code error, const char *reason, uint64_t track_alias) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ERROR));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_unsubscribe(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	return offset;
}

size_t imquic_moq_add_subscribe_done(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
		imquic_moq_sub_done_code status, uint64_t streams_count, const char *reason, gboolean content_exists, uint64_t final_group, uint64_t final_object) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_DONE));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
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
	return offset;
}

size_t imquic_moq_add_subscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
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
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_subscribe_announces_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
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
	return offset;
}

size_t imquic_moq_add_subscribe_announces_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_subannc_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_ERROR),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
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
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	return offset;
}

size_t imquic_moq_add_unsubscribe_announces(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_namespace *track_namespace) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_UNSUBSCRIBE_ANNOUNCES),
			imquic_moq_version_str(moq->version));
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
	return offset;
}

size_t imquic_moq_add_fetch(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_moq_fetch_type type,
		uint64_t subscribe_id, uint64_t joining_subscribe_id, uint64_t preceding_group_offset,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint8_t priority, imquic_moq_group_order group_order,
		uint64_t start_group, uint64_t start_object, uint64_t end_group, uint64_t end_object, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 || (params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
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
	if(moq->version >= IMQUIC_MOQ_VERSION_08 && type != IMQUIC_MOQ_FETCH_STANDALONE && type != IMQUIC_MOQ_FETCH_JOINING) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_FETCH));
		return 0;
	}
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
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
			offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
			offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
			offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
		} else {
			offset += imquic_write_varint(joining_subscribe_id, &bytes[offset], blen-offset);
			offset += imquic_write_varint(preceding_group_offset, &bytes[offset], blen-offset);
		}
	} else {
		offset += imquic_write_varint(start_group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(start_object, &bytes[offset], blen-offset);
		offset += imquic_write_varint(end_group, &bytes[offset], blen-offset);
		offset += imquic_write_varint(end_object, &bytes[offset], blen-offset);
	}
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_fetch_cancel(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id) {
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
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	return offset;
}

size_t imquic_moq_add_fetch_ok(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint8_t group_order,
		uint8_t end_of_track, uint64_t largest_group_id, uint64_t largest_object_id, size_t params_num, imquic_data *parameters) {
	if(bytes == NULL || blen < 1 ||
			(params_num > 0 && (parameters == NULL || parameters->buffer == NULL || parameters->length == 0))) {
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
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	bytes[offset] = group_order;
	offset++;
	bytes[offset] = end_of_track;
	offset++;
	offset += imquic_write_varint(largest_group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(largest_object_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(params_num, &bytes[offset], blen-offset);
	if(params_num > 0) {
		memcpy(&bytes[offset], parameters->buffer, parameters->length);
		offset += parameters->length;
	}
	return offset;
}

size_t imquic_moq_add_fetch_error(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t subscribe_id, imquic_moq_fetch_error_code error, const char *reason) {
	if(bytes == NULL || blen < 1) {
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
	size_t offset = imquic_write_varint(subscribe_id, bytes, blen);
	offset += imquic_write_varint(error, &bytes[offset], blen-offset);
	size_t reason_len = reason ? strlen(reason) : 0;
	offset += imquic_write_varint(reason_len, &bytes[offset], blen-offset);
	if(reason_len > 0) {
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
	return offset;
}

size_t imquic_moq_add_track_status_request(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL ||
			track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS_REQUEST));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
	} else {
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	return offset;
}

size_t imquic_moq_add_track_status(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_namespace *track_namespace, imquic_moq_name *track_name, uint64_t status_code, uint64_t last_group_id, uint64_t last_object_id) {
	if(bytes == NULL || blen < 1 || track_namespace == NULL || track_name == NULL || (track_name->buffer == NULL && track_name->length > 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS));
		return 0;
	}
	size_t offset = 0;
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		/* Single namespace, no tuple */
		if(track_namespace->length > 0 && track_namespace->buffer == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
				imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_TRACK_STATUS));
			return 0;
		}
		offset += imquic_write_varint(track_namespace->length, &bytes[offset], blen-offset);
		if(track_namespace->length > 0) {
			memcpy(&bytes[offset], track_namespace->buffer, track_namespace->length);
			offset += track_namespace->length;
		}
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
		if(tns_num > 32) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: too many tuples\n",
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
	}
	offset += imquic_write_varint(track_name->length, &bytes[offset], blen-offset);
	if(track_name->length > 0) {
		memcpy(&bytes[offset], track_name->buffer, track_name->length);
		offset += track_name->length;
	}
	offset += imquic_write_varint(status_code, &bytes[offset], blen-offset);
	offset += imquic_write_varint(last_group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(last_object_id, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_object_stream(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint64_t object_send_order, uint8_t priority, uint8_t *payload, size_t plen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_OBJECT_STREAM, moq->version));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_OBJECT_STREAM, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_OBJECT_STREAM, bytes, blen);
	offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		offset += imquic_write_varint(object_send_order, &bytes[offset], blen-offset);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_04)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	if(payload != NULL && plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_object_datagram(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id, uint64_t track_alias,
		uint64_t group_id, uint64_t object_id, uint64_t object_status, uint64_t object_send_order, uint8_t priority,
		uint8_t *payload, size_t plen, size_t extensions_count, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM, moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_OBJECT_DATAGRAM, bytes, blen);
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		offset += imquic_write_varint(object_send_order, &bytes[offset], blen-offset);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_08)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, extensions_count, extensions, elen);
	if(moq->version >= IMQUIC_MOQ_VERSION_04)
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
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_OBJECT_DATAGRAM_STATUS, bytes, blen);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	if(moq->version >= IMQUIC_MOQ_VERSION_08)
		offset += imquic_moq_add_object_extensions(moq, &bytes[offset], blen-offset, 0, extensions, elen);
	offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	return offset;
}

size_t imquic_moq_add_stream_header_track(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t subscribe_id, uint64_t track_alias, uint64_t object_send_order, uint8_t priority) {
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
	size_t offset = imquic_write_varint(moq->version < IMQUIC_MOQ_VERSION_06 ?
		IMQUIC_MOQ_STREAM_HEADER_TRACK : IMQUIC_MOQ_STREAM_HEADER_TRACK_V06, bytes, blen);
	offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		offset += imquic_write_varint(object_send_order, &bytes[offset], blen-offset);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
	}
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
	if(plen == 0 && moq->version >= IMQUIC_MOQ_VERSION_04)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	if(plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_stream_header_group(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
		uint64_t track_alias, uint64_t group_id, uint64_t object_send_order, uint8_t priority) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_GROUP, moq->version));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_GROUP, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_STREAM_HEADER_GROUP, bytes, blen);
	offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	if(moq->version == IMQUIC_MOQ_VERSION_03 || moq->version == IMQUIC_MOQ_VERSION_04) {
		offset += imquic_write_varint(object_send_order, &bytes[offset], blen-offset);
	} else if(moq->version >= IMQUIC_MOQ_VERSION_05) {
		bytes[offset] = priority;
		offset++;
	}
	return offset;
}

size_t imquic_moq_add_stream_header_group_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_GROUP, moq->version));
		return 0;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s object on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_STREAM_HEADER_GROUP, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
	if(payload == NULL)
		plen = 0;
	offset += imquic_write_varint(plen, &bytes[offset], blen-offset);
	if(plen == 0 && moq->version >= IMQUIC_MOQ_VERSION_04)
		offset += imquic_write_varint(object_status, &bytes[offset], blen-offset);
	if(plen > 0) {
		memcpy(&bytes[offset], payload, plen);
		offset += plen;
	}
	return offset;
}

size_t imquic_moq_add_subgroup_header(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id,
		uint64_t track_alias, uint64_t group_id, uint64_t subgroup_id, uint8_t priority) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = imquic_write_varint(IMQUIC_MOQ_SUBGROUP_HEADER, bytes, blen);
	if(moq->version < IMQUIC_MOQ_VERSION_07)
		offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(track_alias, &bytes[offset], blen-offset);
	offset += imquic_write_varint(group_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(subgroup_id, &bytes[offset], blen-offset);
	bytes[offset] = priority;
	offset++;
	return offset;
}

size_t imquic_moq_add_subgroup_header_object(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		uint64_t object_id, uint64_t object_status, uint8_t *payload, size_t plen,
		size_t extensions_count, uint8_t *extensions, size_t elen) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s object: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version));
		return 0;
	}
	if(moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send %s on a connection using %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_data_message_type_str(IMQUIC_MOQ_SUBGROUP_HEADER, moq->version),
			imquic_moq_version_str(moq->version));
		return 0;
	}
	size_t offset = 0;
	offset += imquic_write_varint(object_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_fetch_header(imquic_moq_context *moq, uint8_t *bytes, size_t blen, uint64_t subscribe_id) {
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
	offset += imquic_write_varint(subscribe_id, &bytes[offset], blen-offset);
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

size_t imquic_moq_add_goaway(imquic_moq_context *moq, uint8_t *bytes, size_t blen, imquic_data *new_session_uri) {
	if(bytes == NULL || blen < 1) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ %s: invalid arguments\n",
			imquic_get_connection_name(moq->conn), imquic_moq_message_type_str(IMQUIC_MOQ_GOAWAY));
		return 0;
	}
	size_t uri_len = (new_session_uri && new_session_uri->buffer) ? new_session_uri->length : 0;
	size_t offset = imquic_write_varint(uri_len, bytes, blen);
	if(uri_len > 0) {
		memcpy(&bytes[offset], new_session_uri->buffer, uri_len);
		offset += uri_len;
	}
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

/* Parameters parsing */
size_t imquic_moq_parse_setup_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_parsed_setup_parameter *param, uint8_t *error) {
	if(error)
		*error = 1;
	if(param) {
		memset(param, 0, sizeof(*param));
		param->type = 0xFF;
	}
	if(bytes == NULL || blen < 2) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ setup parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken MoQ setup parameter");
	offset += length;
	uint64_t len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken MoQ setup parameter");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64"), length %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), imquic_moq_setup_parameter_type_str(type), type, len);
	IMQUIC_MOQ_CHECK_ERR(len == 0 || len > blen-offset, 0, "Broken MoQ setup parameter");
	/* Update the parsed parameter */
	param->type = type;
	if(type == IMQUIC_MOQ_PARAM_ROLE) {
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %s\n",
			imquic_get_connection_name(moq->conn), imquic_moq_role_type_str(bytes[offset]));
		param->value.role = bytes[offset];
	} else if(type == IMQUIC_MOQ_PARAM_PATH) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] PATH setup parameter not supported yet\n",
			imquic_get_connection_name(moq->conn));
		param->value.path = NULL;
	} else if(type == IMQUIC_MOQ_PARAM_MAX_SUBSCRIBE_ID) {
		param->value.max_subscribe_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0 || len > blen-offset, 0, "Broken MoQ setup parameter");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), param->value.max_subscribe_id);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter '%d'\n",
			imquic_get_connection_name(moq->conn), param->type);
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

size_t imquic_moq_parse_subscribe_parameter(imquic_moq_context *moq, uint8_t *bytes, size_t blen,
		imquic_moq_parsed_subscribe_parameter *param, uint8_t *error) {
	if(error)
		*error = 1;
	if(param) {
		memset(param, 0, sizeof(*param));
		param->type = 0xFF;
	}
	if(bytes == NULL || blen < 2) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't parse MoQ subscribe parameter: not enough data (%zu bytes)\n",
			imquic_get_connection_name(moq->conn), bytes ? blen : 0);
		return 0;
	}
	size_t offset = 0;
	uint8_t length = 0;
	uint64_t type = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken MoQ subscribe parameter");
	offset += length;
	uint64_t len = imquic_read_varint(&bytes[offset], blen-offset, &length);
	IMQUIC_MOQ_CHECK_ERR(length == 0 || length >= blen-offset, 0, "Broken MoQ subscribe parameter");
	offset += length;
	IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- %s (%"SCNu64"), length %"SCNu64"\n",
		imquic_get_connection_name(moq->conn), imquic_moq_subscribe_parameter_type_str(type), type, len);
	IMQUIC_MOQ_CHECK_ERR(len == 0 || len > blen-offset, 0, "Broken MoQ subscribe parameter");
	/* Update the parsed parameter */
	param->type = type;
	if(type == IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO) {
		param->value.auth_info.length = len;
		param->value.auth_info.buffer = &bytes[offset];
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %.*s\n",
			imquic_get_connection_name(moq->conn), (int)param->value.auth_info.length, param->value.auth_info.buffer);
	} else if(type == IMQUIC_MOQ_PARAM_DELIVERY_TIMEOUT) {
		param->value.delivery_timeout = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, 0, "Broken MoQ subscribe parameter");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), param->value.delivery_timeout);
	} else if(type == IMQUIC_MOQ_PARAM_MAX_CACHE_DURATION) {
		param->value.max_cache_duration = imquic_read_varint(&bytes[offset], blen-offset, &length);
		IMQUIC_MOQ_CHECK_ERR(length == 0, 0, "Broken MoQ subscribe parameter");
		IMQUIC_LOG(IMQUIC_MOQ_LOG_HUGE, "[%s][MoQ]  -- -- -- %"SCNu64"\n",
			imquic_get_connection_name(moq->conn), param->value.max_cache_duration);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Unsupported parameter\n",
			imquic_get_connection_name(moq->conn));
	}
	offset += len;
	if(error)
		*error = 0;
	return offset;
}

/* Adding parameters to a buffer */
size_t imquic_moq_parameter_add_int(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint64_t number) {
	if(bytes == NULL || blen == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ numeric parameter: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
		return 0;
	}
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
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
	return offset;
}

size_t imquic_moq_parameter_add_data(imquic_moq_context *moq, uint8_t *bytes, size_t blen, int param, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0 || (buflen > 0 && buf == 0)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Can't add MoQ data parameter: invalid arguments\n",
			imquic_get_connection_name(moq->conn));
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

/* Roles management */
int imquic_moq_set_role(imquic_connection *conn, imquic_moq_role role) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->role_set) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
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
			return -1;
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

imquic_moq_role imquic_moq_get_role(imquic_connection *conn) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || !moq->role_set) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
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
	switch(version) {
		case IMQUIC_MOQ_VERSION_03:
		case IMQUIC_MOQ_VERSION_04:
		case IMQUIC_MOQ_VERSION_05:
		case IMQUIC_MOQ_VERSION_06:
		case IMQUIC_MOQ_VERSION_07:
		case IMQUIC_MOQ_VERSION_08:
		case IMQUIC_MOQ_VERSION_09:
		case IMQUIC_MOQ_VERSION_10:
		case IMQUIC_MOQ_VERSION_ANY:
		case IMQUIC_MOQ_VERSION_ANY_LEGACY:
			moq->version = version;
			break;
		default:
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][MoQ] Unsupported version '%"SCNu32"'\n",
				imquic_get_connection_name(conn), version);
			return -1;
	}
	if(!moq->role_set && moq->version >= IMQUIC_MOQ_VERSION_08 && moq->version != IMQUIC_MOQ_VERSION_ANY_LEGACY) {
		moq->role_set = TRUE;
		moq->type = IMQUIC_MOQ_ROLE_ENDPOINT;
	}
	/* Done */
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
	imquic_moq_version version = moq->version;
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return version;
}

/* Maximum Subscribe ID management */
int imquic_moq_set_max_subscribe_id(imquic_connection *conn, uint64_t max_subscribe_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->local_max_subscribe_id >= max_subscribe_id) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	if(moq->version != IMQUIC_MOQ_VERSION_ANY && moq->version < IMQUIC_MOQ_VERSION_06) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Maximum Subscribe ID not supported on a connection using %s\n",
			imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	moq->local_max_subscribe_id = max_subscribe_id;
	if(g_atomic_int_get(&moq->connected)) {
		/* Already connected, send a MAX_SUBSCRIBE_ID */
		uint8_t buffer[20];
		size_t blen = sizeof(buffer), poffset = 5, start = 0;
		size_t ms_len = imquic_moq_add_max_subscribe_id(moq, &buffer[poffset], blen-poffset, moq->local_max_subscribe_id);
		ms_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_MAX_SUBSCRIBE_ID, buffer, blen, poffset, ms_len, &start);
		imquic_connection_send_on_stream(conn, moq->control_stream_id,
			buffer, moq->control_stream_offset, ms_len, FALSE);
		moq->control_stream_offset += ms_len;
		imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;

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

/* Namespaces and subscriptions */
int imquic_moq_announce(imquic_connection *conn, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce(moq, &buffer[poffset], blen-poffset, tns, 0, NULL);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_ANNOUNCE, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_announce(imquic_connection *conn, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_PUBLISHER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce_ok(moq, &buffer[poffset], blen-poffset, tns);
	ann_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_ANNOUNCE_OK, buffer, blen, poffset, ann_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, ann_len, FALSE);
	moq->control_stream_offset += ann_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_announce(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_PUBLISHER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if this namespace exists and was announced here */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t ann_len = imquic_moq_add_announce_error(moq, &buffer[poffset], blen-poffset, tns, error_code, reason);
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
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
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

int imquic_moq_subscribe(imquic_connection *conn, uint64_t subscribe_id,
		uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 ||
			tn == NULL || (tn->buffer == NULL && tn->length > 0) || moq->type == IMQUIC_MOQ_ROLE_PUBLISHER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Make sure we can send this */
	if(subscribe_id < moq->next_subscribe_id) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Subscribe ID lower than the next we expected (%"SCNu64" < %"SCNu64")\n",
			imquic_get_connection_name(conn), subscribe_id, moq->next_subscribe_id);
		imquic_refcount_decrease(&moq->ref);
		return -1;
	}
	if(moq->version >= IMQUIC_MOQ_VERSION_06 && subscribe_id >= moq->max_subscribe_id) {
		/* TODO Whis should be a failure */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Reached the Maximum Subscribe ID (%"SCNu64")\n",
			imquic_get_connection_name(conn), moq->max_subscribe_id);
		//~ imquic_refcount_decrease(&moq->ref);
		//~ return -1;
	}
	moq->next_subscribe_id = subscribe_id + 1;
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	uint8_t parameters[100];
	uint8_t num_params = 0;
	imquic_data params = {
		.buffer = parameters,
		.length = 0
	};
	if(auth && auth->buffer && auth->length > 0) {
		params.length = imquic_moq_parameter_add_data(moq, parameters, sizeof(parameters),
			IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO, auth->buffer, auth->length);
		num_params = 1;
	}
	if(moq->version == IMQUIC_MOQ_VERSION_03) {
		/* FIXME WE should make locations configurable */
		imquic_moq_location sg = {
			.mode = IMQUIC_MOQ_LOCATION_RELATIVEPREVIOUS,
			.value = 0
		};
		imquic_moq_location so = {
			.mode = IMQUIC_MOQ_LOCATION_ABSOLUTE,
			.value = 0
		};
		imquic_moq_location e = {
			.mode = IMQUIC_MOQ_LOCATION_NONE,
			.value = 0
		};
		sb_len = imquic_moq_add_subscribe_v03(moq, &buffer[poffset], blen-poffset,
			subscribe_id, track_alias, tns, tn, &sg, &so, &e, &e, num_params, &params);
	} else {
		/* FIXME WE should make filters configurable */
		sb_len = imquic_moq_add_subscribe(moq, &buffer[poffset], blen-poffset,
			subscribe_id, track_alias, tns, tn, 0, 0,
			IMQUIC_MOQ_FILTER_LATEST_OBJECT, 0, 0, 0, 0, num_params, &params);
	}
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_ok(moq, &buffer[poffset], blen-poffset,
		subscribe_id,
		expires,
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,
		FALSE,	/* FIXME Content exists */
		0,		/* FIXME Largest group ID */
		0,		/* FIXME Largest object ID */
		0,		/* FIXME Params num */
		NULL);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_OK, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason, uint64_t track_alias) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_error(moq, &buffer[poffset], blen-poffset, subscribe_id, error_code, reason, track_alias);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ERROR, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_unsubscribe(imquic_connection *conn, uint64_t subscribe_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_unsubscribe(moq, &buffer[poffset], blen-poffset, subscribe_id);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_UNSUBSCRIBE, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_auth_info *auth) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Send the request */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = 0;
	uint8_t parameters[100];
	uint8_t num_params = 0;
	imquic_data params = {
		.buffer = parameters,
		.length = 0
	};
	if(auth && auth->buffer && auth->length > 0) {
		params.length = imquic_moq_parameter_add_data(moq, parameters, sizeof(parameters),
			IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO, auth->buffer, auth->length);
		num_params = 1;
	}
	sb_len = imquic_moq_add_subscribe_announces(moq, &buffer[poffset], blen-poffset, tns, num_params, &params);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_announces_ok(moq, &buffer[poffset], blen-poffset, tns);
	sb_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_SUBSCRIBE_ANNOUNCES_OK, buffer, blen, poffset, sb_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, sb_len, FALSE);
	moq->control_stream_offset += sb_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_subscribe_announces(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tns->buffer == 0 || tns->length == 0 || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were subscribed */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t sb_len = imquic_moq_add_subscribe_announces_error(moq, &buffer[poffset], blen-poffset, tns, error_code, reason);
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

int imquic_moq_standalone_fetch(imquic_connection *conn, uint64_t subscribe_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || tns == NULL || tn == NULL ||
			range == NULL || moq->type == IMQUIC_MOQ_ROLE_PUBLISHER) {
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
	uint8_t parameters[100];
	uint8_t num_params = 0;
	imquic_data params = {
		.buffer = parameters,
		.length = 0
	};
	if(auth && auth->buffer && auth->length > 0) {
		params.length = imquic_moq_parameter_add_data(moq, parameters, sizeof(parameters),
			IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO, auth->buffer, auth->length);
		num_params = 1;
	}
	/* FIXME WE should make start/end group/object configurable */
	f_len = imquic_moq_add_fetch(moq, &buffer[poffset], blen-poffset,
		IMQUIC_MOQ_FETCH_STANDALONE,
		subscribe_id, 0, 0, tns, tn,
		0,	/* TODO Priority */
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,	/* FIXME Group order */
		range->start.group,		/* Start group */
		range->start.object,	/* Start Object */
		range->end.group,		/* End group */
		range->end.object,		/* End Object */
		num_params, &params);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_joining_fetch(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id,
		uint64_t preceding_group_offset, gboolean descending, imquic_moq_auth_info *auth) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if this namespace exists and was announced here */
	/* TODO Track subscription and track alias */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = 0;
	uint8_t parameters[100];
	uint8_t num_params = 0;
	imquic_data params = {
		.buffer = parameters,
		.length = 0
	};
	if(auth && auth->buffer && auth->length > 0) {
		params.length = imquic_moq_parameter_add_data(moq, parameters, sizeof(parameters),
			IMQUIC_MOQ_PARAM_AUTHORIZATION_INFO, auth->buffer, auth->length);
		num_params = 1;
	}
	/* FIXME WE should make start/end group/object configurable */
	f_len = imquic_moq_add_fetch(moq, &buffer[poffset], blen-poffset,
		IMQUIC_MOQ_FETCH_JOINING,
		subscribe_id, joining_subscribe_id, preceding_group_offset, NULL, NULL,
		0,	/* TODO Priority */
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,	/* FIXME Group order */
		0, 0, 0, 0,
		num_params, &params);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_accept_fetch(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER || largest == NULL) {
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
		subscribe_id,
		descending ? IMQUIC_MOQ_ORDERING_DESCENDING : IMQUIC_MOQ_ORDERING_ASCENDING,	/* FIXME Group order */
		0,	/* TODO End of track */
		largest->group,		/* Largest group */
		largest->object,	/* Largest Object */
		0, NULL);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_OK, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_reject_fetch(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL || moq->type == IMQUIC_MOQ_ROLE_SUBSCRIBER) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = imquic_moq_add_fetch_error(moq, &buffer[poffset], blen-poffset, subscribe_id, error_code, reason);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_ERROR, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_cancel_fetch(imquic_connection *conn, uint64_t subscribe_id) {
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* TODO Check if we were fetched */
	uint8_t buffer[200];
	size_t blen = sizeof(buffer), poffset = 5, start = 0;
	size_t f_len = imquic_moq_add_fetch_cancel(moq, &buffer[poffset], blen-poffset, subscribe_id);
	f_len = imquic_moq_add_control_message(moq, IMQUIC_MOQ_FETCH_CANCEL, buffer, blen, poffset, f_len, &start);
	imquic_connection_send_on_stream(conn, moq->control_stream_id,
		&buffer[start], moq->control_stream_offset, f_len, FALSE);
	moq->control_stream_offset += f_len;
	imquic_connection_flush_stream(moq->conn, moq->control_stream_id);
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}

int imquic_moq_send_object(imquic_connection *conn, imquic_moq_object *object) {
	if(object == NULL)
		return -1;
	imquic_mutex_lock(&moq_mutex);
	imquic_moq_context *moq = g_hash_table_lookup(moq_sessions, conn);
	if(moq == NULL) {
		imquic_mutex_unlock(&moq_mutex);
		return -1;
	}
	imquic_refcount_increase(&moq->ref);
	imquic_mutex_unlock(&moq_mutex);
	/* Check if we have data to send */
	gboolean has_payload = (object->payload_len > 0 && object->payload != NULL);
	gboolean valid_pkt = has_payload || (moq->version >= IMQUIC_MOQ_VERSION_04 && object->object_status != IMQUIC_MOQ_NORMAL_OBJECT);
	/* FIXME Check how we should send this */
	uint8_t buffer[40960];
	if(object->delivery == IMQUIC_MOQ_USE_DATAGRAM) {
		/* Use a datagram */
		if(has_payload || moq->version < IMQUIC_MOQ_VERSION_08) {
			size_t dg_len = imquic_moq_add_object_datagram(moq, buffer, sizeof(buffer),
				object->subscribe_id, object->track_alias, object->group_id, object->object_id, object->object_status,
				object->object_send_order, object->priority, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
		} else if(!has_payload && moq->version >= IMQUIC_MOQ_VERSION_08) {
			size_t dg_len = imquic_moq_add_object_datagram_status(moq, buffer, sizeof(buffer),
				object->track_alias, object->group_id, object->object_id, object->priority,
				object->object_status, object->extensions, object->extensions_len);
			imquic_connection_send_on_datagram(conn, buffer, dg_len);
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_STREAM && valid_pkt) {
		/* Use a throwaway stream */
		if(moq->version >= IMQUIC_MOQ_VERSION_06) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send OBJECT_STREAM on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		size_t st_len = imquic_moq_add_object_stream(moq, buffer, sizeof(buffer),
			object->subscribe_id, object->track_alias, object->group_id, object->object_id, object->object_status,
			object->object_send_order, object->priority, object->payload, object->payload_len);
		uint64_t stream_id;
		imquic_connection_new_stream_id(conn, FALSE, &stream_id);
		imquic_connection_send_on_stream(conn, stream_id, buffer, 0, st_len, TRUE);
		imquic_connection_flush_stream(conn, stream_id);
	} else if(object->delivery == IMQUIC_MOQ_USE_GROUP && (valid_pkt || object->end_of_stream)) {
		/* Use STREAM_HEADER_GROUP */
		if(moq->version >= IMQUIC_MOQ_VERSION_06) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send STREAM_HEADER_GROUP on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &object->subscribe_id);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->subscribe_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_moq_stream *moq_stream = g_hash_table_lookup(moq_sub->streams_by_group, &object->group_id);
		if(moq_stream == NULL) {
			if(!valid_pkt && object->end_of_stream) {
				/* Nothing to do here */
				imquic_mutex_unlock(&moq->mutex);
				imquic_refcount_decrease(&moq->ref);
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			moq_stream->type = IMQUIC_MOQ_STREAM_HEADER_GROUP;
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			g_hash_table_insert(moq_sub->streams_by_group, imquic_dup_uint64(object->group_id), moq_stream);
			imquic_mutex_unlock(&moq->mutex);
			/* Send a STREAM_HEADER_GROUP */
			size_t shg_len = imquic_moq_add_stream_header_group(moq, buffer, sizeof(buffer),
				object->subscribe_id, object->track_alias, object->group_id, object->object_send_order, object->priority);
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, moq_stream->stream_offset, shg_len, FALSE);
			moq_stream->stream_offset += shg_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shgo_len = 0;
		if(valid_pkt) {
			shgo_len = imquic_moq_add_stream_header_group_object(moq, buffer, sizeof(buffer),
				object->object_id, object->object_status, object->payload, object->payload_len);
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shgo_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_GROUP));
		moq_stream->stream_offset += shgo_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_GROUP) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq_sub->streams_by_group, &object->group_id);
			imquic_mutex_unlock(&moq->mutex);
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_SUBGROUP && (valid_pkt || object->end_of_stream)) {
		/* Use STREAM_HEADER_GROUP */
		if(moq->version < IMQUIC_MOQ_VERSION_06) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send SUBGROUP_HEADER on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions, &object->track_alias);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] No such subscription with track alias '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->track_alias);
			imquic_refcount_decrease(&moq->ref);
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
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			moq_stream->type = IMQUIC_MOQ_SUBGROUP_HEADER;
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			g_hash_table_insert(moq_sub->streams_by_subgroup, imquic_dup_uint64(lookup_id), moq_stream);
			imquic_mutex_unlock(&moq->mutex);
			/* Send a SUBGROUP_HEADER */
			size_t shg_len = imquic_moq_add_subgroup_header(moq, buffer, sizeof(buffer),
				object->subscribe_id, object->track_alias, object->group_id, object->subgroup_id, object->priority);
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, moq_stream->stream_offset, shg_len, FALSE);
			moq_stream->stream_offset += shg_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shgo_len = 0;
		if(valid_pkt) {
			shgo_len = imquic_moq_add_subgroup_header_object(moq, buffer, sizeof(buffer),
				object->object_id, object->object_status, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
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
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send STREAM_HEADER_TRACK on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &object->subscribe_id);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->subscribe_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_moq_stream *moq_stream = moq_sub->stream;
		if(moq_stream == NULL) {
			if(!valid_pkt && object->end_of_stream) {
				/* Nothing to do here */
				imquic_mutex_unlock(&moq->mutex);
				imquic_refcount_decrease(&moq->ref);
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			moq_stream->type = IMQUIC_MOQ_STREAM_HEADER_TRACK;
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			moq_sub->stream = moq_stream;
			imquic_mutex_unlock(&moq->mutex);
			/* Send a STREAM_HEADER_TRACK */
			size_t sht_len = imquic_moq_add_stream_header_track(moq, buffer, sizeof(buffer),
				object->subscribe_id, object->track_alias, object->object_send_order, object->priority);
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, moq_stream->stream_offset, sht_len, FALSE);
			moq_stream->stream_offset += sht_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shto_len = 0;
		if(valid_pkt) {
			shto_len = imquic_moq_add_stream_header_track_object(moq, buffer, sizeof(buffer),
				object->group_id, object->object_id, object->object_status, object->payload, object->payload_len);
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shto_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP));
		moq_stream->stream_offset += shto_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq->subscriptions_by_id, &object->subscribe_id);
			g_hash_table_remove(moq->subscriptions, &object->track_alias);
			imquic_mutex_unlock(&moq->mutex);
		}
	} else if(object->delivery == IMQUIC_MOQ_USE_FETCH && (valid_pkt || object->end_of_stream)) {
		/* Use FETCH_HEADER */
		if(moq->version < IMQUIC_MOQ_VERSION_07) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] Can't send FETCH_HEADER on a connection using %s\n",
				imquic_get_connection_name(conn), imquic_moq_version_str(moq->version));
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_mutex_lock(&moq->mutex);
		imquic_moq_subscription *moq_sub = g_hash_table_lookup(moq->subscriptions_by_id, &object->subscribe_id);
		if(moq_sub == NULL) {
			imquic_mutex_unlock(&moq->mutex);
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s][MoQ] No such subscription '%"SCNu64"' served by this connection\n",
				imquic_get_connection_name(conn), object->subscribe_id);
			imquic_refcount_decrease(&moq->ref);
			return -1;
		}
		imquic_moq_stream *moq_stream = moq_sub->stream;
		if(moq_stream == NULL) {
			if(!valid_pkt && object->end_of_stream) {
				/* Nothing to do here */
				imquic_mutex_unlock(&moq->mutex);
				imquic_refcount_decrease(&moq->ref);
				return -1;
			}
			/* Create a new stream */
			moq_stream = g_malloc0(sizeof(imquic_moq_stream));
			moq_stream->type = IMQUIC_MOQ_FETCH_HEADER;
			imquic_connection_new_stream_id(conn, FALSE, &moq_stream->stream_id);
			moq_sub->stream = moq_stream;
			imquic_mutex_unlock(&moq->mutex);
			/* Send a FETCH_HEADER */
			size_t sht_len = imquic_moq_add_fetch_header(moq, buffer, sizeof(buffer), object->subscribe_id);
			imquic_connection_send_on_stream(conn, moq_stream->stream_id,
				buffer, moq_stream->stream_offset, sht_len, FALSE);
			moq_stream->stream_offset += sht_len;
		} else {
			imquic_mutex_unlock(&moq->mutex);
		}
		/* Send the object */
		size_t shto_len = 0;
		if(valid_pkt) {
			shto_len = imquic_moq_add_fetch_header_object(moq, buffer, sizeof(buffer),
				object->group_id, object->subgroup_id, object->object_id, object->priority,
				object->object_status, object->payload, object->payload_len,
				object->extensions_count, object->extensions, object->extensions_len);
		}
		imquic_connection_send_on_stream(conn, moq_stream->stream_id,
			buffer, moq_stream->stream_offset, shto_len,
			(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP));
		moq_stream->stream_offset += shto_len;
		imquic_connection_flush_stream(moq->conn, moq_stream->stream_id);
		if(object->end_of_stream || object->object_status == IMQUIC_MOQ_END_OF_TRACK_AND_GROUP) {
			imquic_mutex_lock(&moq->mutex);
			g_hash_table_remove(moq->subscriptions_by_id, &object->subscribe_id);
			imquic_mutex_unlock(&moq->mutex);
		}
	}
	/* Done */
	imquic_refcount_decrease(&moq->ref);
	return 0;
}
