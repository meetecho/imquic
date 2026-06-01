/*! \file   imquic-moq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic MoQ public interface
 * \details Public interface to the Media Over QUIC (MoQ) native support
 * in the imquic library. This is where public functions are callbacks to
 * interact with the MoQ features of the library are defined.
 *
 * \ingroup MoQ Core
 */

#include "imquic/moq.h"
#include "internal/configuration.h"
#include "internal/connection.h"
#include "internal/moq.h"

/* Helper to dynamically return a set of ALPNs depending on the version to negotiate */
static const char *imquic_moq_version_alpn(imquic_moq_version version);

/* Create a MoQ server */
imquic_server *imquic_create_moq_server(const char *name, ...) {
	if(g_atomic_int_get(&initialized) != IMQUIC_INITIALIZED) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic not initialized\n");
		return NULL;
	}
	/* Traverse the variable arguments to build a configuration object */
	va_list args;
	va_start(args, name);
	imquic_configuration config = { 0 };
	config.name = name;
	config.is_server = TRUE;
	int property = va_arg(args, int);
	if(property != IMQUIC_CONFIG_INIT) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "First argument is not IMQUIC_CONFIG_INIT\n");
		va_end(args);
		return NULL;
	}
	property = va_arg(args, int);
	while(property != IMQUIC_CONFIG_DONE) {
		if(property == IMQUIC_CONFIG_LOCAL_BIND) {
			config.ip = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_LOCAL_PORT) {
			config.local_port = va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_REMOTE_HOST) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_REMOTE_PORT) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_TLS_CERT) {
			config.cert_pem = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_TLS_KEY) {
			config.cert_key = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_TLS_NO_VERIFY) {
			config.cert_no_verify = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_EARLY_DATA) {
			config.early_data = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_TICKET_FILE) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_SNI || property == IMQUIC_CONFIG_HTTP3_PATH) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_WT_PROTOCOLS) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ || property == IMQUIC_CONFIG_QLOG_ROQ_PACKETS) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			config.qlog_moq = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ_MESSAGES) {
			config.qlog_moq_messages = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ_OBJECTS) {
			config.qlog_moq_objects = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_SEQUENTIAL) {
			config.qlog_sequential = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_MOQ_VERSION) {
			config.moq_version = va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_MOQ_GREASE) {
			config.moq_grease = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_USER_DATA) {
			config.user_data = va_arg(args, void *);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Unsupported property %d (%s)\n", property, imquic_config_str(property));
			va_end(args);
			return NULL;
		}
		property = va_arg(args, int);
	}
	va_end(args);
	/* Check if we need raw MoQ and/or MoQ over WebTransport */
	config.alpn = config.raw_quic ? imquic_moq_version_alpn(config.moq_version) : NULL;
	config.wt_protocols = config.webtransport ? imquic_moq_version_alpn(config.moq_version) : NULL;
	if(config.alpn == NULL && config.wt_protocols == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid MoQ version\n");
		return NULL;
	}
	/* Create the server */
	imquic_server *server = imquic_network_endpoint_create(&config);
	if(server == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	server->internal_callbacks = TRUE;
	server->protocol = IMQUIC_MOQ;
	server->moq_version = config.moq_version;
	server->moq_grease = config.moq_grease;
	server->new_connection = imquic_moq_new_connection;
	server->stream_incoming = imquic_moq_stream_incoming;
	server->datagram_incoming = imquic_moq_datagram_incoming;
	server->reset_stream_incoming = imquic_moq_reset_stream_incoming;
	server->stop_sending_incoming = imquic_moq_stop_sending_incoming;
	server->connection_gone = imquic_moq_connection_gone;
	return server;
}

/* Create a MoQ client */
imquic_client *imquic_create_moq_client(const char *name, ...) {
	if(g_atomic_int_get(&initialized) != IMQUIC_INITIALIZED) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic not initialized\n");
		return NULL;
	}
	/* Traverse the variable arguments to build a configuration object */
	va_list args;
	va_start(args, name);
	imquic_configuration config = { 0 };
	config.name = name;
	config.is_server = FALSE;
	int property = va_arg(args, int);
	if(property != IMQUIC_CONFIG_INIT) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "First argument is not IMQUIC_CONFIG_INIT\n");
		va_end(args);
		return NULL;
	}
	property = va_arg(args, int);
	while(property != IMQUIC_CONFIG_DONE) {
		if(property == IMQUIC_CONFIG_LOCAL_BIND) {
			config.ip = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_LOCAL_PORT) {
			config.local_port = va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_REMOTE_HOST) {
			config.remote_host = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_REMOTE_PORT) {
			config.remote_port = va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_TLS_CERT) {
			config.cert_pem = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_TLS_KEY) {
			config.cert_key = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_TLS_NO_VERIFY) {
			config.cert_no_verify = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_EARLY_DATA) {
			config.early_data = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_TICKET_FILE) {
			config.ticket_file = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_SNI) {
			config.sni = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_HTTP3_PATH) {
			config.h3_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_WT_PROTOCOLS) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ || property == IMQUIC_CONFIG_QLOG_ROQ_PACKETS) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			config.qlog_moq = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ_MESSAGES) {
			config.qlog_moq_messages = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ_OBJECTS) {
			config.qlog_moq_objects = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_SEQUENTIAL) {
			config.qlog_sequential = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_MOQ_VERSION) {
			config.moq_version = va_arg(args, int);
		} else if(property == IMQUIC_CONFIG_MOQ_GREASE) {
			config.moq_grease = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_USER_DATA) {
			config.user_data = va_arg(args, void *);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Unsupported property %d (%s)\n", property, imquic_config_str(property));
			va_end(args);
			return NULL;
		}
		property = va_arg(args, int);
	}
	va_end(args);
	/* Check if we need raw MoQ and/or MoQ over WebTransport */
	config.alpn = config.raw_quic ? imquic_moq_version_alpn(config.moq_version) : NULL;
	config.wt_protocols = config.webtransport ? imquic_moq_version_alpn(config.moq_version) : NULL;
	if(config.alpn == NULL && config.wt_protocols == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid MoQ version\n");
		return NULL;
	}
	/* Create the client */
	imquic_client *client = imquic_network_endpoint_create(&config);
	if(client == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	client->internal_callbacks = TRUE;
	client->protocol = IMQUIC_MOQ;
	client->moq_version = config.moq_version;
	client->moq_grease = config.moq_grease;
	client->new_connection = imquic_moq_new_connection;
	client->stream_incoming = imquic_moq_stream_incoming;
	client->datagram_incoming = imquic_moq_datagram_incoming;
	client->reset_stream_incoming = imquic_moq_reset_stream_incoming;
	client->stop_sending_incoming = imquic_moq_stop_sending_incoming;
	client->connection_gone = imquic_moq_connection_gone;
	return client;
}

/* Helpers */
static size_t imquic_moq_track_render(uint8_t *data, size_t dlen, char *buffer, size_t blen) {
	if(data == NULL || dlen == 0 || buffer == NULL || blen == 0)
		return 0;
	size_t i = 0, offset = 0;
	for(i=0; i<dlen; i++) {
		if((data[i] >= 0x30 && data[i] <= 0x39) ||	/* 0-9 */
				(data[i] >= 0x41 && data[i] <= 0x5a) ||	/* A-Z */
				(data[i] >= 0x61 && data[i] <= 0x7a) ||	/* a-z */
				(data[i] == 0x5f)) {	/* underscore */
			/* Write as is */
			buffer[offset] = (char)data[i];
			offset++;
		} else {
			/* Render as .XX (2-digit hex) */
			g_snprintf(&buffer[offset], blen-offset, ".%02x", data[i]);
			offset += 3;
		}
		if(offset >= blen) {
			/* Buffer exceeded, return */
			break;
		}
		buffer[offset] = '\0';
	}
	return offset;
}

const char *imquic_moq_namespace_str(imquic_moq_namespace *tns, char *buffer, size_t blen, gboolean tuple) {
	if(buffer == NULL)
		return NULL;
	*buffer = '\0';
	if(tns == NULL)
		return buffer;
	size_t offset = 0;
	while(tns != NULL) {
		if(blen - offset == 0)
			goto trunc;
		if(offset > 0) {
			buffer[offset] = '-';
			offset++;
			buffer[offset] = '\0';
		}
		offset += imquic_moq_track_render(tns->buffer, tns->length, &buffer[offset], blen-offset);
		if(offset >= blen)
			goto trunc;
		if(!tuple)
			break;
		tns = tns->next;
	}
	return buffer;
trunc:
	IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render namespace(s) as a string (truncation would occur)\n");
	return NULL;
}

gboolean imquic_moq_namespace_equals(imquic_moq_namespace *first, imquic_moq_namespace *second) {
	if(first == NULL || second == NULL)
		return FALSE;
	size_t i = 0;
	while(first || second) {
		if(first == NULL || second == NULL)
			return FALSE;
		if(first->length != second->length)
			return FALSE;
		for(i=0; i<first->length; i++) {
			if(first->buffer[i] != second->buffer[i])
				return FALSE;
		}
		first = first->next;
		second = second->next;
	}
	/* If we got here, it's a success */
	return TRUE;
}

gboolean imquic_moq_namespace_contains(imquic_moq_namespace *parent, imquic_moq_namespace *child) {
	if(parent == NULL)
		return TRUE;
	if(child == NULL)
		return FALSE;
	size_t i = 0;
	while(parent) {
		if(child == NULL)
			return FALSE;
		if(parent->length != child->length)
			return FALSE;
		for(i=0; i<parent->length; i++) {
			if(parent->buffer[i] != child->buffer[i])
				return FALSE;
		}
		parent = parent->next;
		child = child->next;
	}
	/* If we got here, it's a success */
	return TRUE;
}

imquic_moq_namespace *imquic_moq_namespace_duplicate(imquic_moq_namespace *tns) {
	if(tns == NULL)
		return NULL;
	imquic_moq_namespace *dup = g_malloc0(32 * sizeof(imquic_moq_namespace));
	int index = 0;
	while(tns != NULL) {
		if(tns->buffer == NULL) {
			dup[index].buffer = NULL;
			dup[index].length = 0;
		} else {
			dup[index].buffer = g_malloc(tns->length);
			memcpy(dup[index].buffer, tns->buffer, tns->length);
			dup[index].length = tns->length;
		}
		if(index == 31) {
			dup[index].next = NULL;
			break;
		}
		dup[index].next = tns->next ? &dup[index+1] : NULL;
		index++;
		tns = tns->next;
	}
	return dup;
}

gboolean imquic_moq_namespace_is_valid(imquic_moq_namespace *tns, gboolean fail_if_empty, uint64_t *tns_num) {
	if(tns_num)
		*tns_num = 0;
	if(tns == NULL)
		return !fail_if_empty;
	uint8_t tuples = 0;
	size_t tot_len = 0;
	while(tns != NULL) {
		tuples++;
		if(tns->buffer == NULL || tns->length == 0)
			return FALSE;
		if(tuples == 1 && tns->length == 1 && tns->buffer[0] == '.')
			return FALSE;
		tot_len += tns->length;
		tns = tns->next;
	}
	if(tuples > 32 || tot_len > 4096)
		return FALSE;
	/* If we got here, the namespace is valid */
	if(tns_num)
		*tns_num = tuples;
	return TRUE;
}

void imquic_moq_namespace_free(imquic_moq_namespace *tns) {
	if(tns == NULL)
		return;
	imquic_moq_namespace *temp = tns;
	while(temp != NULL) {
		g_free(temp->buffer);
		temp = temp->next;
	}
	g_free(tns);
}

const char *imquic_moq_track_str(imquic_moq_track *tn, char *buffer, size_t blen) {
	if(buffer == NULL)
		return NULL;
	*buffer = '\0';
	if(tn == NULL || tn->buffer == 0 || tn->length == 0)
		return buffer;
	size_t offset = imquic_moq_track_render(tn->buffer, tn->length, buffer, blen);
	if(offset >= blen)
		goto trunc;
	return buffer;
trunc:
	IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render track name as a string (truncation would occur)\n");
	return NULL;
}

gboolean imquic_moq_track_equals(imquic_moq_track *first, imquic_moq_track *second) {
	if(first == NULL || second == NULL)
		return FALSE;
	if(first->length != second->length)
		return FALSE;
	size_t i = 0;
	for(i=0; i<first->length; i++) {
		if(first->buffer[i] != second->buffer[i])
			return FALSE;
	}
	/* If we got here, it's a success */
	return TRUE;
}

imquic_moq_track *imquic_moq_track_duplicate(imquic_moq_track *tn) {
	if(tn == NULL)
		return NULL;
	imquic_moq_track *dup = g_malloc0(sizeof(imquic_moq_track));
	dup->length = tn->buffer ? tn->length : 0;
	if(dup->length > 0) {
		dup->buffer = g_malloc(dup->length);
		memcpy(dup->buffer, tn->buffer, tn->length);
	}
	return dup;
}

gboolean imquic_moq_track_is_valid(imquic_moq_track *tn) {
	if(tn == NULL)
		return TRUE;
	if(tn->buffer != NULL && tn->length == 0)
		tn->buffer = NULL;
	if(tn->buffer == NULL && tn->length > 0)
		return FALSE;
	return tn->length < 4096;
}

void imquic_moq_track_free(imquic_moq_track *tn) {
	if(tn != NULL) {
		g_free(tn->buffer);
		g_free(tn);
	}
}

/* Setting callbacks */
void imquic_set_new_moq_connection_cb(imquic_endpoint *endpoint,
		void (* new_moq_connection)(imquic_connection *conn, void *user_data)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.new_connection = new_moq_connection;
	}
}

void imquic_set_incoming_moq_connection_cb(imquic_endpoint *endpoint,
		uint64_t (* incoming_moq_connection)(imquic_connection *conn, uint8_t *auth, size_t authlen)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		if(!endpoint->is_server) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set this MoQ callback on clients\n");
			return;
		}
		endpoint->callbacks.moq.incoming_moq_connection = incoming_moq_connection;
	}
}

void imquic_set_moq_ready_cb(imquic_endpoint *endpoint,
		void (* moq_ready)(imquic_connection *conn)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.moq_ready = moq_ready;
	}
}

void imquic_set_incoming_publish_namespace_cb(imquic_endpoint *endpoint,
		void (* incoming_publish_namespace)(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_publish_namespace = incoming_publish_namespace;
	}
}

void imquic_set_incoming_publish_namespace_cancel_cb(imquic_endpoint *endpoint,
		void (* incoming_publish_namespace_cancel)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_publish_namespace_cancel = incoming_publish_namespace_cancel;
	}
}

void imquic_set_publish_namespace_accepted_cb(imquic_endpoint *endpoint,
		void (* publish_namespace_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_namespace_accepted = publish_namespace_accepted;
	}
}

void imquic_set_publish_namespace_error_cb(imquic_endpoint *endpoint,
		void (* publish_namespace_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_namespace_error = publish_namespace_error;
	}
}

void imquic_set_publish_namespace_done_cb(imquic_endpoint *endpoint,
		void (* publish_namespace_done)(imquic_connection *conn, uint64_t request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_namespace_done = publish_namespace_done;
	}
}

void imquic_set_incoming_publish_cb(imquic_endpoint *endpoint,
		void (* incoming_publish)(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_track *tn,
			uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_publish = incoming_publish;
	}
}

void imquic_set_publish_accepted_cb(imquic_endpoint *endpoint,
		void (* publish_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_accepted = publish_accepted;
	}
}

void imquic_set_publish_error_cb(imquic_endpoint *endpoint,
		void (* publish_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_codes,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_error = publish_error;
	}
}

void imquic_set_incoming_subscribe_cb(imquic_endpoint *endpoint,
		void (* incoming_subscribe)(imquic_connection *conn, uint64_t request_id,
			imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_subscribe = incoming_subscribe;
	}
}

void imquic_set_subscribe_accepted_cb(imquic_endpoint *endpoint,
		void (* subscribe_accepted)(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_properties)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_accepted = subscribe_accepted;
	}
}

void imquic_set_subscribe_error_cb(imquic_endpoint *endpoint,
		void (* subscribe_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_codes,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_error = subscribe_error;
	}
}

void imquic_set_request_updated_cb(imquic_endpoint *endpoint,
		void (* request_updated)(imquic_connection *conn, uint64_t request_id, uint64_t sub_request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.request_updated = request_updated;
	}
}

void imquic_set_request_update_accepted_cb(imquic_endpoint *endpoint,
		void (* request_update_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.request_update_accepted = request_update_accepted;
	}
}

void imquic_set_request_update_error_cb(imquic_endpoint *endpoint,
		void (* request_update_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_codes,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.request_update_error = request_update_error;
	}
}

void imquic_set_publish_done_cb(imquic_endpoint *endpoint,
		void (* publish_done)(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.publish_done = publish_done;
	}
}

void imquic_set_incoming_unsubscribe_cb(imquic_endpoint *endpoint,
		void (* incoming_unsubscribe)(imquic_connection *conn, uint64_t request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unsubscribe = incoming_unsubscribe;
	}
}

void imquic_set_requests_blocked_cb(imquic_endpoint *endpoint,
		void (* requests_blocked)(imquic_connection *conn, uint64_t max_request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.requests_blocked = requests_blocked;
	}
}

void imquic_set_incoming_subscribe_namespace_cb(imquic_endpoint *endpoint,
		void (* incoming_subscribe_namespace)(imquic_connection *conn, uint64_t request_id,
			imquic_moq_namespace *tns, imquic_moq_subscribe_namespace_options subscribe_options, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_subscribe_namespace = incoming_subscribe_namespace;
	}
}

void imquic_set_subscribe_namespace_accepted_cb(imquic_endpoint *endpoint,
		void (* subscribe_namespace_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_namespace_accepted = subscribe_namespace_accepted;
	}
}

void imquic_set_subscribe_namespace_error_cb(imquic_endpoint *endpoint,
		void (* subscribe_namespace_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_namespace_error = subscribe_namespace_error;
	}
}

void imquic_set_incoming_unsubscribe_namespace_cb(imquic_endpoint *endpoint,
		void (* incoming_unsubscribe_namespace)(imquic_connection *conn, uint64_t request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unsubscribe_namespace = incoming_unsubscribe_namespace;
	}
}

void imquic_set_incoming_subscribe_tracks_cb(imquic_endpoint *endpoint,
		void (* incoming_subscribe_tracks)(imquic_connection *conn, uint64_t request_id,
			imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_subscribe_tracks = incoming_subscribe_tracks;
	}
}

void imquic_set_subscribe_tracks_accepted_cb(imquic_endpoint *endpoint,
		void (* subscribe_tracks_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_tracks_accepted = subscribe_tracks_accepted;
	}
}

void imquic_set_subscribe_tracks_error_cb(imquic_endpoint *endpoint,
		void (* subscribe_tracks_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_tracks_error = subscribe_tracks_error;
	}
}

void imquic_set_incoming_unsubscribe_tracks_cb(imquic_endpoint *endpoint,
		void (* incoming_unsubscribe_tracks)(imquic_connection *conn, uint64_t request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unsubscribe_tracks = incoming_unsubscribe_tracks;
	}
}

void imquic_set_incoming_namespace_cb(imquic_endpoint *endpoint,
		void (* incoming_namespace)(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_namespace = incoming_namespace;
	}
}

void imquic_set_incoming_namespace_done_cb(imquic_endpoint *endpoint,
		void (* incoming_namespace_done)(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_namespace_done = incoming_namespace_done;
	}
}

void imquic_set_incoming_publish_blocked_cb(imquic_endpoint *endpoint,
		void (* incoming_publish_blocked)(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_track *tn)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_publish_blocked = incoming_publish_blocked;
	}
}

void imquic_set_incoming_standalone_fetch_cb(imquic_endpoint *endpoint,
		void (* incoming_standalone_fetch)(imquic_connection *conn, uint64_t request_id,
			imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_location_range *range, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_standalone_fetch = incoming_standalone_fetch;
	}
}

void imquic_set_incoming_joining_fetch_cb(imquic_endpoint *endpoint,
		void (* incoming_joining_fetch)(imquic_connection *conn, uint64_t request_id, uint64_t joining_request_id,
			gboolean absolute, uint64_t joining_start, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_joining_fetch = incoming_joining_fetch;
	}
}

void imquic_set_incoming_fetch_cancel_cb(imquic_endpoint *endpoint,
		void (* incoming_fetch_cancel)(imquic_connection *conn, uint64_t request_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_fetch_cancel = incoming_fetch_cancel;
	}
}

void imquic_set_fetch_accepted_cb(imquic_endpoint *endpoint,
		void (* fetch_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_location *largest, imquic_moq_request_parameters *parameters, GList *track_properties)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.fetch_accepted = fetch_accepted;
	}
}

void imquic_set_fetch_error_cb(imquic_endpoint *endpoint,
		void (* fetch_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_codes,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.fetch_error = fetch_error;
	}
}

void imquic_set_incoming_track_status_cb(imquic_endpoint *endpoint,
		void (* incoming_track_status)(imquic_connection *conn, uint64_t request_id,
			imquic_moq_namespace *tns, imquic_moq_track *tn, imquic_moq_request_parameters *parameters)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_track_status = incoming_track_status;
	}
}

void imquic_set_track_status_accepted_cb(imquic_endpoint *endpoint,
		void (* track_status_accepted)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters, GList *track_properties)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.track_status_accepted = track_status_accepted;
	}
}

void imquic_set_track_status_error_cb(imquic_endpoint *endpoint,
		void (* track_status_error)(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_codes,
			const char *reason, uint64_t retry_interval, imquic_moq_redirect *redirect)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.track_status_error = track_status_error;
	}
}

void imquic_set_incoming_object_cb(imquic_endpoint *endpoint,
		void (* incoming_object)(imquic_connection *conn, imquic_moq_object *object)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_object = incoming_object;
	}
}

void imquic_set_incoming_goaway_cb(imquic_endpoint *endpoint,
		void (* incoming_goaway)(imquic_connection *conn, const char *uri, uint64_t timeout)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_goaway = incoming_goaway;
	}
}

void imquic_set_incoming_request_goaway_cb(imquic_endpoint *endpoint,
		void (* incoming_request_goaway)(imquic_connection *conn, uint64_t request_id, const char *uri, uint64_t timeout)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_request_goaway = incoming_request_goaway;
	}
}

void imquic_set_moq_connection_gone_cb(imquic_endpoint *endpoint,
		void (* moq_connection_gone)(imquic_connection *conn, uint64_t error_code, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.connection_gone = moq_connection_gone;
	}
}

/* Versions */
const char *imquic_moq_version_str(imquic_moq_version version) {
	switch(version) {
		case IMQUIC_MOQ_VERSION_16:
			return "draft-ietf-moq-transport-16";
		case IMQUIC_MOQ_VERSION_17:
			return "draft-ietf-moq-transport-17";
		case IMQUIC_MOQ_VERSION_18:
			return "draft-ietf-moq-transport-18";
		case IMQUIC_MOQ_VERSION_ANY:
			return "draft-ietf-moq-transport-XX(-from--16-to-18)";
		default: break;
	}
	return NULL;
}

static const char *imquic_moq_version_alpn(imquic_moq_version version) {
	switch(version) {
		case IMQUIC_MOQ_VERSION_16:
			return "moqt-16";
		case IMQUIC_MOQ_VERSION_17:
			return "moqt-17";
		case IMQUIC_MOQ_VERSION_18:
			return "moqt-18";
		case IMQUIC_MOQ_VERSION_ANY:
			return "moqt-18,moqt-17,moqt-16";
		default: break;
	}
	return NULL;
}

/* Delivery modes */
const char *imquic_moq_delivery_str(imquic_moq_delivery type) {
	switch(type) {
		case IMQUIC_MOQ_USE_DATAGRAM:
			return "OBJECT_DATAGRAM";
		case IMQUIC_MOQ_USE_SUBGROUP:
			return "STREAM_HEADER_SUBGROUP";
		case IMQUIC_MOQ_USE_FETCH:
			return "FETCH_HEADER";
		default: break;
	}
	return NULL;
}

/* Object statuses */
const char *imquic_moq_object_status_str(imquic_moq_object_status status) {
	switch(status) {
		case IMQUIC_MOQ_NORMAL_OBJECT:
			return "NORMAL_OBJECT";
		case IMQUIC_MOQ_END_OF_GROUP:
			return "END_OF_GROUP";
		case IMQUIC_MOQ_END_OF_TRACK:
			return "END_OF_TRACK";
		default: break;
	}
	return NULL;
}

/* Property types  */
const char *imquic_moq_property_type_str(imquic_moq_version version, imquic_moq_property_type type) {
	switch(type) {
		case IMQUIC_MOQ_PROPERTY_OBJECT_DELIVERY_TIMEOUT:
			return (version >= IMQUIC_MOQ_VERSION_18 ? "Object Delivery Timeout" : "Delivery Timeout");
		case IMQUIC_MOQ_PROPERTY_MAX_CACHE_DURATION:
			return "Max Cache Duration";
		case IMQUIC_MOQ_PROPERTY_SUBGROUP_DELIVERY_TIMEOUT:
			return "Subgroup Delivery Timeout";
		case IMQUIC_MOQ_PROPERTY_DEFAULT_PUBLISHER_PRIORITY:
			return "Default Publisher Priority";
		case IMQUIC_MOQ_PROPERTY_DEFAULT_GROUP_ORDER:
			return "Default Group Order";
		case IMQUIC_MOQ_PROPERTY_DYNAMIC_GROUPS:
			return "Dynamic Groups";
		case IMQUIC_MOQ_PROPERTY_PRIOR_GROUP_ID_GAP:
			return "Prior Group ID Gap";
		case IMQUIC_MOQ_PROPERTY_PRIOR_OBJECT_ID_GAP:
			return "Prior Object ID Gap";
		case IMQUIC_MOQ_PROPERTY_IMMUTABLE_PROPERTIES:
			return "Immutable Extensions";
		case IMQUIC_MOQ_LOC_TIMESTAMP:
			return "LOC Timestamp";
		case IMQUIC_MOQ_LOC_TIMESCALE:
			return "LOC Timescale";
		case IMQUIC_MOQ_LOC_VIDEO_CONFIG:
			return "LOC Video Config";
		case IMQUIC_MOQ_LOC_VIDEO_FRAME_MARKING:
			return "LOC Video Frame Marking";
		case IMQUIC_MOQ_LOC_AUDIO_LEVEL:
			return "LOC Audio Level";
		default: break;
	}
	return NULL;
}

/* Catalog support */
static imquic_json_parameter catalog_parameters[] = {
	{"version", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_REQUIRED | IMQUIC_JSON_PARAM_POSITIVE},
	{"deltaUpdate", IMQUIC_JSON_BOOL, 0},
	{"addTracks", IMQUIC_JSON_ARRAY, 0},
	{"removeTracks", IMQUIC_JSON_ARRAY, 0},
	{"cloneTracks", IMQUIC_JSON_ARRAY, 0},
	{"generatedAt", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"isComplete", IMQUIC_JSON_BOOL, 0},
	{"tracks", IMQUIC_JSON_ARRAY, IMQUIC_JSON_PARAM_REQUIRED},
};
static imquic_json_parameter track_parameters[] = {
	{"namespace", IMQUIC_JSON_STRING, 0},
	{"name", IMQUIC_JSON_STRING, IMQUIC_JSON_PARAM_REQUIRED},
	{"packaging", IMQUIC_JSON_STRING, IMQUIC_JSON_PARAM_REQUIRED},
	{"eventType", IMQUIC_JSON_STRING, 0},
	{"isLive", IMQUIC_JSON_BOOL, IMQUIC_JSON_PARAM_REQUIRED},
	{"targetLatency", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"role", IMQUIC_JSON_STRING, 0},
	{"label", IMQUIC_JSON_STRING, 0},
	{"renderGroup", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"altGroup", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"initData", IMQUIC_JSON_STRING, 0},
	{"depends", IMQUIC_JSON_ARRAY, 0},
	{"temporalId", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"spatialId", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"codec", IMQUIC_JSON_STRING, 0},
	{"mimeType", IMQUIC_JSON_STRING, 0},
	{"framerate", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"timescale", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"bitrate", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"width", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"height", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"samplerate", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"channelConfig", IMQUIC_JSON_STRING, 0},
	{"displayWidth", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"displayHeight", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
	{"lang", IMQUIC_JSON_STRING, 0},
	{"parentName", IMQUIC_JSON_STRING, 0},
	{"trackDuration", IMQUIC_JSON_INTEGER, IMQUIC_JSON_PARAM_POSITIVE},
};


imquic_moq_catalog *imquic_moq_catalog_create(uint8_t version) {
	imquic_moq_catalog *catalog = g_malloc0(sizeof(imquic_moq_catalog));
	catalog->version = 1;
	catalog->generated_at = g_get_real_time();
	return catalog;
}

imquic_moq_catalog *imquic_moq_catalog_parse(const char *json) {
	if(json == NULL)
		return NULL;
	/* Parse the JSON */
	json_error_t error;
	json_t *root = json_loads(json, 0, &error);
	if(root == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Catalog error: invalid JSON on line %d: %s\n",
			error.line, error.text);
		return NULL;
	}
	/* Validate the JSON */
	int res = 0;
	IMQUIC_VALIDATE_JSON_OBJECT(root, catalog_parameters, res);
	if(res != 0) {
		json_decref(root);
		return NULL;
	}
	size_t i = 0;
	json_t *tracks = json_object_get(root, "tracks");
	for(i=0; i<json_array_size(tracks); i++) {
		json_t *t = json_array_get(tracks, i);
		IMQUIC_VALIDATE_JSON_OBJECT(t, track_parameters, res);
		if(res != 0) {
			json_decref(root);
			return NULL;
		}
	}
	/* Parse the JSON and create the catalog */
	uint8_t version = json_integer_value(json_object_get(root, "version"));
	if(version != 1) {
		json_decref(root);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Catalog error: invalid version\n");
		return NULL;
	}
	imquic_moq_catalog *catalog = imquic_moq_catalog_create(version);
	json_t *g = json_object_get(root, "generatedAt");
	catalog->generated_at = g ? json_integer_value(g) : g_get_real_time();
	/* Iterate on tracks */
	for(i=0; i<json_array_size(tracks); i++) {
		json_t *t = json_array_get(tracks, i);
		/* Initialize the new track and add it */
		const char *track_namespace = json_string_value(json_object_get(t, "namespace"));
		const char *track_name = json_string_value(json_object_get(t, "name"));
		const char *packaging = json_string_value(json_object_get(t, "packaging"));
		gboolean is_live = json_is_true(json_object_get(t, "isLive"));
		imquic_moq_catalog_track *track = imquic_moq_catalog_create_track(track_namespace,
			track_name, packaging, is_live);
		if(track == NULL || imquic_moq_catalog_add_track(catalog, track) < 0) {
			json_decref(root);
			imquic_moq_catalog_destroy(catalog);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Catalog error: error adding track\n");
			return NULL;
		}
		/* Add the other fields we understand */
		json_t *tl = json_object_get(t, "targetLatency");
		track->target_latency = tl ? json_integer_value(tl) : 0;
		json_t *r = json_object_get(t, "role");
		track->role = r ? g_strdup(json_string_value(r)) : NULL;
		json_t *rg = json_object_get(t, "renderGroup");
		track->render_group = rg ? json_integer_value(rg) : 0;
		json_t *c = json_object_get(t, "codec");
		track->codec = c ? g_strdup(json_string_value(c)) : NULL;
		json_t *s = json_object_get(t, "samplerate");
		track->samplerate = s ? json_integer_value(s) : 0;
		json_t *cc = json_object_get(t, "channelConfig");
		track->channel_config = cc ? g_strdup(json_string_value(cc)) : NULL;
		json_t *w = json_object_get(t, "width");
		track->width = w ? json_integer_value(w) : 0;
		json_t *h = json_object_get(t, "height");
		track->height = h ? json_integer_value(h) : 0;
		json_t *f = json_object_get(t, "framerate");
		track->framerate = f ? json_integer_value(f) : 0;
		json_t *b = json_object_get(t, "bitrate");
		track->bitrate = b ? json_integer_value(b) : 0;
	}
	/* Done */
	json_decref(root);
	return catalog;
}

int imquic_moq_catalog_update(imquic_moq_catalog *catalog, const char *json) {
	if(catalog == NULL)
		return -1;
	if(json == NULL)	/* Nothing to do */
		return 0;
	/* TODO */
	IMQUIC_LOG(IMQUIC_LOG_WARN, "Catalog deltas not supported yet\n");
	return -1;
}

imquic_moq_catalog_track *imquic_moq_catalog_create_track(const char *track_namespace,
		const char *track_name, const char *packaging, gboolean is_live) {
	if(track_name == NULL || packaging == NULL)
		return NULL;
	imquic_moq_catalog_track *track = g_malloc0(sizeof(imquic_moq_catalog_track));
	track->track_name = g_strdup(track_name);
	track->track_namespace = (track_namespace ? g_strdup(track_namespace) : NULL);
	track->packaging = g_strdup(packaging);
	track->is_live = is_live;
	return track;
}

int imquic_moq_catalog_add_track(imquic_moq_catalog *catalog, imquic_moq_catalog_track *track) {
	if(catalog == NULL || track == NULL)
		return -1;
	catalog->tracks = g_list_append(catalog->tracks, track);
	/* TODO We should create deltas */
	return 0;
}

int imquic_moq_catalog_remove_track(imquic_moq_catalog *catalog,
		const char *track_namespace, const char *track_name) {
	if(catalog == NULL || track_name == NULL)
		return -1;
	/* Look for the track in the catalog */
	gboolean found = FALSE;
	GList *temp = catalog->tracks;
	while(temp) {
		imquic_moq_catalog_track *track = (imquic_moq_catalog_track *)temp->data;
		if(track->track_name != NULL && !strcasecmp(track->track_name, track_name) &&
				((track_namespace == NULL && track->track_namespace == NULL) ||
					(track->track_namespace != NULL && !strcasecmp(track->track_namespace, track_namespace)))) {
			/* Found */
			found = TRUE;
			catalog->tracks = g_list_remove(catalog->tracks, track);
			imquic_moq_catalog_track_destroy(track);
			break;
		}
		temp = temp->next;
	}
	/* TODO We should create deltas */
	return found ? 0 : -1;
}

char *imquic_moq_catalog_serialize(imquic_moq_catalog *catalog) {
	json_t *json = imquic_moq_catalog_serialize_obj(catalog);
	if(json == NULL)
		return NULL;
	char *json_str = json_dumps(json, JSON_COMPACT | JSON_PRESERVE_ORDER);
	json_decref(json);
	return json_str;
}

json_t *imquic_moq_catalog_serialize_obj(imquic_moq_catalog *catalog) {
	if(catalog == NULL)
		return NULL;
	json_t *json = json_object();
	json_object_set_new(json, "version", json_integer(catalog->version));
	json_object_set_new(json, "generatedAt", json_integer(catalog->generated_at));
	json_t *tracks = json_array();
	GList *temp = catalog->tracks;
	while(temp) {
		imquic_moq_catalog_track *track = (imquic_moq_catalog_track *)temp->data;
		json_t *t = json_object();
		if(track->track_namespace != NULL)
			json_object_set_new(t, "namespace", json_string(track->track_namespace));
		if(track->track_name != NULL)
			json_object_set_new(t, "name", json_string(track->track_name));
		if(track->packaging != NULL)
			json_object_set_new(t, "packaging", json_string(track->packaging));
		json_object_set_new(t, "isLive", track->is_live ? json_true() : json_false());
		if(track->target_latency > 0)
			json_object_set_new(t, "targetLatency", json_integer(track->target_latency));
		if(track->role != NULL)
			json_object_set_new(t, "role", json_string(track->role));
		if(track->render_group > 0)
			json_object_set_new(t, "renderGroup", json_integer(track->render_group));
		if(track->codec != NULL)
			json_object_set_new(t, "codec", json_string(track->codec));
		if(track->samplerate > 0)
			json_object_set_new(t, "samplerate", json_integer(track->samplerate));
		if(track->channel_config != NULL)
			json_object_set_new(t, "channelConfig", json_string(track->channel_config));
		if(track->width > 0)
			json_object_set_new(t, "width", json_integer(track->width));
		if(track->height > 0)
			json_object_set_new(t, "height", json_integer(track->height));
		if(track->framerate > 0)
			json_object_set_new(t, "framerate", json_integer(track->framerate));
		if(track->bitrate > 0)
			json_object_set_new(t, "bitrate", json_integer(track->bitrate));
		json_array_append_new(tracks, t);
		temp = temp->next;
	}
	json_object_set_new(json, "tracks", tracks);
	return json;
}

void imquic_moq_catalog_track_destroy(imquic_moq_catalog_track *track) {
	if(track == NULL)
		return;
	g_free(track->track_name);
	g_free(track->track_namespace);
	g_free(track->packaging);
	g_free(track->role);
	g_free(track->codec);
	g_free(track->channel_config);
	g_free(track);
}

void imquic_moq_catalog_destroy(imquic_moq_catalog *catalog) {
	if(catalog == NULL)
		return;
	if(catalog->tracks != NULL)
		g_list_free_full(catalog->tracks, (GDestroyNotify)imquic_moq_catalog_track_destroy);
	g_free(catalog);
}
