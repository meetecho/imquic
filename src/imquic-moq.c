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

#define IMQUIC_MOQ_ALPN		"moq-00"

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
		} else if(property == IMQUIC_CONFIG_TLS_PASSWORD) {
			config.cert_pwd = va_arg(args, char *);
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
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_SUBPROTOCOL) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_USER_DATA) {
			config.user_data = va_arg(args, void *);
		} else if(property == IMQUIC_CONFIG_DONE) {
			break;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Unsupported property %d (%s)\n", property, imquic_config_str(property));
			return NULL;
		}
		property = va_arg(args, int);
	}
	va_end(args);
	/* Check if we need raw MoQ and/or MoQ over WebTransport */
	config.alpn = IMQUIC_MOQ_ALPN;
	if(config.webtransport) {
		if(!config.raw_quic)
			config.alpn = NULL;
 		config.subprotocol = IMQUIC_MOQ_ALPN;
	}
	/* Create the server */
	imquic_server *server = imquic_network_endpoint_create(&config);
	if(server == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	server->internal_callbacks = TRUE;
	server->protocol = IMQUIC_MOQ;
	server->new_connection = imquic_moq_new_connection;
	server->stream_incoming = imquic_moq_stream_incoming;
	server->datagram_incoming = imquic_moq_datagram_incoming;
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
	config.alpn = "moq-10";
	int property = va_arg(args, int);
	if(property != IMQUIC_CONFIG_INIT) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "First argument is not IMQUIC_CONFIG_INIT\n");
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
		} else if(property == IMQUIC_CONFIG_TLS_PASSWORD) {
			config.cert_pwd = va_arg(args, char *);
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
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_SUBPROTOCOL) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating MoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_USER_DATA) {
			config.user_data = va_arg(args, void *);
		} else if(property == IMQUIC_CONFIG_DONE) {
			break;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Unsupported property %d (%s)\n", property, imquic_config_str(property));
			return NULL;
		}
		property = va_arg(args, int);
	}
	va_end(args);
	/* Check if we need raw MoQ and/or MoQ over WebTransport */
	config.alpn = IMQUIC_MOQ_ALPN;
	if(config.webtransport) {
		if(!config.raw_quic)
			config.alpn = NULL;
 		config.subprotocol = IMQUIC_MOQ_ALPN;
	}
	/* Create the client */
	imquic_client *client = imquic_network_endpoint_create(&config);
	if(client == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	client->internal_callbacks = TRUE;
	client->protocol = IMQUIC_MOQ;
	client->new_connection = imquic_moq_new_connection;
	client->stream_incoming = imquic_moq_stream_incoming;
	client->datagram_incoming = imquic_moq_datagram_incoming;
	client->connection_gone = imquic_moq_connection_gone;
	return client;
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

void imquic_set_incoming_announce_cb(imquic_endpoint *endpoint,
		void (* incoming_announce)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_announce = incoming_announce;
	}
}

void imquic_set_incoming_announce_cancel_cb(imquic_endpoint *endpoint,
		void (* incoming_announce_cancel)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_announce_cancel = incoming_announce_cancel;
	}
}

void imquic_set_announce_accepted_cb(imquic_endpoint *endpoint,
		void (* announce_accepted)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.announce_accepted = announce_accepted;
	}
}

void imquic_set_announce_error_cb(imquic_endpoint *endpoint,
		void (* announce_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.announce_error = announce_error;
	}
}

void imquic_set_incoming_unannounce_cb(imquic_endpoint *endpoint,
		void (* incoming_unannounce)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unannounce = incoming_unannounce;
	}
}

void imquic_set_incoming_subscribe_cb(imquic_endpoint *endpoint,
		void (* incoming_subscribe)(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_subscribe = incoming_subscribe;
	}
}

void imquic_set_subscribe_accepted_cb(imquic_endpoint *endpoint,
		void (* subscribe_accepted)(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_accepted = subscribe_accepted;
	}
}

void imquic_set_subscribe_error_cb(imquic_endpoint *endpoint,
		void (* subscribe_error)(imquic_connection *conn, uint64_t subscribe_id, int error_codes, const char *reason, uint64_t track_alias)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_error = subscribe_error;
	}
}

void imquic_set_subscribe_done_cb(imquic_endpoint *endpoint,
		void (* subscribe_done)(imquic_connection *conn, uint64_t subscribe_id, int status_code, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_done = subscribe_done;
	}
}

void imquic_set_incoming_unsubscribe_cb(imquic_endpoint *endpoint,
		void (* incoming_unsubscribe)(imquic_connection *conn, uint64_t subscribe_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unsubscribe = incoming_unsubscribe;
	}
}

void imquic_set_incoming_subscribe_announces_cb(imquic_endpoint *endpoint,
		void (* incoming_subscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_auth_info *auth)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_subscribe_announces = incoming_subscribe_announces;
	}
}

void imquic_set_subscribe_announces_accepted_cb(imquic_endpoint *endpoint,
		void (* subscribe_announces_accepted)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_announces_accepted = subscribe_announces_accepted;
	}
}

void imquic_set_subscribe_announces_error_cb(imquic_endpoint *endpoint,
		void (* subscribe_announces_error)(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.subscribe_announces_error = subscribe_announces_error;
	}
}

void imquic_set_incoming_unsubscribe_announces_cb(imquic_endpoint *endpoint,
		void (* incoming_unsubscribe_announces)(imquic_connection *conn, imquic_moq_namespace *tns)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_unsubscribe_announces = incoming_unsubscribe_announces;
	}
}

void imquic_set_incoming_fetch_cb(imquic_endpoint *endpoint,
		void (* incoming_fetch)(imquic_connection *conn, uint64_t subscribe_id, imquic_moq_namespace *tns, imquic_moq_name *tn, gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_fetch = incoming_fetch;
	}
}

void imquic_set_incoming_fetch_cancel_cb(imquic_endpoint *endpoint,
		void (* incoming_fetch_cancel)(imquic_connection *conn, uint64_t subscribe_id)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_fetch_cancel = incoming_fetch_cancel;
	}
}

void imquic_set_fetch_accepted_cb(imquic_endpoint *endpoint,
		void (* fetch_accepted)(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.fetch_accepted = fetch_accepted;
	}
}

void imquic_set_fetch_error_cb(imquic_endpoint *endpoint,
		void (* fetch_error)(imquic_connection *conn, uint64_t subscribe_id, int error_codes, const char *reason)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.fetch_error = fetch_error;
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
		void (* incoming_goaway)(imquic_connection *conn, const char *uri)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.incoming_goaway = incoming_goaway;
	}
}

void imquic_set_moq_connection_gone_cb(imquic_endpoint *endpoint,
		void (* moq_connection_gone)(imquic_connection *conn)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set MoQ callback on non-MoQ endpoint\n");
			return;
		}
		endpoint->callbacks.moq.connection_gone = moq_connection_gone;
	}
}

/* Roles */
const char *imquic_moq_role_str(imquic_moq_role role) {
	switch(role) {
		case IMQUIC_MOQ_PUBLISHER:
			return "Publisher";
		case IMQUIC_MOQ_SUBSCRIBER:
			return "Subscriber";
		case IMQUIC_MOQ_PUBSUB:
			return "PubSub";
		default: break;
	}
	return NULL;
}

/* Versions */
const char *imquic_moq_version_str(imquic_moq_version version) {
	switch(version) {
		case IMQUIC_MOQ_VERSION_03:
			return "draft-ietf-moq-transport-03";
		case IMQUIC_MOQ_VERSION_04:
			return "draft-ietf-moq-transport-04";
		case IMQUIC_MOQ_VERSION_05:
			return "draft-ietf-moq-transport-05";
		case IMQUIC_MOQ_VERSION_06:
			return "draft-ietf-moq-transport-06";
		case IMQUIC_MOQ_VERSION_07:
			return "draft-ietf-moq-transport-07";
		case IMQUIC_MOQ_VERSION_07_PATCH:
			return "draft-ietf-moq-transport-07-PATCH";
		case IMQUIC_MOQ_VERSION_ANY:
			return "draft-ietf-moq-transport-XX";
		case IMQUIC_MOQ_VERSION_ANY_LEGACY:
			return "draft-ietf-moq-transport-XX(-pre-06)";
		default: break;
	}
	return NULL;
}

/* Delivery modes */
const char *imquic_moq_delivery_str(imquic_moq_delivery type) {
	switch(type) {
		case IMQUIC_MOQ_USE_DATAGRAM:
			return "OBJECT_DATAGRAM";
		case IMQUIC_MOQ_USE_STREAM:
			return "OBJECT_STREAM";
		case IMQUIC_MOQ_USE_GROUP:
			return "STREAM_HEADER_GROUP";
		case IMQUIC_MOQ_USE_SUBGROUP:
			return "STREAM_HEADER_SUBGROUP";
		case IMQUIC_MOQ_USE_TRACK:
			return "STREAM_HEADER_TRACK";
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
		case IMQUIC_MOQ_OBJECT_DOESNT_EXIST:
			return "OBJECT_DOESNT_EXIST";
		case IMQUIC_MOQ_END_OF_GROUP:
			return "END_OF_GROUP";
		case IMQUIC_MOQ_END_OF_TRACK_AND_GROUP:
			return "END_OF_TRACK_AND_GROUP";
		case IMQUIC_MOQ_END_OF_SUBGROUP:
			return "END_OF_SUBGROUP";
		default: break;
	}
	return NULL;
}