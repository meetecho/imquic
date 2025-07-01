/*! \file   imquic-roq.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic RoQ public interface
 * \details Public interface to the RTP Over QUIC (RoQ) native support
 * in the imquic library. This is where public functions are callbacks to
 * interact with the RoQ features of the library are defined.
 *
 * \ingroup RoQ Core
 */

#include "imquic/roq.h"
#include "internal/configuration.h"
#include "internal/connection.h"
#include "internal/roq.h"

#define IMQUIC_ROQ_ALPN		"roq-10"

/* Create a RoQ server */
imquic_server *imquic_create_roq_server(const char *name, ...) {
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
		} else if(property == IMQUIC_CONFIG_TLS_PASSWORD) {
			config.cert_pwd = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_EARLY_DATA) {
			config.early_data = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_TICKET_FILE) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_SUBPROTOCOL) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating RoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_SNI || property == IMQUIC_CONFIG_HTTP3_PATH) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ) {
			config.qlog_roq = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating RoQ endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_SEQUENTIAL) {
			config.qlog_sequential = va_arg(args, gboolean);
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
	/* Check if we need raw RoQ and/or RoQ over WebTransport */
	config.alpn = IMQUIC_ROQ_ALPN;
	if(config.webtransport) {
		if(!config.raw_quic)
			config.alpn = NULL;
 		config.subprotocol = IMQUIC_ROQ_ALPN;
	}
	/* Create the server */
	imquic_server *server = imquic_network_endpoint_create(&config);
	if(server == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	server->internal_callbacks = TRUE;
	server->protocol = IMQUIC_ROQ;
	server->new_connection = imquic_roq_new_connection;
	server->stream_incoming = imquic_roq_stream_incoming;
	server->datagram_incoming = imquic_roq_datagram_incoming;
	server->connection_gone = imquic_roq_connection_gone;
	return server;
}

/* Create a RoQ client */
imquic_client *imquic_create_roq_client(const char *name, ...) {
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
	config.qlog_quic = TRUE;
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
		} else if(property == IMQUIC_CONFIG_TLS_PASSWORD) {
			config.cert_pwd = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_EARLY_DATA) {
			config.early_data = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_TICKET_FILE) {
			config.ticket_file = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN || property == IMQUIC_CONFIG_SUBPROTOCOL) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating RoQ endpoints\n",
				imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_SNI) {
			config.sni = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_HTTP3_PATH) {
			config.h3_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ) {
			config.qlog_roq = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating RoQ endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_SEQUENTIAL) {
			config.qlog_sequential = va_arg(args, gboolean);
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
	/* Check if we need raw RoQ and/or RoQ over WebTransport */
	config.alpn = IMQUIC_ROQ_ALPN;
	if(config.webtransport) {
		if(!config.raw_quic)
			config.alpn = NULL;
 		config.subprotocol = IMQUIC_ROQ_ALPN;
	}
	/* Create the client */
	imquic_client *client = imquic_network_endpoint_create(&config);
	if(client == NULL)
		return NULL;
	/* Set our own callbacks for the endpoint, we'll expose different ones to the user */
	client->internal_callbacks = TRUE;
	client->protocol = IMQUIC_ROQ;
	client->new_connection = imquic_roq_new_connection;
	client->stream_incoming = imquic_roq_stream_incoming;
	client->datagram_incoming = imquic_roq_datagram_incoming;
	client->connection_gone = imquic_roq_connection_gone;
	return client;
}

/* Setting callbacks */
void imquic_set_new_roq_connection_cb(imquic_endpoint *endpoint,
		void (* new_roq_connection)(imquic_connection *conn, void *user_data)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_ROQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set RoQ callback on non-RoQ endpoint\n");
			return;
		}
		endpoint->callbacks.roq.new_connection = new_roq_connection;
	}
}

void imquic_set_rtp_incoming_cb(imquic_endpoint *endpoint,
		void (* rtp_incoming)(imquic_connection *conn, uint64_t flow_id, uint8_t *bytes, size_t blen)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_ROQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set RoQ callback on non-RoQ endpoint\n");
			return;
		}
		endpoint->callbacks.roq.rtp_incoming = rtp_incoming;
	}
}

void imquic_set_roq_connection_gone_cb(imquic_endpoint *endpoint,
		void (* roq_connection_gone)(imquic_connection *conn)) {
	if(endpoint != NULL) {
		if(endpoint->protocol != IMQUIC_ROQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't set RoQ callback on non-RoQ endpoint\n");
			return;
		}
		endpoint->callbacks.roq.connection_gone = roq_connection_gone;
	}
}

/* Delivery modes */
const char *imquic_roq_multiplexing_str(imquic_roq_multiplexing multiplexing) {
	switch(multiplexing) {
		case IMQUIC_ROQ_DATAGRAM:
			return "DATAGRAM";
		case IMQUIC_ROQ_STREAM:
			return "STREAM";
		default: break;
	}
	return NULL;
}
