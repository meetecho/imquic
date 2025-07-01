/*! \file   imquic.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic public interface
 * \details Public interface to the imquic library. This is where public
 * functions are callbacks to interact with the library are defined.
 *
 * \ingroup Core
 */

#include "imquic/imquic.h"
#include "internal/configuration.h"
#include "internal/quic.h"
#include "internal/loop.h"
#include "internal/crypto.h"
#include "internal/buffer.h"
#include "internal/qlog.h"
#include "internal/utils.h"
#include "internal/listmap.h"
#include "internal/version.h"
/* Protocols */
#include "internal/http3.h"
#include "internal/moq.h"
#include "internal/roq.h"

/* Logging */
int imquic_log_level = IMQUIC_LOG_VERB;
gboolean imquic_log_timestamps = FALSE;
gboolean imquic_log_colors = TRUE;
gboolean imquic_lock_debug = FALSE;
gboolean imquic_refcount_debug = FALSE;

#ifdef IMQUIC_REFCOUNT_DEBUG
/* Reference counters debugging */
GHashTable *imquic_counters = NULL;
imquic_mutex imquic_counters_mutex;
#endif

/* Initialize the library */
volatile int initialized = IMQUIC_NOT_INITIALIZED;
int imquic_init(const char *secrets_log) {
	if(!g_atomic_int_compare_and_exchange(&initialized, IMQUIC_NOT_INITIALIZED, IMQUIC_INITIALIZING)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic already initialized\n");
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Initializing imquic\n");
	/* Initialize the QUIC stack itself */
	imquic_quic_init();
	/* Initialize the TLS code */
	imquic_tls_init(secrets_log);
	/* Initialize the network stack */
	imquic_network_init();
	/* Register the protocols the library supports natively */
	imquic_moq_init();
	imquic_roq_init();
	/* Start the library thread/loop */
	if(imquic_loop_init() < 0)
		return -1;
	g_atomic_int_set(&initialized, IMQUIC_INITIALIZED);
	return 0;
}

gboolean imquic_is_inited(void) {
	return g_atomic_int_get(&initialized) == IMQUIC_INITIALIZED;
}

void imquic_deinit(void) {
	g_atomic_int_set(&initialized, IMQUIC_UNINITIALIZED);
	imquic_quic_deinit();
	imquic_network_deinit();
	imquic_moq_deinit();
	imquic_roq_deinit();
#ifdef IMQUIC_REFCOUNT_DEBUG
	/* Any reference counters that are still up while we're leaving? (debug-mode only) */
	imquic_mutex_lock(&imquic_counters_mutex);
	if(imquic_counters && g_hash_table_size(imquic_counters) > 0) {
		IMQUIC_PRINT("Debugging reference counters: %d still allocated\n", g_hash_table_size(imquic_counters));
		GHashTableIter iter;
		gpointer value;
		g_hash_table_iter_init(&iter, imquic_counters);
		while(g_hash_table_iter_next(&iter, NULL, &value)) {
			IMQUIC_PRINT("  -- %p\n", value);
		}
	} else {
		IMQUIC_PRINT("Debugging reference counters: 0 still allocated\n");
	}
	imquic_mutex_unlock(&imquic_counters_mutex);
#endif
}

/* Versioning */
uint32_t imquic_get_version(void) {
	uint32_t major = imquic_version_major;
	uint32_t minor = imquic_version_minor;
	uint32_t patch = imquic_version_patch;
	return (major << 24) + (minor << 16) + patch;
}
int imquic_get_version_major(void) {
	return imquic_version_major;
}
int imquic_get_version_minor(void) {
	return imquic_version_minor;
}
int imquic_get_version_patch(void) {
	return imquic_version_patch;
}
const char *imquic_get_version_release(void) {
	return imquic_version_release;
}
const char *imquic_get_version_string(void) {
	return imquic_version_string;
}
const char *imquic_get_version_string_full(void) {
	return imquic_version_string_full;
}
const char *imquic_get_build_time(void) {
	return imquic_build_git_time;
}
const char *imquic_get_build_sha(void) {
	return imquic_build_git_sha;
}

/* Logging */
void imquic_set_log_level(int level) {
	if(level < IMQUIC_LOG_NONE)
		level = IMQUIC_LOG_NONE;
	else if(level > IMQUIC_LOG_MAX)
		level = IMQUIC_LOG_MAX;
	imquic_log_level = level;
}

/* QLOG */
gboolean imquic_is_qlog_supported(void) {
	return imquic_qlog_is_supported();
}

/* Debugging */
void imquic_set_lock_debugging(gboolean enabled) {
	imquic_lock_debug = enabled;
}

void imquic_set_refcount_debugging(gboolean enabled) {
	imquic_refcount_debug = enabled;
}

/* Configuration */
const char *imquic_config_str(imquic_config type) {
	switch(type) {
		case IMQUIC_CONFIG_INIT:
			return "IMQUIC_CONFIG_INIT";
		case IMQUIC_CONFIG_LOCAL_BIND:
			return "IMQUIC_CONFIG_LOCAL_BIND";
		case IMQUIC_CONFIG_LOCAL_PORT:
			return "IMQUIC_CONFIG_LOCAL_PORT";
		case IMQUIC_CONFIG_REMOTE_HOST:
			return "IMQUIC_CONFIG_REMOTE_HOST";
		case IMQUIC_CONFIG_REMOTE_PORT:
			return "IMQUIC_CONFIG_REMOTE_PORT";
		case IMQUIC_CONFIG_TLS_CERT:
			return "IMQUIC_CONFIG_TLS_CERT";
		case IMQUIC_CONFIG_TLS_KEY:
			return "IMQUIC_CONFIG_TLS_KEY";
		case IMQUIC_CONFIG_TLS_PASSWORD:
			return "IMQUIC_CONFIG_TLS_PASSWORD";
		case IMQUIC_CONFIG_SNI:
			return "IMQUIC_CONFIG_SNI";
		case IMQUIC_CONFIG_ALPN:
			return "IMQUIC_CONFIG_ALPN";
		case IMQUIC_CONFIG_RAW_QUIC:
			return "IMQUIC_CONFIG_RAW_QUIC";
		case IMQUIC_CONFIG_WEBTRANSPORT:
			return "IMQUIC_CONFIG_WEBTRANSPORT";
		case IMQUIC_CONFIG_SUBPROTOCOL:
			return "IMQUIC_CONFIG_SUBPROTOCOL";
		case IMQUIC_CONFIG_DONE:
			return "IMQUIC_CONFIG_DONE";
		default:
			break;
	}
	return NULL;
}

/* Create a server */
imquic_server *imquic_create_server(const char *name, ...) {
	if(g_atomic_int_get(&initialized) != IMQUIC_INITIALIZED) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic not initialized\n");
		return NULL;
	}
	/* Traverse the variable arguments to build a configuration object */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Creating new server '%s'\n", name);
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
		} else if(property == IMQUIC_CONFIG_SNI) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN) {
			config.alpn = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_HTTP3_PATH) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating servers\n", imquic_config_str(property));
			va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_SUBPROTOCOL) {
			config.subprotocol = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating generic endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating generic endpoints\n", imquic_config_str(property));
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
	/* Create the server */
	return imquic_network_endpoint_create(&config);
}

/* Create a client */
imquic_client *imquic_create_client(const char *name, ...) {
	if(g_atomic_int_get(&initialized) != IMQUIC_INITIALIZED) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "imquic not initialized\n");
		return NULL;
	}
	/* Traverse the variable arguments to build a configuration object */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Creating new client '%s'\n", name);
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
		} else if(property == IMQUIC_CONFIG_SNI) {
			config.sni = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_ALPN) {
			config.alpn = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_RAW_QUIC) {
			config.raw_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_WEBTRANSPORT) {
			config.webtransport = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_HTTP3_PATH) {
			config.h3_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_SUBPROTOCOL) {
			config.subprotocol = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_PATH) {
			config.qlog_path = va_arg(args, char *);
		} else if(property == IMQUIC_CONFIG_QLOG_QUIC) {
			config.qlog_quic = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_HTTP3) {
			config.qlog_http3 = va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_ROQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating generic endpoints\n", imquic_config_str(property));
			va_arg(args, gboolean);
		} else if(property == IMQUIC_CONFIG_QLOG_MOQ) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "%s is ignored when creating generic endpoints\n", imquic_config_str(property));
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
	/* Create the client */
	return imquic_network_endpoint_create(&config);
}

/* Endpoints management */
const char *imquic_get_endpoint_name(imquic_endpoint *endpoint) {
	return endpoint ? (const char *)endpoint->name : NULL;
}

gboolean imquic_is_endpoint_server(imquic_endpoint *endpoint) {
	return endpoint ? endpoint->is_server : FALSE;
}

const char *imquic_get_endpoint_alpn(imquic_endpoint *endpoint) {
	return endpoint ? (const char *)endpoint->alpn : NULL;
}

const char *imquic_get_endpoint_subprotocol(imquic_endpoint *endpoint) {
	return endpoint ? (const char *)endpoint->subprotocol : NULL;
}

uint16_t imquic_get_endpoint_port(imquic_endpoint *endpoint) {
	return endpoint ? endpoint->port : 0;
}

void imquic_start_endpoint(imquic_endpoint *endpoint) {
	if(endpoint && g_atomic_int_compare_and_exchange(&endpoint->started, 0, 1)) {
		if(endpoint->is_server) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Starting server\n", endpoint->name);
			imquic_loop_poll_endpoint(endpoint);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connecting to remote endpoint\n", endpoint->name);
			imquic_loop_poll_endpoint(endpoint);
			/* Start the QUIC stack */
			imquic_start_quic_client(endpoint);
		}
	}
}

void imquic_shutdown_endpoint(imquic_endpoint *endpoint) {
	if(endpoint && g_atomic_int_compare_and_exchange(&endpoint->shutting, 0, 1)) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Shutting down %s\n",
			endpoint->name, endpoint->is_server ? "server" : "client");
		imquic_network_endpoint_shutdown(endpoint);
	}
}

/* Setting callbacks */
void imquic_set_new_connection_cb(imquic_endpoint *endpoint,
		void (* new_connection)(imquic_connection *conn, void *user_data)) {
	if(endpoint != NULL) {
		if(endpoint->internal_callbacks) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't seq QUIC callback when using specific protocol handler\n");
		} else {
			endpoint->new_connection = new_connection;
		}
	}
}

void imquic_set_stream_incoming_cb(imquic_endpoint *endpoint,
		void (* stream_incoming)(imquic_connection *conn, uint64_t stream_id,
			uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete)) {
	if(endpoint != NULL) {
		if(endpoint->internal_callbacks) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't seq QUIC callback when using specific protocol handler\n");
		} else {
			endpoint->stream_incoming = stream_incoming;
		}
	}
}

void imquic_set_datagram_incoming_cb(imquic_endpoint *endpoint,
		void (* datagram_incoming)(imquic_connection *conn, uint8_t *bytes, uint64_t length)) {
	if(endpoint != NULL) {
		if(endpoint->internal_callbacks) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't seq QUIC callback when using specific protocol handler\n");
		} else {
			endpoint->datagram_incoming = datagram_incoming;
		}
	}
}

void imquic_set_connection_gone_cb(imquic_endpoint *endpoint,
		void (* connection_gone)(imquic_connection *conn)) {
	if(endpoint != NULL) {
		if(endpoint->internal_callbacks) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Can't seq QUIC callback when using specific protocol handler\n");
		} else {
			endpoint->connection_gone = connection_gone;
		}
	}
}

/* FIXME Interacting with connections */
int  imquic_send_on_stream(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	if(conn == NULL)
		return -1;
	if(imquic_connection_send_on_stream(conn, stream_id, bytes, offset, length, complete) < 0)
		return -1;
	imquic_connection_flush_stream(conn, stream_id);
	return 0;
}

int imquic_send_on_datagram(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	if(conn == NULL)
		return -1;
	return imquic_connection_send_on_datagram(conn, bytes, length);
}

const char *imquic_get_connection_alpn(imquic_connection *conn) {
	return (const char *)(conn && conn->socket ? conn->socket->alpn : NULL);
}

const char *imquic_get_connection_name(imquic_connection *conn) {
	return (const char *)(conn ? conn->name : NULL);
}

int imquic_new_stream_id(imquic_connection *conn, gboolean bidirectional, uint64_t *stream_id) {
	return imquic_connection_new_stream_id(conn, bidirectional, stream_id);
}

void imquic_close_connection(imquic_connection *conn, uint64_t error, const char *reason) {
	/* FIXME */
	imquic_connection_close(conn, error, 0, reason);
}

/* References */
void imquic_connection_ref(imquic_connection *conn) {
	if(conn)
		imquic_refcount_increase(&conn->ref);
}

void imquic_connection_unref(imquic_connection *conn) {
	if(conn)
		imquic_refcount_decrease(&conn->ref);
}

/* Reading and writing Stream ID */
void imquic_stream_id_parse(uint64_t stream_id, uint64_t *id, gboolean *client_initiated, gboolean *bidirectional) {
	imquic_parse_stream_id(stream_id, id, client_initiated, bidirectional);
}

uint64_t imquic_stream_id_build(uint64_t id, gboolean client_initiated, gboolean bidirectional) {
	return imquic_build_stream_id(id, client_initiated, bidirectional);
}

/* Reading and writing variable size integers */
uint64_t imquic_varint_read(uint8_t *bytes, size_t blen, uint8_t *length) {
	return imquic_read_varint(bytes, blen, length);
}

uint8_t imquic_varint_write(uint64_t number, uint8_t *bytes, size_t blen) {
	return imquic_write_varint(number, bytes, blen);
}

/* Utilities to use 64-bit integers as parts of lists and hashtables */
uint64_t imquic_uint64_random(void) {
	return imquic_random_uint64();
}

uint64_t *imquic_uint64_dup(uint64_t num) {
	return imquic_dup_uint64(num);
}
