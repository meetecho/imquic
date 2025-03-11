/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic QUIC/WebTransport echo-server
 *
 */

#include <imquic/imquic.h>

#include "echo-server-options.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping server, please wait...\n");
			break;
		case 1:
			IMQUIC_PRINT("In a hurry? I'm trying to free resources cleanly, here!\n");
			break;
		default:
			IMQUIC_PRINT("Ok, leaving immediately...\n");
			break;
	}
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
}

/* Handled connections */
static GHashTable *connections = NULL;

static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	g_hash_table_insert(connections, conn, conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
}

static void imquic_demo_stream_incoming(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	/* Got incoming data via STREAM */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] [STREAM-%"SCNu64"] Got data: %"SCNu64"--%"SCNu64" (%s)\n",
		imquic_get_connection_name(conn),
		stream_id, offset, offset+length, (complete ? "complete" : "not complete"));
	if(length > 0) {
		int len = length;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %.*s\n", len, (char *)(bytes));
	}
	/* FIXME Send it back */
	imquic_send_on_stream(conn, stream_id, bytes, offset, length, complete);
}

static void imquic_demo_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	/* Got incoming data via DATAGRAM */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] [DATAGRAM] Got data: %"SCNu64"\n", imquic_get_connection_name(conn), length);
	int len = length;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %.*s\n", len - 1, (char *)(bytes + 1));
	/* FIXME Send it back */
	imquic_send_on_datagram(conn, bytes, length);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	if(g_hash_table_remove(connections, conn))
		imquic_connection_unref(conn);
}

int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_demo_handle_signal);
	signal(SIGTERM, imquic_demo_handle_signal);

	IMQUIC_PRINT("imquic version %s\n", imquic_get_version_string_full());
	IMQUIC_PRINT("  -- %s (commit hash)\n", imquic_get_build_sha());
	IMQUIC_PRINT("  -- %s (build time)\n", imquic_get_build_time());

	/* Initialize some command line options defaults */
	options.debug_level = IMQUIC_LOG_INFO;
	/* Let's call our cmdline parser */
	if(!demo_options_parse(&options, argc, argv)) {
		demo_options_show_usage();
		demo_options_destroy();
		exit(1);
	}
	/* Logging level */
	imquic_set_log_level(options.debug_level);
	/* Debugging */
	if(options.debug_locks)
		imquic_set_lock_debugging(TRUE);
	if(options.debug_refcounts)
		imquic_set_refcount_debugging(TRUE);

	int ret = 0;
	if(options.cert_pem == NULL || strlen(options.cert_pem) == 0 || options.cert_key == NULL || strlen(options.cert_key) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing certificate/key\n");
		ret = 1;
		goto done;
	}
	if(options.port > 65535) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid port\n");
		ret = 1;
		goto done;
	}
	if(!options.raw_quic && !options.webtransport) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "No raw QUIC or WebTransport enabled (enable at least one)\n");
		ret = 1;
		goto done;
	}
	if(options.raw_quic) {
		if(options.alpn == NULL || strlen(options.alpn) == 0) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing ALPN to negotiate\n");
			ret = 1;
			goto done;
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", options.alpn);
	}
	if(options.early_data)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled\n");

	/* Initialize the library and create a server */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *server = imquic_create_server("echo-server",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_ALPN, options.alpn,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, options.early_data,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, (options.qlog_path != NULL),
		IMQUIC_CONFIG_DONE, NULL);
	if(server == NULL) {
		ret = 1;
		goto done;
	}
	imquic_set_new_connection_cb(server, imquic_demo_new_connection);
	imquic_set_stream_incoming_cb(server, imquic_demo_stream_incoming);
	imquic_set_datagram_incoming_cb(server, imquic_demo_datagram_incoming);
	imquic_set_connection_gone_cb(server, imquic_demo_connection_gone);
	connections = g_hash_table_new(NULL, NULL);
	imquic_start_endpoint(server);

	while(!stop)
		g_usleep(100000);

	imquic_shutdown_endpoint(server);

done:
	imquic_deinit();
	g_hash_table_unref(connections);
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
