/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic QUIC/WebTransport echo-client
 *
 */

#include <imquic/imquic.h>

#include "echo-client-options.h"

/* Command line options */
static demo_options options = { 0 };

/* Our connection */
static imquic_connection *echo_conn = NULL;

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

static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	echo_conn = conn;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
	/* Send our text */
	const char *text = options.text ? options.text : "ciao";
	uint64_t stream_id = 0;
	imquic_new_stream_id(conn, TRUE, &stream_id);
	imquic_send_on_stream(conn, stream_id, (uint8_t *)text, 0, strlen(text), TRUE);
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
		for(size_t i=0; i<length; ++i)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "%02x", bytes[i]);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
	}
	if(complete)
		g_atomic_int_inc(&stop);
}

static void imquic_demo_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	/* Got incoming data via DATAGRAM */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] [DATAGRAM] Got data: %"SCNu64"\n", imquic_get_connection_name(conn), length);
	int len = length;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %.*s\n", len - 1, (char *)(bytes + 1));
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	if(conn == echo_conn)
		imquic_connection_unref(conn);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_demo_handle_signal);
	signal(SIGTERM, imquic_demo_handle_signal);

	IMQUIC_PRINT("imquic version %s\n", imquic_get_version_string_full());
	IMQUIC_PRINT("  -- %s (commit hash)\n", imquic_get_build_sha());
	IMQUIC_PRINT("  -- %s (build time)\n\n", imquic_get_build_time());

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
	if(options.remote_host == NULL || options.remote_port == 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid QUIC server address\n");
		ret = 1;
		goto done;
	}
	if(options.port > 65535) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid local port\n");
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
	if(options.ticket_file != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled (ticket file '%s')\n", options.ticket_file);

	/* Check if we need to create a QLOG file, and which we should save */
	gboolean qlog_quic = FALSE, qlog_http3 = FALSE;
	if(options.qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating QLOG file(s) in '%s'\n", options.qlog_path);
		if(options.qlog_sequential)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using sequential JSON\n");
		int i = 0;
		while(options.qlog_logging != NULL && options.qlog_logging[i] != NULL) {
			if(!strcasecmp(options.qlog_logging[i], "quic")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging QUIC events\n");
				qlog_quic = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "http3") && options.webtransport) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging HTTP/3 events\n");
				qlog_http3 = TRUE;
			}
			i++;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");

	/* Initialize the library and create a server */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_client *client = imquic_create_client("echo-client",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_REMOTE_HOST, options.remote_host,
		IMQUIC_CONFIG_REMOTE_PORT, options.remote_port,
		IMQUIC_CONFIG_SNI, options.sni,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_ALPN, options.alpn,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, (options.ticket_file != NULL),
		IMQUIC_CONFIG_TICKET_FILE, options.ticket_file,
		IMQUIC_CONFIG_HTTP3_PATH, options.path,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	imquic_set_new_connection_cb(client, imquic_demo_new_connection);
	imquic_set_stream_incoming_cb(client, imquic_demo_stream_incoming);
	imquic_set_datagram_incoming_cb(client, imquic_demo_datagram_incoming);
	imquic_set_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	while(!stop)
		g_usleep(100000);

	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
