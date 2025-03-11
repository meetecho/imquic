/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic RoQ server
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/roq.h>

#include "roq-server-options.h"

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

/* RTP header */
typedef struct imquic_rtp_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t csrccount:4;
	uint16_t markerbit:1;
	uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[0];
} imquic_rtp_header;
static gboolean imquic_is_rtp(uint8_t *buf, guint len) {
	if (len < 12)
		return FALSE;
	imquic_rtp_header *header = (imquic_rtp_header *)buf;
	return (header->version == 2 && ((header->type < 64) || (header->type >= 96)));
}

/* Debugging: printing the content of a hex buffer */
static void imquic_roq_print_hex(int level, uint8_t *buf, size_t buflen) {
	IMQUIC_LOG(level, "\t");
	for(size_t i=0; i<buflen; ++i)
		IMQUIC_LOG(level, "%02x", buf[i]);
	IMQUIC_LOG(level, "\n");
}

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	g_hash_table_insert(connections, conn, conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New RoQ connection\n", imquic_get_connection_name(conn));
}

static void imquic_demo_rtp_incoming(imquic_connection *conn, uint64_t flow_id, uint8_t *bytes, size_t blen) {
	/* The library gives us access to the RTP packet directly. no matter how it got there */
	if(!imquic_is_rtp(bytes, blen)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s]  -- [flow=%"SCNu64"][%zu] Not an RTP packet\n",
			imquic_get_connection_name(conn), flow_id, blen);
		imquic_roq_print_hex(IMQUIC_LOG_INFO, bytes, blen);
		return;
	}
	imquic_rtp_header *rtp = (imquic_rtp_header *)bytes;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- [flow=%"SCNu64"][%zu] ssrc=%"SCNu32", pt=%d, seq=%"SCNu16", ts=%"SCNu32"\n",
		imquic_get_connection_name(conn), flow_id, blen,
		ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] RoQ connection gone\n", imquic_get_connection_name(conn));
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
	if(options.early_data)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled\n");

	/* Initialize the library and create a server */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *server = imquic_create_roq_server("roq-server",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, (options.qlog_path != NULL),
		IMQUIC_CONFIG_EARLY_DATA, options.early_data,
		IMQUIC_CONFIG_DONE, NULL);
	if(server == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", imquic_get_endpoint_alpn(server));
	if(options.webtransport && imquic_get_endpoint_subprotocol(server) != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Subprotocol: %s\n", imquic_get_endpoint_subprotocol(server));
	imquic_set_new_roq_connection_cb(server, imquic_demo_new_connection);
	imquic_set_rtp_incoming_cb(server, imquic_demo_rtp_incoming);
	imquic_set_roq_connection_gone_cb(server, imquic_demo_connection_gone);
	connections = g_hash_table_new(NULL, NULL);
	imquic_start_endpoint(server);

	while(!stop)
		g_usleep(100000);

	imquic_shutdown_endpoint(server);

done:
	imquic_deinit();
	if(connections != NULL)
		g_hash_table_unref(connections);
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
