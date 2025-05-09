/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic RoQ client
 *
 */

#include <arpa/inet.h>
#include <sys/socket.h>
#if defined (__MACH__) || defined(__FreeBSD__)
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif
#include <unistd.h>
#include <poll.h>

#include <imquic/imquic.h>
#include <imquic/roq.h>

#include "roq-client-options.h"

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
	return ((header->type < 64) || (header->type >= 96));
}

/* Our connection */
static imquic_connection *roq_conn = NULL;

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New connection\n", imquic_get_connection_name(conn));
	roq_conn = conn;
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection gone\n", imquic_get_connection_name(conn));
	if(conn == roq_conn)
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
	options.audio_flow = -1;
	options.audio_port = -1;
	options.video_flow = -1;
	options.video_port = -1;
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

	int ret = 0, audio_fd = -1, video_fd = -1;
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
	if(options.ticket_file != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled (ticket file '%s')\n", options.ticket_file);
	if(options.audio_port <= 0 && options.video_port <= 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "No local audio/video RTP port specified\n");
		ret = 1;
		goto done;
	}
	if(options.audio_port > 0 && options.audio_flow < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid audio flow ID\n");
		ret = 1;
		goto done;
	}
	if(options.video_port > 0 && options.video_flow < 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid video flow ID\n");
		ret = 1;
		goto done;
	}
	if(options.audio_port > 0 && options.video_port > 0 && options.audio_flow == options.video_flow) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Audio and video flow IDs must be different\n");
		ret = 1;
		goto done;
	}
	/* Since this is a RoQ server, we use a static ALPN */
	imquic_roq_multiplexing multiplexing;
	const char *mode = NULL;
	gboolean one_stream_per_packet = FALSE;
	if(options.multiplexing == NULL || !strcasecmp(options.multiplexing, "datagram")) {
		multiplexing = IMQUIC_ROQ_DATAGRAM;
		mode = "DATAGRAM";
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Multiplexing: DATAGRAM\n");
	} else if(!strcasecmp(options.multiplexing, "stream")) {
		multiplexing = IMQUIC_ROQ_STREAM;
		mode = "STREAM";
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Multiplexing: one STREAM per flow\n");
	} else if(!strcasecmp(options.multiplexing, "streams")) {
		multiplexing = IMQUIC_ROQ_STREAM;
		mode = "STREAMS";
		one_stream_per_packet = TRUE;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Multiplexing: one STREAM per RTP packet\n");
	} else {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported multiplexing mode '%s'\n", options.multiplexing);
		ret = 1;
		goto done;
	}

	/* Create the audio and/or video sockets */
	if(options.audio_port > 0) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Audio: port %d, flow ID %d\n", options.audio_port, options.audio_flow);
		audio_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		struct sockaddr_in address = { 0 };
		address.sin_family = AF_INET;
		address.sin_port = g_htons(options.audio_port);
		address.sin_addr.s_addr = INADDR_ANY;
		if(bind(audio_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Bind to audio port '%"SCNu16" failed... %d (%s)\n",
				options.audio_port, errno, g_strerror(errno));
			ret = 1;
			goto done;
		}
	}
	if(options.video_port > 0) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Video: port %d, flow ID %d\n", options.video_port, options.video_flow);
		video_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		struct sockaddr_in address = { 0 };
		address.sin_family = AF_INET;
		address.sin_port = g_htons(options.video_port);
		address.sin_addr.s_addr = INADDR_ANY;
		if(bind(video_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Bind to video port '%"SCNu16" failed... %d (%s)\n",
				options.video_port, errno, g_strerror(errno));
			ret = 1;
			goto done;
		}
	}

	/* Check if we need to create a QLOG file */
	gboolean qlog_quic = FALSE, qlog_http3 = FALSE, qlog_roq = FALSE;
	if(options.qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating QLOG file '%s'\n", options.qlog_path);
		if(options.qlog_sequential)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using sequential JSON\n");
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging QUIC events\n");
		int i = 0;
		while(options.qlog_logging != NULL && options.qlog_logging[i] != NULL) {
			if(!strcasecmp(options.qlog_logging[i], "quic")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging QUIC events\n");
				qlog_quic = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "http3") && options.webtransport) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging HTTP/3 events\n");
				qlog_http3 = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "roq")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging RoQ events\n");
				qlog_roq = TRUE;
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
	imquic_client *client = imquic_create_roq_client("roq-client",
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
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, (options.ticket_file != NULL),
		IMQUIC_CONFIG_TICKET_FILE, options.ticket_file,
		IMQUIC_CONFIG_HTTP3_PATH, options.path,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_ROQ, qlog_roq,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", imquic_get_endpoint_alpn(client));
	if(options.webtransport && imquic_get_endpoint_subprotocol(client) != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Subprotocol: %s\n", imquic_get_endpoint_subprotocol(client));
	imquic_set_new_roq_connection_cb(client, imquic_demo_new_connection);
	imquic_set_roq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	/* Wait for incoming RTP packets */
	socklen_t addrlen;
	struct sockaddr_storage remote;
	int resfd = 0, bytes = 0, num = 0, i = 0;
	struct pollfd fds[2];
	uint8_t buffer[1500];
	size_t sent = 0;
	int64_t now = g_get_monotonic_time(), before = now;
	uint64_t flow_id = 0;
	/* Loop */
	while(!g_atomic_int_get(&stop)) {
		now = g_get_monotonic_time();
		if(now - before >= 5*G_USEC_PER_SEC) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "5 seconds with no RTP traffic, shutting down...\n");
			break;
		}
		num = 0;
		if(audio_fd != -1) {
			fds[num].fd = audio_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(video_fd != -1) {
			fds[num].fd = video_fd;
			fds[num].events = POLLIN;
			fds[num].revents = 0;
			num++;
		}
		if(num == 0)
			break;
		/* Wait for some data */
		resfd = poll(fds, num, 100);
		if(resfd < 0) {
			if(errno == EINTR) {
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "Got an EINTR (%s), ignoring...\n", g_strerror(errno));
				continue;
			}
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error polling... %d (%s)\n", errno, g_strerror(errno));
			break;
		}
		for(i=0; i<num; i++) {
			if(fds[i].revents & (POLLERR | POLLHUP)) {
				/* Socket error? */
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error polling %s RTP socket: %s... %d (%s)\n",
					fds[i].fd == audio_fd ? "audio" : "video",
					fds[i].revents & POLLERR ? "POLLERR" : "POLLHUP", errno, g_strerror(errno));
				if(fds[i].fd == audio_fd) {
					close(audio_fd);
					audio_fd = -1;
				} else {
					close(video_fd);
					video_fd = -1;
				}
				continue;
			} else if(fds[i].revents & POLLIN) {
				/* Got an RTP packet */
				addrlen = sizeof(remote);
				bytes = recvfrom(fds[i].fd, buffer, 1500, 0, (struct sockaddr *)&remote, &addrlen);
				if(bytes < 0 || !imquic_is_rtp(buffer, bytes)) {
					/* Failed to read or not an RTP packet? */
					continue;
				}
				before = g_get_monotonic_time();
				if(roq_conn != NULL) {
					/* Send the RTP packet using the specified multiplexing mode */
					flow_id = (fds[i].fd == audio_fd ? options.audio_flow : options.video_flow);
					sent = imquic_roq_send_rtp(roq_conn, multiplexing, flow_id, buffer, bytes, one_stream_per_packet);
					if(sent == 0) {
						IMQUIC_LOG(IMQUIC_LOG_WARN, "Couldn't send RTP packet...\n");
					} else {
						imquic_rtp_header *rtp = (imquic_rtp_header *)buffer;
						IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- [%s][flow=%"SCNu64"][%d] ssrc=%"SCNu32", pt=%"SCNu16", seq=%"SCNu16", ts=%"SCNu32"\n",
							mode, flow_id, bytes, ntohl(rtp->ssrc), rtp->type, ntohs(rtp->seq_number), ntohl(rtp->timestamp));
					}
				}
			}
		}
	}

	/* We're done */
	imquic_shutdown_endpoint(client);

done:
	if(audio_fd > -1)
		close(audio_fd);
	if(video_fd > -1)
		close(video_fd);
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
