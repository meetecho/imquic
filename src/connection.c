/*! \file   connection.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC connection abstraction
 * \details Abstraction of QUIC connections, during or after establishment.
 * This is where helper functions are exposed to the QUIC stack internals
 * for the purpose of creating STREAM ids, send data, and notify upper
 * layers about incoming data or shutdowns.
 *
 * \ingroup Core
 */

#include "internal/quic.h"
#include "internal/connection.h"
#include "internal/stream.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Connection ID utilities */
const char *imquic_connection_id_str(imquic_connection_id *cid, char *buffer, size_t blen) {
	if(cid == NULL || cid->len == 0 || blen == 0)
		return NULL;
	if(cid->len*2 >= blen) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render connection ID as a string (truncation would occur)\n");
		return NULL;
	}
	*buffer = '\0';
	char hex[3];
	size_t offset = 0;
	for(size_t i=0; i<cid->len; i++) {
		g_snprintf(hex, sizeof(hex), "%02x", cid->id[i]);
		imquic_strlcat_fast(buffer, hex, blen, &offset);
	}
	return buffer;
}

imquic_connection_id *imquic_connection_id_dup(imquic_connection_id *cid) {
	if(cid == NULL)
		return NULL;
	imquic_connection_id *dup = g_malloc(sizeof(imquic_connection_id));
	memcpy(dup, cid, sizeof(imquic_connection_id));
	return dup;
}

gboolean imquic_connection_id_equal(const void *a, const void *b) {
	const imquic_connection_id *cid_a = (imquic_connection_id *)a;
	const imquic_connection_id *cid_b = (imquic_connection_id *)b;
	if(!a || !b || cid_a->len != cid_b->len)
		return FALSE;
	for(size_t i=0; i<cid_a->len; i++) {
		if(cid_a->id[i] != cid_b->id[i])
			return FALSE;
	}
	return TRUE;
}

guint imquic_connection_id_hash(gconstpointer v) {
	/* Basically the same as g_str_hash, but on the ID content */
	imquic_connection_id *cid = (imquic_connection_id *)v;
	guint32 hash = 5381;
	for(size_t i=0; i<cid->len; i++)
		hash = (hash << 5) + hash + cid->id[i];
	return hash;
}

/* QUIC Transport parameters */
void imquic_connection_parameters_init(imquic_connection_parameters *params) {
	if(params == NULL)
		return;
	/* Set defaults as per https://datatracker.ietf.org/doc/html/rfc9000#transport-parameter-definitions */
	memset(params, 0, sizeof(*params));
	params->max_udp_payload_size = 65527;
	params->ack_delay_exponent = 3;
	params->max_ack_delay = 25;
	params->active_connection_id_limit = 2;
}

/* Idle timeout monitoring */
static gboolean imquic_connection_idle_timeout(gpointer user_data) {
	imquic_connection *conn = (imquic_connection *)user_data;
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return G_SOURCE_REMOVE;
	int64_t max_idle_timeout = conn->local_params.max_idle_timeout;
	if(conn->remote_params.max_idle_timeout > 0 && conn->remote_params.max_idle_timeout < max_idle_timeout)
		max_idle_timeout = conn->remote_params.max_idle_timeout;
	int64_t now = g_get_monotonic_time();
	if(now > (conn->last_activity + (max_idle_timeout*1000))) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Max idle timeout expired (%"SCNi64"ms)\n",
			imquic_get_connection_name(conn), max_idle_timeout);
		imquic_connection_close(conn, IMQUIC_NO_ERROR, 0, "Max idle timeout expired");
		return G_SOURCE_REMOVE;
	}
	return G_SOURCE_CONTINUE;
}

/* Connection initialization */
static void imquic_connection_free(const imquic_refcount *conn_ref) {
	imquic_connection *conn = imquic_refcount_containerof(conn_ref, imquic_connection, ref);
	g_free(conn->name);
	g_free(conn->alpn.buffer);
	g_list_free(conn->connection_ids);
	g_hash_table_unref(conn->streams);
	g_hash_table_unref(conn->streams_done);
	g_queue_free_full(conn->incoming_data, (GDestroyNotify)g_free);
	g_queue_free_full(conn->outgoing_data, (GDestroyNotify)g_free);
	g_queue_free_full(conn->outgoing_datagram, (GDestroyNotify)g_free);
	imquic_listmap_destroy(conn->blocked_streams);
	if(conn->ld_timer != NULL)
		g_source_destroy((GSource *)conn->ld_timer);
	if(conn->idle_timer != NULL)
		g_source_destroy((GSource *)conn->idle_timer);
	enum ssl_encryption_level_t level;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		imquic_listmap_destroy(conn->sent_pkts[level]);
		g_list_free_full(conn->recvd[level], (GDestroyNotify)g_free);
		imquic_buffer_destroy(conn->crypto_in[level]);
		imquic_buffer_destroy(conn->crypto_out[level]);
	}
	if(conn->ssl != NULL)
		SSL_free(conn->ssl);
	imquic_http3_connection_destroy(conn->http3);
	if(conn->socket != NULL)
		imquic_refcount_decrease(&conn->socket->ref);
	free(conn);
}

imquic_connection *imquic_connection_create(imquic_network_endpoint *socket) {
	if(socket == NULL)
		return NULL;
	/* FIXME */
	imquic_connection *conn = g_malloc0(sizeof(imquic_connection));
	imquic_mutex_lock(&socket->mutex);
	uint64_t id = ++socket->conns_num;
	imquic_mutex_unlock(&socket->mutex);
	char name[200];
	g_snprintf(name, sizeof(name), "%s/%"SCNu64, socket->name, id);
	conn->name = g_strdup(name);
	conn->just_started = TRUE;
	conn->is_server = socket->is_server;
	conn->socket = socket;
	imquic_refcount_increase(&socket->ref);
	conn->level = ssl_encryption_initial;
	enum ssl_encryption_level_t level;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		conn->sent_pkts[level] = imquic_listmap_create(IMQUIC_LISTMAP_NUMBER64, (GDestroyNotify)imquic_sent_packet_destroy);
	}
	/* Initialize local and remote parameters: we add a few defaults to the local ones too */
	imquic_connection_parameters_init(&conn->local_params);
	imquic_connection_parameters_init(&conn->remote_params);
	/* FIXME Maybe these should be configurable */
	conn->local_params.max_idle_timeout = 60000;
	conn->local_params.active_connection_id_limit = 8;
	conn->local_params.initial_max_streams_bidi = 128;
	conn->local_params.initial_max_streams_uni = 128;
	conn->local_params.initial_max_data = 1048576;
	conn->local_params.initial_max_stream_data_bidi_remote = 1048576;
	conn->local_params.initial_max_stream_data_bidi_local = 1048576;
	conn->local_params.initial_max_stream_data_uni = 1048576;
	conn->local_params.max_udp_payload_size = 1472;
	conn->local_params.max_datagram_frame_size = 65535;
	/* FIXME Flow control */
	conn->flow_control.local_max_data = conn->local_params.initial_max_data;
	conn->flow_control.local_max_streams_bidi = conn->local_params.initial_max_streams_bidi;
	conn->flow_control.local_max_streams_uni = conn->local_params.initial_max_streams_uni;
	/* RTT initialization */
	conn->rtt.smoothed = 333;	/* FIXME Default in RFC 9002 */
	conn->rtt.rttvar = conn->rtt.smoothed / 2;
	/* Streams map */
	conn->streams = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_stream_destroy);
	conn->streams_done = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	conn->incoming_data = g_queue_new();
	conn->outgoing_data = g_queue_new();
	conn->outgoing_datagram = g_queue_new();
	conn->blocked_streams = imquic_listmap_create(IMQUIC_LISTMAP_NUMBER64, (GDestroyNotify)g_free);
	/* We'll set the ALPN(s) manually: 1 byte prefix + the string itself for each of them */
	size_t length = 0, offset = 0, alpn_len = 0;
	if(conn->socket->raw_quic) {
		alpn_len = strlen(conn->socket->alpn);
		length = alpn_len + 1;
	}
	if(conn->socket->webtransport)
		length += 3;	/* h3 */
	conn->alpn.length = length;
	conn->alpn.buffer = g_malloc(conn->alpn.length);
	if(conn->socket->raw_quic) {
		conn->alpn.buffer[0] = alpn_len;
		memcpy(conn->alpn.buffer + 1, conn->socket->alpn, alpn_len);
		offset = alpn_len + 1;
	}
	if(conn->socket->webtransport) {
		conn->alpn.buffer[offset] = 2;
		memcpy(conn->alpn.buffer + offset + 1, "h3", 2);
	}
	imquic_refcount_init(&conn->ref, imquic_connection_free);
	imquic_network_endpoint_add_connection(conn->socket, conn, TRUE);
	conn->loop_source = imquic_loop_poll_connection(conn);
#ifdef HAVE_QLOG
	/* Check if we need to generate a QLOG file */
	if(conn->socket->qlog_path != NULL) {
		if(conn->is_server) {
			char filename[1024];
			g_snprintf(filename, sizeof(filename), "%s/imquic-%"SCNi64"-%"SCNu64".%s",
				conn->socket->qlog_path, g_get_real_time(), id,
				conn->socket->qlog_sequential ? "sqlog" : "qlog");
			conn->qlog = imquic_qlog_create(conn->name, conn->socket->qlog_sequential,
				TRUE, filename, conn->socket->qlog_quic,
				conn->socket->qlog_http3, conn->socket->qlog_roq, conn->socket->qlog_moq);
		} else {
			conn->qlog = imquic_qlog_create(conn->name, conn->socket->qlog_sequential,
				FALSE, (char *)conn->socket->qlog_path, conn->socket->qlog_quic,
				conn->socket->qlog_http3, conn->socket->qlog_roq, conn->socket->qlog_moq);
		}
	}
#endif
	conn->last_activity = g_get_monotonic_time();
	conn->idle_timer = imquic_loop_add_timer(1000, imquic_connection_idle_timeout, conn);
	return conn;
}

void imquic_connection_destroy(imquic_connection *conn) {
	if(conn && g_atomic_int_compare_and_exchange(&conn->destroyed, 0, 1)) {
		if(conn->loop_source != NULL) {
			g_source_destroy((GSource *)conn->loop_source);
			g_source_unref((GSource *)conn->loop_source);
			conn->loop_source = NULL;
		}
		if(conn->connection_ids != NULL) {
			GList *temp = conn->connection_ids;
			while(temp) {
				imquic_connection_id *cid = (imquic_connection_id *)temp->data;
				imquic_quic_connection_remove(cid);
				g_free(cid);
				temp = temp->next;
			}
			g_list_free(conn->connection_ids);
			conn->connection_ids = NULL;
		}
#ifdef HAVE_QLOG
		if(conn->qlog != NULL) {
			imquic_qlog_destroy(conn->qlog);
			conn->qlog = NULL;
		}
#endif
		imquic_refcount_decrease(&conn->ref);
	}
}

/* Helper to change the current encryption level, optionally resetting state
 * https://datatracker.ietf.org/doc/html/rfc9002#section-a.11 */
void imquic_connection_change_level(imquic_connection *conn, enum ssl_encryption_level_t level) {
	if(conn == NULL || conn->level >= level)
		return;
	/* FIXME Check if we need to reset the loss detection state for the
	 * previous level, and in case drop the packets we sent back there */
	if(conn->is_server && conn->level == ssl_encryption_initial) {
		imquic_listmap_clear(conn->sent_pkts[conn->level]);
		conn->ack_eliciting_in_flight[conn->level] = 0;
		conn->last_ack_eliciting_time[conn->level] = 0;
		conn->loss_time[conn->level] = 0;
		conn->pto_count = 0;
		imquic_connection_update_loss_timer(conn);
	}
	/* Set the new level */
	conn->level = level;
}

/* Helper to update the RTT
 * https://quicwg.org/base-drafts/rfc9002.html#appendix-A.7 */
void imquic_connection_update_rtt(imquic_connection *conn, int64_t sent_time, uint16_t ack_delay) {
	if(conn == NULL)
		return;
	int64_t now = g_get_monotonic_time();
	if(now < sent_time)
		return;
	/* Update the latest RTT */
	conn->rtt.latest = (now - sent_time)/1000;
	if(conn->rtt.first_sample == 0) {
		/* This is the first RTT sample */
		conn->rtt.min = conn->rtt.latest;
		conn->rtt.smoothed = conn->rtt.latest;
		conn->rtt.rttvar = conn->rtt.smoothed / 2;
		conn->rtt.first_sample = now;
		return;
	}
	if(conn->rtt.latest < conn->rtt.min)
		conn->rtt.min = conn->rtt.latest;
	if(conn->connected && conn->remote_params.max_ack_delay > 0 &&
			conn->remote_params.max_ack_delay < ack_delay)
		ack_delay = conn->remote_params.max_ack_delay;
	/* Adjust the RTT */
	uint16_t adjusted_rtt = conn->rtt.latest;
	if(conn->rtt.latest >= conn->rtt.min + ack_delay)
		adjusted_rtt -= ack_delay;
	/* Now compute smoothed and rttvar */
	uint16_t diff = conn->rtt.smoothed > adjusted_rtt ?
		(conn->rtt.smoothed - adjusted_rtt) : (adjusted_rtt - conn->rtt.smoothed);
	double rttvar = 0.75 * (double)(conn->rtt.latest) + 0.25 * (double)(diff);
	conn->rtt.rttvar = rttvar;
	double smoothed = 0.875 * (double)(conn->rtt.smoothed) + 0.125 * (double)(adjusted_rtt);
	conn->rtt.smoothed = smoothed;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][RTT] latest=%"SCNu16" (%"SCNu16"), min=%"SCNu16", smoothed=%"SCNu16", var=%"SCNu16"\n",
		imquic_get_connection_name(conn), conn->rtt.latest, adjusted_rtt, conn->rtt.min, conn->rtt.smoothed, conn->rtt.rttvar);
}

/* Helper to get the next PTO timeout (GetPtoTimeAndSpace)
 * https://quicwg.org/base-drafts/rfc9002.html#appendix-A.8 */
static int64_t imquic_connection_get_pto_timeout(imquic_connection *conn) {
	if(conn == NULL)
		return 0;
	uint16_t rttvar = conn->rtt.rttvar ? conn->rtt.rttvar : 1;
	uint32_t duration = (conn->rtt.smoothed + (4 * rttvar)) * (1 << conn->pto_count);
	int64_t pto_timeout = G_MAXINT64;
	enum ssl_encryption_level_t level;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		if(!conn->ack_eliciting_in_flight[level] || conn->last_ack_eliciting_time[level] == 0)
			continue;
		if(level == ssl_encryption_application) {
			if(!conn->connected)
				return pto_timeout;
			duration += conn->remote_params.max_ack_delay * (1 << conn->pto_count);
		}
		int64_t t = conn->last_ack_eliciting_time[level] + duration*1000;
		if(t < pto_timeout)
			pto_timeout = t;
	}
	return pto_timeout;
}

/* Helper to update the loss detection timer
 * https://quicwg.org/base-drafts/rfc9002.html#appendix-A.8 */
void imquic_connection_update_loss_timer(imquic_connection *conn) {
	if(conn == NULL)
		return;
	if(conn->ld_timer != NULL)
		g_source_destroy((GSource *)conn->ld_timer);
	conn->ld_timer = NULL;
	int64_t now = g_get_monotonic_time();
	/* GetLossTimeAndSpace */
	int64_t tm = conn->loss_time[ssl_encryption_initial];
	if(tm == 0 || (conn->loss_time[ssl_encryption_handshake] > 0 && conn->loss_time[ssl_encryption_handshake] < tm))
		tm = conn->loss_time[ssl_encryption_handshake];
	if(tm == 0 || (conn->loss_time[ssl_encryption_application] > 0 && conn->loss_time[ssl_encryption_application] < tm))
		tm = conn->loss_time[ssl_encryption_application];
	if(tm > 0) {
		/* FIXME Time threshold loss detection */
		int64_t timeout = (tm > now ? (tm - now) : 0) / 1000;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][TTLD] Setting next timeout in %"SCNi64"ms\n",
			imquic_get_connection_name(conn), timeout);
		conn->ld_timer = imquic_loop_add_timer(timeout, imquic_connection_loss_detection_timeout, conn);
		return;
	}
	gboolean ack_eliciting = FALSE;
	enum ssl_encryption_level_t level;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		if(conn->ack_eliciting_in_flight[level]) {
			ack_eliciting = TRUE;
			break;
		}
	}
	if(!ack_eliciting && (conn->is_server || !conn->just_started)) {
		/* FIXME Nothing to detect lost, for now */
		uint32_t max_idle_timeout = conn->local_params.max_idle_timeout;
		if(conn->remote_params.max_idle_timeout > 0 && conn->remote_params.max_idle_timeout < max_idle_timeout)
			max_idle_timeout = conn->remote_params.max_idle_timeout;
		if(max_idle_timeout > 0) {
			int64_t timeout = max_idle_timeout / 2;
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][IDLE] Setting next timeout in %"SCNi64"ms\n",
				imquic_get_connection_name(conn), timeout);
			conn->ld_timer = imquic_loop_add_timer(timeout, imquic_connection_loss_detection_timeout, conn);
		}
		return;
	}
	/* GetPtoTimeAndSpace */
	tm = imquic_connection_get_pto_timeout(conn);
	int64_t timeout = (tm > now ? (tm - now) : 0) / 1000;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s][PTO] Setting next timeout in %"SCNi64"ms\n",
		imquic_get_connection_name(conn), timeout);
	conn->ld_timer = imquic_loop_add_timer(timeout, imquic_connection_loss_detection_timeout, conn);
}

/* Callback to handle loss detection timeouts
 * https://quicwg.org/base-drafts/rfc9002.html#appendix-A.9 */
gboolean imquic_connection_loss_detection_timeout(gpointer user_data) {
	imquic_connection *conn = (imquic_connection *)user_data;
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return G_SOURCE_REMOVE;
	conn->ld_timer = NULL;
	/* GetLossTimeAndSpace */
	enum ssl_encryption_level_t level = ssl_encryption_initial;
	int64_t tm = conn->loss_time[level];
	if(tm == 0 || (conn->loss_time[ssl_encryption_handshake] > 0 &&
			conn->loss_time[ssl_encryption_handshake] < tm)) {
		level = ssl_encryption_handshake;
		tm = conn->loss_time[level];
	}
	if(tm == 0 || (conn->loss_time[ssl_encryption_application] > 0 &&
			conn->loss_time[ssl_encryption_application] < tm)) {
		level = ssl_encryption_application;
		tm = conn->loss_time[level];
	}
	if(tm > 0) {
		/* Time threshold loss detection */
		GList *lost = imquic_connection_detect_lost(conn);
		if(lost != NULL) {
			/* TODO This is also used for congestion control, see OnPacketsLost
			 * https://quicwg.org/base-drafts/rfc9002.html#appendix-B.8 */
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Lost packets (%d)\n",
				imquic_get_connection_name(conn), g_list_length(lost));
			GList *temp = lost;
			while(temp != NULL) {
				imquic_sent_packet *sent_pkt = (imquic_sent_packet *)temp->data;
				if(sent_pkt != NULL) {
					/* FIXME Retransmit this packet if needed, or get rid of it */
					IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %"SCNu64" (%s)\n",
						sent_pkt->packet_number, imquic_encryption_level_str(sent_pkt->level));
					imquic_retransmit_packet(conn, sent_pkt);
				}
				temp = temp->next;
			}

			g_list_free(lost);
		}
		imquic_connection_update_loss_timer(conn);
		return G_SOURCE_REMOVE;
	}
	/* FIXME PTO. Send new data if available, else retransmit old data.
     * If neither is available, send a single PING frame */
	imquic_sent_packet *sent_pkt = NULL;
	if(conn->level == ssl_encryption_initial) {
		/* Only retransmit handshake/application level data when they're detected as lost, not here */
		imquic_listmap_traverse(conn->sent_pkts[conn->level]);
		sent_pkt = imquic_listmap_next(conn->sent_pkts[conn->level], NULL);
	}
	if(sent_pkt != NULL) {
		/* Retransmit this packet */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Retransmitting packet\n",
			imquic_get_connection_name(conn));
		imquic_retransmit_packet(conn, sent_pkt);
	} else {
		/* Send a PING */
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Sending PING\n",
			imquic_get_connection_name(conn));
		imquic_send_keepalive(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	}
	conn->pto_count++;
	imquic_connection_update_loss_timer(conn);
	return G_SOURCE_REMOVE;
}

/* Detect lost packets
 * https://quicwg.org/base-drafts/rfc9002.html#appendix-A.10 */
GList *imquic_connection_detect_lost(imquic_connection *conn) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return NULL;
	GList *lost = NULL;
	enum ssl_encryption_level_t level;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		conn->loss_time[level] = 0;
		int64_t loss_delay = conn->rtt.latest > conn->rtt.smoothed ? conn->rtt.latest : conn->rtt.smoothed;
		if(loss_delay == 0)
			loss_delay = 1;
		loss_delay *= 1125;
		int64_t now = g_get_monotonic_time();
		int64_t lost_send_time = now - loss_delay;
		/* Traverse the sent packets for which we haven't received an ACK yet */
		imquic_sent_packet *sent_pkt = NULL;
		imquic_listmap_traverse(conn->sent_pkts[level]);
		gboolean found = TRUE;
		while(found) {
			sent_pkt = imquic_listmap_next(conn->sent_pkts[level], &found);
			if(sent_pkt) {
				/* Check if we can consider this packet lost */
				if(sent_pkt->packet_number >= conn->largest_acked[level])
					continue;
				if((sent_pkt->sent_time <= lost_send_time) ||
						(conn->largest_acked[level] > sent_pkt->packet_number + 3)) {
					/* It is, add it to the list */
					//~ IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Packet %"SCNu64" (%s) lost because it was sent too long ago (%"SCNi64" < %"SCNi64"; %"SCNi64"; %"SCNu16", %"SCNu16", %"SCNi64")\n",
						//~ imquic_get_connection_name(conn), sent_pkt->packet_number, imquic_encryption_level_str(level),
						//~ sent_pkt->sent_time, lost_send_time, now, conn->rtt.latest, conn->rtt.smoothed, loss_delay);
					lost = g_list_prepend(lost, sent_pkt);
				} else {
					/* Not lost yet */
					int64_t pkt_loss_time = sent_pkt->sent_time + loss_delay;
					if(conn->loss_time[level] == 0 || conn->loss_time[level] > pkt_loss_time)
						conn->loss_time[level] = pkt_loss_time;
				}
			}
		}
	}
	lost = g_list_reverse(lost);
	return lost;
}

/* Helper to generate a new stream ID for this connection */
int imquic_connection_new_stream_id(imquic_connection *conn, gboolean bidirectional, uint64_t *stream_id) {
	if(conn == NULL)
		return -1;
	/* Get a new stream ID */
	imquic_mutex_lock(&conn->mutex);
	uint64_t new_stream_id = imquic_build_stream_id(bidirectional ? conn->stream_next_bidi : conn->stream_next_uni,
		!conn->is_server, bidirectional);
	if(bidirectional)
		conn->stream_next_bidi++;
	else
		conn->stream_next_uni++;
	/* Create a new stream instance */
	imquic_stream *stream = imquic_stream_create(new_stream_id, conn->is_server);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Created new %s initiated %s stream '%"SCNu64"'\n",
		imquic_get_connection_name(conn), stream->client_initiated ? "client" : "server",
		stream->bidirectional ? "bidirectional" : "unidirectional", new_stream_id);
	g_hash_table_insert(conn->streams, imquic_dup_uint64(new_stream_id), stream);
	imquic_mutex_unlock(&conn->mutex);
	if(stream_id)
		*stream_id = new_stream_id;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		imquic_qlog_stream_state_updated(conn->qlog, new_stream_id,
			(bidirectional ? "bidirectional" : "unidirectional"),
			(!bidirectional ? "sending" : NULL), "open");
	}
#endif
	/* FIXME Flow control */
	if(bidirectional) {
		stream->local_max_data = conn->local_params.initial_max_stream_data_bidi_local;
		stream->remote_max_data = conn->remote_params.initial_max_stream_data_bidi_remote;
	} else {
		stream->local_max_data = conn->local_params.initial_max_stream_data_uni;
		stream->remote_max_data = conn->remote_params.initial_max_stream_data_uni;
	}
	if(conn->http3 != NULL && conn->http3->webtransport) {
		/* We need to write the info on the new WebTransport stream */
		uint8_t prefix[10];
		size_t plen = sizeof(prefix);
		size_t offset = imquic_write_varint(stream->bidirectional ? IMQUIC_HTTP3_WEBTRANSPORT_STREAM : IMQUIC_HTTP3_WEBTRANSPORT_UNI_STREAM, prefix, plen);
		offset += imquic_write_varint(0, &prefix[offset], plen-offset);	/* FIXME Should we expose session ID? */
		imquic_connection_send_on_stream(conn, stream->stream_id, prefix, 0, offset, FALSE);
		stream->skip_out = offset;
	}
	return 0;
}

/* Helper to send data on a DATAGRAM */
int imquic_connection_send_on_datagram(imquic_connection *conn, uint8_t *bytes, uint64_t length) {
	if(conn == NULL)
		return -1;
	if(conn->local_params.max_datagram_frame_size == 0 || conn->remote_params.max_datagram_frame_size == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Datagrams support not avaiable on this connection\n",
			imquic_get_connection_name(conn));
		return -1;
	}
	if(bytes == NULL || length == 0)
		return 0;
	/* FIXME */
	imquic_data *d = imquic_data_create(bytes, length);
	imquic_mutex_lock(&conn->mutex);
	g_queue_push_tail(conn->outgoing_datagram, d);
	imquic_mutex_unlock(&conn->mutex);
	g_atomic_int_set(&conn->wakeup, 1);
	imquic_loop_wakeup();
	return 0;
}

/* Helper to send data on a STREAM */
int imquic_connection_send_on_stream(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete) {
	if(conn == NULL)
		return -1;
	/* FIXME Queue on the outgoing buffer of the stream */
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream == NULL) {
		imquic_mutex_unlock(&conn->mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't send data, no such stream %"SCNu64"\n",
			imquic_get_connection_name(conn), stream_id);
		return -1;
	}
	imquic_refcount_increase(&stream->ref);
	imquic_mutex_unlock(&conn->mutex);
	offset += stream->skip_out;
	if(!imquic_stream_can_send(stream, offset, length, TRUE)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Can't send data on stream %"SCNu64"\n",
			imquic_get_connection_name(conn), stream_id);
		imquic_refcount_decrease(&stream->ref);
		return -1;
	}
	imquic_mutex_lock(&stream->mutex);
	if(bytes != NULL)
		imquic_buffer_put(stream->out_data, bytes, offset, length);
	if(complete)
		imquic_stream_mark_complete(stream, FALSE);
	imquic_mutex_unlock(&stream->mutex);
	imquic_refcount_decrease(&stream->ref);
	return 0;
}

/* Helper to notify incoming DATAGRAM data to the application */
void imquic_connection_notify_datagram_incoming(imquic_connection *conn, uint8_t *data, uint64_t length) {
	if(conn == NULL || conn->socket == NULL || data == NULL || length == 0)
		return;
	if(conn->socket->datagram_incoming == NULL)
		return;
	/* Notify the data */
	conn->socket->datagram_incoming(conn, data, length);
}

/* Helper to notify incoming STREAM data to the application */
void imquic_connection_notify_stream_incoming(imquic_connection *conn, imquic_stream *stream, uint8_t *data, uint64_t offset, uint64_t length) {
	if(conn == NULL || conn->socket == NULL || stream == NULL)
		return;
	if(conn->socket->stream_incoming == NULL)
		return;
	if(stream->skip_in > 0 && data != NULL && length > 0) {
		if(offset >= stream->skip_in) {
			/* We're past the initial skipped data, just fix the offset */
			offset -= stream->skip_in;
		} else {
			/* We need to skip some bytes and shift the offset/length */
			size_t diff = stream->skip_in - offset;
			if(diff >= length) {
				/* This is all data we can skip */
				return;
			}
			data += diff;
			length -= diff;
			if(length == 0)
				data = NULL;
		}
	}
	/* Notify the data */
	conn->socket->stream_incoming(conn, stream->stream_id, data,
		offset, length,	(stream->in_state == IMQUIC_STREAM_COMPLETE));
}

/* Helper to flush a stream */
void imquic_connection_flush_stream(imquic_connection *conn, uint64_t stream_id) {
	imquic_mutex_lock(&conn->mutex);
	if(g_hash_table_lookup(conn->streams, &stream_id) == NULL) {
		imquic_mutex_unlock(&conn->mutex);
		return;
	}
	g_queue_push_tail(conn->outgoing_data, imquic_dup_uint64(stream_id));
	imquic_mutex_unlock(&conn->mutex);
	g_atomic_int_set(&conn->wakeup, 1);
	imquic_loop_wakeup();
}

/* Helpers to close connections */
void imquic_connection_close(imquic_connection *conn, uint64_t error_code, uint64_t frame_type, const char *reason) {
	/* FIXME Send a CONNECTION CLOSE (01c) */
	if(conn == NULL || conn->socket == NULL || !g_atomic_int_compare_and_exchange(&conn->closed, 0, 1))
		return;
#if HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		imquic_qlog_connection_closed(conn->qlog, TRUE,
			(frame_type == IMQUIC_CONNECTION_CLOSE ? error_code : 0),
			(frame_type == IMQUIC_CONNECTION_CLOSE_APP ? error_code : 0),
			reason);
	}
#endif
	imquic_send_close_connection(conn, error_code, frame_type, reason);
}
