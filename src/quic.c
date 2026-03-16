/*! \file   quic.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC management
 * \details Implementation of the QUIC life cycle management, leveraging
 * methods and callbacks provided by picoquic to manage connections
 *
 * \ingroup Core
 *  */

#include <picoquic.h>
#include <picoquic_config.h>
#include <picoquic_internal.h>
#include <autoqlog.h>

#include "internal/quic.h"
#include "internal/qlog.h"
#include "imquic/debug.h"

/* picoquic stream callback as a string (for debugging purposes) */
static const char *picoquic_call_back_event_t_str(picoquic_call_back_event_t event) {
	switch(event) {
		case picoquic_callback_stream_data:
			return "picoquic_callback_stream_data";
		case picoquic_callback_stream_fin:
			return "picoquic_callback_stream_fin";
		case picoquic_callback_stream_reset:
			return "picoquic_callback_stream_reset";
		case picoquic_callback_stop_sending:
			return "picoquic_callback_stop_sending";
		case picoquic_callback_stateless_reset:
			return "picoquic_callback_stateless_reset";
		case picoquic_callback_close:
			return "picoquic_callback_close";
		case picoquic_callback_application_close:
			return "picoquic_callback_application_close";
		case picoquic_callback_stream_gap:
			return "picoquic_callback_stream_gap";
		case picoquic_callback_prepare_to_send:
			return "picoquic_callback_prepare_to_send";
		case picoquic_callback_almost_ready:
			return "picoquic_callback_almost_ready";
		case picoquic_callback_ready:
			return "picoquic_callback_ready";
		case picoquic_callback_datagram:
			return "picoquic_callback_datagram";
		case picoquic_callback_version_negotiation:
			return "picoquic_callback_version_negotiation";
		case picoquic_callback_request_alpn_list:
			return "picoquic_callback_request_alpn_list";
		case picoquic_callback_set_alpn:
			return "picoquic_callback_set_alpn";
		case picoquic_callback_pacing_changed:
			return "picoquic_callback_pacing_changed";
		case picoquic_callback_prepare_datagram:
			return "picoquic_callback_prepare_datagram";
		case picoquic_callback_datagram_acked:
			return "picoquic_callback_datagram_acked";
		case picoquic_callback_datagram_lost:
			return "picoquic_callback_datagram_lost";
		case picoquic_callback_datagram_spurious:
			return "picoquic_callback_datagram_spurious";
		case picoquic_callback_path_available:
			return "picoquic_callback_path_available";
		case picoquic_callback_path_suspended:
			return "picoquic_callback_path_suspended";
		case picoquic_callback_path_deleted:
			return "picoquic_callback_path_deleted";
		case picoquic_callback_path_quality_changed:
			return "picoquic_callback_path_quality_changed";
		case picoquic_callback_path_address_observed:
			return "picoquic_callback_path_address_observed";
		case picoquic_callback_app_wakeup:
			return "picoquic_callback_app_wakeup";
		case picoquic_callback_next_path_allowed:
			return "picoquic_callback_next_path_allowed";
		default:
			break;
	}
	return NULL;
}

/* picoquic callbacks */
static int imquic_quic_stream_callback(picoquic_cnx_t *pconn,
	uint64_t stream_id, uint8_t *bytes, size_t blen,
	picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx);
static size_t imquic_quic_select_alpn(picoquic_quic_t *qc, picoquic_iovec_t* list, size_t count);

/* Resources */
static char *sslkeylog_file = NULL;
/* FIXME Ugly way to have a static encryption key in case we need 0-RTT on the server side */
static uint8_t encryption_key[32] = { 0 };

/* Initialize the stack */
void imquic_quic_init(const char *secrets_log) {
	/* Initialize some picoquic stuff */
	picoquic_register_all_congestion_control_algorithms();
	/* Keep track of the sslogkey file, if needed */
	if(secrets_log != NULL)
		sslkeylog_file = g_strdup(secrets_log);
}

void imquic_quic_deinit(void) {
	g_free(sslkeylog_file);
}

const char *imquic_quic_sslkeylog_file(void) {
	return (const char *)sslkeylog_file;
}

/* Create a picoquic context */
int imquic_quic_create_context(imquic_network_endpoint *endpoint, imquic_configuration *config) {
	if(endpoint == NULL || config == NULL)
		return -1;
	picoquic_quic_config_t piconfig;
	picoquic_config_init(&piconfig);
	if(endpoint->is_server) {
		piconfig.server_port = config->local_port;
		piconfig.server_cert_file = config->cert_pem;
		piconfig.server_key_file = config->cert_key;
		/* FIXME Early data seems not to be working yet */
		if(config->early_data) {
			piconfig.ticket_encryption_key = encryption_key;
			piconfig.ticket_encryption_key_length = sizeof(encryption_key);
		}
	} else {
		if(config->sni != NULL)
			piconfig.sni = config->sni;
		/* FIXME Early data seems not to be working yet */
		if(config->early_data)
			piconfig.ticket_file_name = config->ticket_file;
	}
	/* We always enable this: if the env variable isn't set it will be ignored */
	piconfig.enable_sslkeylog = 1;
	/* FIXME Enrich configuration */
	uint64_t current_time = picoquic_current_time();
	endpoint->qc = picoquic_create_and_configure(&piconfig,
		imquic_quic_stream_callback, endpoint, current_time, NULL);
	if(endpoint->qc == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error creating picoquic context\n", config->name);
		return -1;
	}
	if(endpoint->is_server) {
		picoquic_set_alpn_select_fn_v2(endpoint->qc, imquic_quic_select_alpn);
	}
	/* Enable support for DATAGRAM */
	int ret = picoquic_set_default_tp_value(endpoint->qc, picoquic_tp_max_datagram_frame_size, 1532);
	if(ret != 0) {
		/* FIXME Should this be a fatal error? */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error configuring support for DATAGRAM: %d\n",
			config->name, ret);
	}
	/* FIXME Does picoquic verify the cert by default? */
	if(config->cert_no_verify)
		picoquic_set_null_verifier(endpoint->qc);
	if(sslkeylog_file != NULL)
		picoquic_set_key_log_file(endpoint->qc, sslkeylog_file);
	/* Enable QLOG, if we need it */
	if(endpoint->qlog_quic && endpoint->qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Enabling QLOG logging of QUIC frames\n", config->name);
		picoquic_set_qlog(endpoint->qc, endpoint->qlog_path);
		picoquic_set_log_level(endpoint->qc, 1);
	}
	/* Done */
	return 0;
}

/* Process incoming packets and pass them to picoquic */
void imquic_quic_incoming_packet(imquic_network_endpoint *endpoint, uint8_t *buffer, size_t len, imquic_network_address *sender) {
	if(endpoint == NULL || buffer == NULL || len == 0 || sender == NULL)
		return;
	/* Invoke the callback function for parsing the QUIC message */
	int ret = picoquic_incoming_packet(endpoint->qc, buffer, len,
		(struct sockaddr *)&sender->addr, (struct sockaddr *)&endpoint->local_address.addr,
		0, 0, picoquic_current_time());
	if(ret < 0)
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error processing incoming QUIC message: %d\n", endpoint->name, ret);
}

/* Handle queued connection events, to process them via picoquic */
gboolean imquic_quic_queued_event(imquic_connection *conn, imquic_connection_event *event) {
	if(conn == NULL || event == NULL) {
		imquic_connection_event_destroy(event);
		return G_SOURCE_REMOVE;
	}
	/* Check what event we need to process */
	if(event->type == IMQUIC_CONNECTION_EVENT_STREAM) {
		/* Send STREAM data */
		int ret = picoquic_add_to_stream(conn->piconn, event->stream_id,
			event->data ? event->data->bytes : NULL, event->data ? event->data->length : 0, event->fin);
		if(ret != 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error queueing data for STREAM %"SCNu64": %d\n",
				conn->name, event->stream_id, ret);
		}
	} else if(event->type == IMQUIC_CONNECTION_EVENT_DATAGRAM) {
		/* Send DATAGRAM data */
		int ret = picoquic_queue_datagram_frame(conn->piconn,
			event->data ? event->data->length : 0, event->data ? event->data->bytes : NULL);
		if(ret != 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error queueing DATAGRAM data: %d\n",
				conn->name, ret);
		}
	} else if(event->type == IMQUIC_CONNECTION_EVENT_RESET_STREAM) {
		/* Send a RESET_STREAM */
		int ret = picoquic_reset_stream(conn->piconn, event->stream_id, event->error_code);
		if(ret != 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error resetting STREAM %"SCNu64": %d\n",
				conn->name, event->stream_id, ret);
		}
	} else if(event->type == IMQUIC_CONNECTION_EVENT_STOP_SENDING) {
		/* Send a STOP_SENDING */
		int ret = picoquic_stop_sending(conn->piconn, event->stream_id, event->error_code);
		if(ret != 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error stopping STREAM %"SCNu64": %d\n",
				conn->name, event->stream_id, ret);
		}
	} else if(event->type == IMQUIC_CONNECTION_EVENT_CLOSE_CONN) {
		/* Send a CONNECTION_CLOSE */
		g_free(conn->local_reason);
		conn->local_reason = event->reason ? g_strdup(event->reason) : NULL;
		int ret = picoquic_close_ex(conn->piconn, event->error_code, conn->local_reason);
		if(ret != 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error sending CLOSE_CONNECTION: %d\n",
				conn->name, ret);
		}
	}
	imquic_connection_event_destroy(event);
	return G_SOURCE_CONTINUE;
}

/* Schedule the next picoquic lifecycle iteration */
void imquic_quic_next_step(imquic_network_endpoint *endpoint) {
	if(endpoint->timer != NULL)
		g_source_destroy((GSource *)endpoint->timer);
	int64_t wait_ns = picoquic_get_next_wake_delay(endpoint->qc, picoquic_current_time(), G_USEC_PER_SEC);
	IMQUIC_LOG(IMQUIC_LOG_DBG, "[%s] Next wake delay: %"SCNi64"ns\n", endpoint->name, wait_ns);
	endpoint->timer = imquic_loop_add_timer((wait_ns / 1000), (GSourceFunc)imquic_network_send_packet, endpoint);
}

/* picoquic callbacks */
static int imquic_quic_stream_callback(picoquic_cnx_t *pconn,
		uint64_t stream_id, uint8_t *bytes, size_t blen,
		picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx) {
	/* Check what the callback is about */
	imquic_network_endpoint *endpoint = (imquic_network_endpoint *)callback_ctx;
	imquic_connection *conn = pconn ? g_hash_table_lookup(endpoint->connections_by_cnx, pconn) : NULL;
	char *name = conn ? conn->name : endpoint->name;
	IMQUIC_LOG(IMQUIC_LOG_DBG, "[%s] %s\n", name, picoquic_call_back_event_t_str(fin_or_event));
	if(fin_or_event == picoquic_callback_request_alpn_list) {
		/* This is how we offer ALPNs as clients */
		if(endpoint->webtransport) {
			int ret = picoquic_add_proposed_alpn(bytes, "h3");
			if(ret != 0) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't offer ALPN '%s'\n",
					name, "h3");
			}
		}
		if(endpoint->raw_quic) {
			int i = 0;
			while(endpoint->alpn[i] != NULL) {
				int ret = picoquic_add_proposed_alpn(bytes, endpoint->alpn[i]);
				if(ret != 0) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Couldn't offer ALPN '%s'\n",
						name, endpoint->alpn[i]);
				}
				i++;
			}
		}
	} else if(fin_or_event == picoquic_callback_almost_ready) {
		/* A connection was established for a specific ALPN */
		picoquic_connection_id_t initial_cid = picoquic_get_initial_cnxid(pconn);
		if(endpoint->is_server && conn == NULL) {
			/* New connection */
			conn = imquic_connection_create(endpoint, pconn);
		}
		name = conn->name;
		imquic_connection_id_str(&initial_cid, conn->initial_cid_str, sizeof(conn->initial_cid_str));
#ifdef HAVE_QLOG
		if(endpoint->qlog_path && (endpoint->qlog_http3 || endpoint->qlog_roq || endpoint->qlog_moq)) {
			conn->qlog = imquic_qlog_create(conn->name, conn->initial_cid_str,
				endpoint->qlog_path, endpoint->qlog_sequential, endpoint->is_server,
				endpoint->qlog_http3, endpoint->qlog_roq, endpoint->qlog_roq_packets,
				endpoint->qlog_moq, endpoint->qlog_moq_messages, endpoint->qlog_moq_objects);
		}
#endif
		const char *alpn = picoquic_tls_get_negotiated_alpn(pconn);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection established (ALPN=%s)\n",
			name, alpn);
		conn->alpn_negotiated = TRUE;
		conn->chosen_alpn = g_strdup(alpn);
		if(endpoint->webtransport && !strcasecmp(alpn, "h3"))
			conn->http3 = imquic_http3_connection_create(conn, endpoint->wt_protocols);
		if(conn->http3 != NULL) {
			if(conn->is_server) {
				/* If this is an HTTP/3 connection, as a server wait for a SETTINGS */
			} else {
				/* If this is an HTTP/3 connection, as a client send a SETTINGS */
				imquic_http3_prepare_settings(conn->http3);
			}
		} else if(endpoint->new_connection) {
			conn->established = TRUE;
			endpoint->new_connection(conn, endpoint->user_data);
		}
	} else if(fin_or_event == picoquic_callback_datagram) {
		/* FIXME We have incoming DATAGRAM data */
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Incoming DATAGRAM data (%zu bytes)\n",
			name, blen);
		imquic_connection_notify_datagram_incoming(conn, bytes, blen);
	} else if(fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin) {
		/* FIXME We have incoming STREAM data */
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Incoming STREAM data (stream %"SCNu64", %zu bytes)\n",
			name, stream_id, blen);
		/* Is this an existing stream or a new one? */
		imquic_mutex_lock(&conn->mutex);
		gboolean new_stream = FALSE;
		imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
		if(stream == NULL) {
			/* New stream, take note of it */
			new_stream = TRUE;
			stream = imquic_stream_create(stream_id, endpoint->is_server);
			g_hash_table_insert(conn->streams, imquic_uint64_dup(stream_id), stream);
		}
		if(fin_or_event == picoquic_callback_stream_fin)
			imquic_stream_mark_complete(stream, TRUE);
		imquic_mutex_unlock(&conn->mutex);
		if(conn->http3 != NULL) {
			/* Process the data as HTTP/3 */
			imquic_http3_process_stream_data(conn, stream, bytes, blen, new_stream);
		} else {
			/* Pass the data to the application callback */
			imquic_connection_notify_stream_incoming(conn, stream, bytes, blen);
		}
	} else if(fin_or_event == picoquic_callback_stream_reset) {
		/* Use the picoquic internal API to obtain the error_code */
		uint64_t error_code = 0;
		picoquic_stream_head_t *ps = picoquic_find_stream(pconn, stream_id);
		if(ps != NULL)
			error_code = ps->remote_error;
		/* Update the local state of the stream */
		imquic_mutex_lock(&conn->mutex);
		imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
		if(stream != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Stream %"SCNu64" has been reset by the peer\n", stream_id);
			if(stream->in_state != IMQUIC_STREAM_COMPLETE)
				stream->in_state = IMQUIC_STREAM_RESET;
		}
		imquic_mutex_unlock(&conn->mutex);
		/* Pass the data to the application callback */
		if(endpoint->reset_stream_incoming)
			endpoint->reset_stream_incoming(conn, stream_id, error_code);
	} else if(fin_or_event == picoquic_callback_stop_sending) {
		/* Use the picoquic internal API to obtain the error_code */
		uint64_t error_code = 0;
		picoquic_stream_head_t *ps = picoquic_find_stream(pconn, stream_id);
		if(ps != NULL)
			error_code = ps->remote_stop_error;
		/* Update the local state of the stream */
		imquic_mutex_lock(&conn->mutex);
		imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
		if(stream != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "We've been asked to stop sending on stream %"SCNu64"\n", stream_id);
			if(stream->out_state != IMQUIC_STREAM_COMPLETE)
				stream->out_state = IMQUIC_STREAM_RESET;
		}
		imquic_mutex_unlock(&conn->mutex);
		/* Pass the data to the application callback */
		if(endpoint->stop_sending_incoming)
			endpoint->stop_sending_incoming(conn, stream_id, error_code);
	} else if(fin_or_event == picoquic_callback_application_close) {
		/* TODO Should we handle this somehow? */
	} else if(fin_or_event == picoquic_callback_close) {
		/* FIXME Connection closed */
		uint64_t local_reason = 0, remote_reason = 0,
			local_application_reason = 0, remote_application_reason = 0;
		picoquic_get_close_reasons(pconn, &local_reason, &remote_reason,
			&local_application_reason, &remote_application_reason);
		if(conn != NULL) {
			uint64_t error_code = 0;
			const char *reason = NULL;
			if(g_atomic_int_get(&conn->closing)) {
				error_code = local_application_reason ? local_application_reason : local_reason;
				reason = pconn->local_error_reason;
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection closed: %"SCNu64" (%s)\n",
					name, error_code, reason ? reason : "no reason");
			} else if(g_atomic_int_compare_and_exchange(&conn->closed, 0, 1)) {
				error_code = remote_application_reason ? remote_application_reason : remote_reason;
				reason = pconn->remote_error_reason;
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection closed by peer: %"SCNu64" (%s)\n",
					name, error_code, reason ? reason : "no reason");
			}
			g_atomic_int_set(&conn->closed, 1);
			imquic_connection_notify_gone(conn, error_code, reason);
		}
	}
	imquic_quic_next_step(endpoint);
	return 0;
}

static size_t imquic_quic_select_alpn(picoquic_quic_t *qc, picoquic_iovec_t* list, size_t count) {
	imquic_network_endpoint *endpoint = (imquic_network_endpoint *)picoquic_get_default_callback_context(qc);
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Client offered ALPNs:\n", endpoint->name);
	char alpn[20];
	for(size_t i=0; i<count; i++) {
		g_snprintf(alpn, sizeof(alpn), "%.*s", (int)list[i].len, (char *)list[i].base);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s]   -- %s\n", endpoint->name, alpn);
		if(endpoint->webtransport && !strcasecmp(alpn, "h3")) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Negotiated ALPN: %s (WebTransport)\n",
				endpoint->name, alpn);
			return i;
		}
		if(endpoint->raw_quic) {
			int j = 0;
			while(endpoint->alpn[j] != NULL) {
				if(!strcasecmp(alpn, endpoint->alpn[j])) {
					IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Negotiated ALPN: %s\n",
						endpoint->name, alpn);
					return i;
				}
				j++;
			}
		}
	}
	return count;
}
