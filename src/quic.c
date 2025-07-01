/*! \file   quic.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC stack implementation
 * \details Implementation of the QUIC stack itself. This is where message
 * parsing and building is implemented, including connection establishment
 * and (mostly) state management.
 *
 * \ingroup Core
 */

#include <arpa/inet.h>
#include <netdb.h>

#include "internal/quic.h"
#include "internal/error.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Connections tracking */
static GHashTable *connections = NULL;
void imquic_quic_connection_add(imquic_connection *conn, imquic_connection_id *cid) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed) || cid == NULL)
		return;
	imquic_refcount_increase(&conn->ref);
	conn->connection_ids = g_list_prepend(conn->connection_ids, imquic_connection_id_dup(cid));
	g_hash_table_insert(connections, imquic_connection_id_dup(cid), conn);
}
void imquic_quic_connection_remove(imquic_connection_id *cid) {
	if(cid == NULL)
		return;
	g_hash_table_remove(connections, cid);
}

/* Initialize the stack */
void imquic_quic_init(void) {
	connections = g_hash_table_new_full(imquic_connection_id_hash, imquic_connection_id_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_connection_unref);
}

void imquic_quic_deinit(void) {
	/* TODO */
}

/* QUIC stack */
const char *imquic_long_packet_type_str(imquic_long_packet_type type) {
	switch(type) {
		case IMQUIC_INITIAL:
			return "Initial";
		case IMQUIC_0RTT:
			return "0-RTT";
		case IMQUIC_HANDSHAKE:
			return "Handshake";
		case IMQUIC_RETRY:
			return "Retry";
		default: break;
	}
	return NULL;
}

const char *imquic_frame_type_str(imquic_frame_type type) {
	switch(type) {
		case IMQUIC_PADDING:
			return "PADDING";
		case IMQUIC_PING:
			return "PING";
		case IMQUIC_ACK:
		case IMQUIC_ACK_WITH_ECN:
			return "ACK";
		case IMQUIC_RESET_STREAM:
			return "RESET_STREAM";
		case IMQUIC_STOP_SENDING:
			return "STOP_SENDING";
		case IMQUIC_CRYPTO:
			return "CRYPTO";
		case IMQUIC_NEW_TOKEN:
			return "NEW_TOKEN";
		case IMQUIC_STREAM:
		case IMQUIC_STREAM_F:
		case IMQUIC_STREAM_L:
		case IMQUIC_STREAM_LF:
		case IMQUIC_STREAM_O:
		case IMQUIC_STREAM_OF:
		case IMQUIC_STREAM_OL:
		case IMQUIC_STREAM_OLF:
			return "STREAM";
		case IMQUIC_MAX_DATA:
			return "MAX_DATA";
		case IMQUIC_MAX_STREAM_DATA:
			return "MAX_STREAM_DATA";
		case IMQUIC_MAX_STREAMS:
			return "MAX_STREAMS";
		case IMQUIC_DATA_BLOCKED:
			return "DATA_BLOCKED";
		case IMQUIC_STREAM_DATA_BLOCKED:
			return "STREAM_DATA_BLOCKED";
		case IMQUIC_STREAMS_BLOCKED:
		case IMQUIC_STREAMS_BLOCKED_UNI:
			return "STREAMS_BLOCKED";
		case IMQUIC_NEW_CONNECTION_ID:
			return "NEW_CONNECTION_ID";
		case IMQUIC_RETIRE_CONNECTION_ID:
			return "RETIRE_CONNECTION_ID";
		case IMQUIC_PATH_CHALLENGE:
			return "PATH_CHALLENGE";
		case IMQUIC_PATH_RESPONSE:
			return "PATH_RESPONSE";
		case IMQUIC_CONNECTION_CLOSE:
		case IMQUIC_CONNECTION_CLOSE_APP:
			return "CONNECTION_CLOSE";
		case IMQUIC_HANDSHAKE_DONE:
			return "HANDSHAKE_DONE";
		case IMQUIC_DATAGRAM:
		case IMQUIC_DATAGRAM_L:
			return "DATAGRAM";
		default: break;
	}
	return NULL;
}

const char *imquic_transport_parameter_str(imquic_transport_parameter param) {
	switch(param) {
		case IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID:
			return "original_destination_connection_id";
		case IMQUIC_MAX_IDLE_TIMEOUT:
			return "max_idle_timeout";
		case IMQUIC_STATELESS_RESET_TOKEN:
			return "stateless_reset_token";
		case IMQUIC_MAX_UDP_PAYLOAD_SIZE:
			return "max_udp_payload_size";
		case IMQUIC_INITIAL_MAX_DATA:
			return "initial_max_data";
		case IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			return "initial_max_stream_data_bidi_local";
		case IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			return "initial_max_stream_data_bidi_remote";
		case IMQUIC_INITIAL_MAX_STREAM_DATA_UNI:
			return "initial_max_stream_data_uni";
		case IMQUIC_INITIAL_MAX_STREAMS_BIDI:
			return "initial_max_streams_bidi";
		case IMQUIC_INITIAL_MAX_STREAMS_UNI:
			return "initial_max_streams_uni";
		case IMQUIC_ACK_DELAY_EXPONENT:
			return "ack_delay_exponent";
		case IMQUIC_MAX_ACK_DELAY:
			return "max_ack_delay";
		case IMQUIC_DISABLE_ACTIVE_MIGRATION:
			return "disable_active_migration";
		case IMQUIC_PREFERRED_ADDRESS:
			return "preferred_address";
		case IMQUIC_ACTIVE_CONNECTION_ID_LIMIT:
			return "active_connection_id_limit";
		case IMQUIC_INITIAL_SOURCE_CONNECTION_ID:
			return "initial_source_connection_id";
		case IMQUIC_RETRY_SOURCE_CONNECTION_ID:
			return "retry_source_connection_id";
		case IMQUIC_MAX_DATAGRAM_FRAME_SIZE:
			return "max_datagram_frame_size";
		default: break;
	}
	return NULL;
}

/* Frame serialization */
imquic_frame *imquic_frame_create(imquic_frame_type type, uint8_t *buffer, size_t size) {
	if(size == 0)
		return NULL;
	imquic_frame *frame = g_malloc(sizeof(imquic_frame));
	frame->type = type;
	frame->buffer = g_malloc(size);
	if(buffer != NULL)
		memcpy(frame->buffer, buffer, size);
	else
		memset(frame->buffer, 0, size);
	frame->size = size;
#ifdef HAVE_QLOG
	frame->qlog_frame = NULL;
#endif
	return frame;
}

void imquic_frame_destroy(imquic_frame *frame) {
	if(frame) {
		g_free(frame->buffer);
#ifdef HAVE_QLOG
		if(frame->qlog_frame != NULL)
			json_decref(frame->qlog_frame);
#endif
		g_free(frame);
	}
}

/* Packet management */
imquic_packet *imquic_packet_create(void) {
	imquic_packet *pkt = g_malloc0(sizeof(imquic_packet));
	return pkt;
}

int imquic_packet_long_init(imquic_packet *pkt, imquic_long_packet_type type, imquic_connection_id *src, imquic_connection_id *dest) {
	pkt->type = type;
	if(type == IMQUIC_INITIAL)
		pkt->level = ssl_encryption_initial;
	else if(type == IMQUIC_HANDSHAKE)
		pkt->level = ssl_encryption_handshake;
	pkt->is_valid = TRUE;
	pkt->is_protected = FALSE;
	pkt->is_encrypted = FALSE;
	pkt->longheader = TRUE;
	pkt->version = 1;
	pkt->packet_number = 0;	/* Will be set later */
	pkt->length_offset = 0;
	pkt->pkn_offset = 0;
	pkt->payload_offset = 0;
	pkt->retransmit_if_lost = FALSE;
	pkt->ack_eliciting = FALSE;
	if(dest)
		memcpy(&pkt->destination, dest, sizeof(imquic_connection_id));
	else
		memset(&pkt->destination, 0, sizeof(imquic_connection_id));
	if(src)
		memcpy(&pkt->source, src, sizeof(imquic_connection_id));
	else
		memset(&pkt->source, 0, sizeof(imquic_connection_id));
	return 0;
}

int imquic_packet_short_init(imquic_packet *pkt, imquic_connection_id *dest) {
	pkt->level = ssl_encryption_application;	/* FIXME */
	pkt->is_valid = TRUE;
	pkt->is_protected = FALSE;
	pkt->is_encrypted = FALSE;
	pkt->longheader = FALSE;
	pkt->spin_bit = FALSE;
	pkt->key_phase = FALSE;
	pkt->packet_number = 0;	/* Will be set later */
	pkt->length_offset = 0;
	pkt->pkn_offset = 0;
	pkt->payload_offset = 0;
	pkt->retransmit_if_lost = FALSE;
	pkt->ack_eliciting = FALSE;
	if(dest)
		memcpy(&pkt->destination, dest, sizeof(imquic_connection_id));
	else
		memset(&pkt->destination, 0, sizeof(imquic_connection_id));
	return 0;
}

void imquic_packet_destroy(imquic_packet *pkt) {
	if(pkt) {
		g_list_free_full(pkt->frames, (GDestroyNotify)imquic_frame_destroy);
#ifdef HAVE_QLOG
		if(pkt->qlog_frames != NULL)
			json_decref(pkt->qlog_frames);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
#endif
		g_free(pkt);
	}
}

void imquic_sent_packet_destroy(imquic_sent_packet *sent_pkt) {
	if(sent_pkt) {
		imquic_packet_destroy(sent_pkt->packet);
		g_free(sent_pkt);
	}
}

/* Helper to parse an incoming packet */
int imquic_parse_packet(imquic_network_endpoint *socket, imquic_network_address *sender,
		imquic_connection **pconn, imquic_packet *pkt, uint8_t *quic, size_t bytes, size_t tot) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "Parsing packet (exploring %zu bytes)\n", bytes);
	*pconn = NULL;
	imquic_connection *conn = NULL;
	memset(pkt, 0, sizeof(*pkt));
	pkt->is_protected = TRUE;
	pkt->is_encrypted = TRUE;

	size_t blen = bytes;
	size_t offset = 0;

	uint8_t pn_length = 0;
	uint64_t pn = 0;
	uint64_t p_len = 0;

	/* Header */
	uint8_t byte = quic[0];
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "%02x\n", byte);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- " BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(byte));
	uint8_t lh = (byte & 0x80) >> 7;
	if(lh) {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "QUIC Long Header\n");
		pkt->longheader = TRUE;
		/* Start from the header packet protection */
		uint8_t fb = (byte & 0x40) >> 6;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Fixed Bit:   %d\n", (fb ? 1 : 0));
		if(!fb) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Fixed Bit is not 1, invalid packet\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		uint8_t type = (byte & 0x30) >> 4;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Packet Type: %02x (%s)\n", type, imquic_long_packet_type_str(type));
		pkt->type = type;
		/* Set the encryption level */
		if(type == IMQUIC_INITIAL)
			pkt->level = ssl_encryption_initial;
		else if(type == IMQUIC_0RTT)
			pkt->level = ssl_encryption_early_data;
		else if(type == IMQUIC_HANDSHAKE)
			pkt->level = ssl_encryption_handshake;
		else
			pkt->level = ssl_encryption_application;
		uint8_t tsb = byte & 0x0F;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Type Bits:   %02x (protected)\n", tsb);
		offset++;
		uint32_t version = 0;
		memcpy(&version, &quic[offset], sizeof(version));
		version = g_ntohl(version);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Version:     %08x\n", version);
		if(version != 1) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Version is not 1, unsupported QUIC version\n");
			/* TODO We should send a version negotiation packet here (17.2.1) */
			pkt->is_valid = FALSE;
			return -1;
		}
		pkt->version = version;
		offset += 4;
		size_t dcid_len = quic[offset];
		if(dcid_len > 20) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Destination Connection ID too long (%zu)\n", dcid_len);
			pkt->is_valid = FALSE;
			return -1;
		}
		offset++;
		size_t dcid_offset = offset;
		offset += dcid_len;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Dest (len):  %zu\n", dcid_len);
		if(dcid_len > 0) {
			imquic_print_hex(IMQUIC_LOG_HUGE, &quic[dcid_offset], dcid_len);
			memcpy(pkt->destination.id, &quic[dcid_offset], dcid_len);
			pkt->destination.len = dcid_len;
		}
		size_t scid_len = quic[offset];
		if(scid_len > 20) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Source Connection ID too long (%zu)\n", scid_len);
			pkt->is_valid = FALSE;
			return -1;
		}
		offset++;
		size_t scid_offset = offset;
		offset += scid_len;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Src (len):   %zu\n", scid_len);
		if(scid_len > 0) {
			imquic_print_hex(IMQUIC_LOG_HUGE, &quic[scid_offset], scid_len);
			memcpy(pkt->source.id, &quic[scid_offset], scid_len);
			pkt->source.len = scid_len;
		}
		if(type == IMQUIC_RETRY) {
			/* We got a Retry */
			conn = g_hash_table_lookup(connections, &pkt->destination);
#ifdef HAVE_QLOG
			if(conn != NULL && conn->qlog != NULL && conn->qlog->quic && bytes == tot) {
				conn->dgram_id_in++;
				imquic_qlog_udp_datagrams_received(conn->qlog, conn->dgram_id_in, bytes);
			}
#endif
			if(conn == NULL || conn->is_server || conn->level > ssl_encryption_initial) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Ignoring invalid Retry packet\n");
#ifdef HAVE_QLOG
				if(conn != NULL && conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("retry",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_INVALID);
				}
#endif
				return bytes;
			}
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Received a Retry\n");
			if((bytes - offset) < 16) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Invalid Retry packet, not enough room for integrity tag\n");
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("retry",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_INVALID);
				}
#endif
				return bytes;
			}
			size_t token_len = bytes - offset - 16;
			if(token_len > sizeof(conn->retry_token.buffer)) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Ignoring Retry packet, token too large\n");
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("retry",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_INVALID);
				}
#endif
				return bytes;
			}
			conn->retry_token.length = token_len;
			memcpy(conn->retry_token.buffer, &quic[offset], token_len);
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Retry token (%zu bytes)\n", token_len);
			imquic_print_hex(IMQUIC_LOG_HUGE, conn->retry_token.buffer, conn->retry_token.length);
			offset += token_len;
			/* Validate Retry integrity tag */
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Retry integrity tag (%zu bytes)\n", bytes-offset);
			imquic_print_hex(IMQUIC_LOG_HUGE, &quic[offset], 16);
			if(imquic_verify_retry(quic, bytes, conn->remote_cid.id, conn->remote_cid.len) < 0) {
				/* The verification of the integrity tag failed */
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("retry",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
				}
#endif
				return bytes;
			}
			/* Update destination ID and secrets */
			conn->remote_cid.len = pkt->source.len;
			if(pkt->source.len > 0)
				memcpy(conn->remote_cid.id, pkt->source.id, pkt->source.len);
			if(imquic_derive_initial_secret(&conn->keys[ssl_encryption_initial],
					conn->remote_cid.id, conn->remote_cid.len, FALSE) < 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error deriving initial secret\n", imquic_get_connection_name(conn));
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("retry",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
				}
#endif
				return bytes;
			}
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, FALSE),
					conn->keys[ssl_encryption_initial].local.key[0], conn->keys[ssl_encryption_initial].local.key_len, 0);
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, TRUE),
					conn->keys[ssl_encryption_initial].remote.key[0], conn->keys[ssl_encryption_initial].remote.key_len, 0);
			}
#endif
			/* Updated the Initial packet and resend it */
			uint64_t last_pkn = conn->pkn[ssl_encryption_initial] - 1;
			imquic_sent_packet *sent_pkt = imquic_listmap_find(conn->sent_pkts[ssl_encryption_initial], &last_pkn);
			if(sent_pkt && sent_pkt->packet) {
				sent_pkt->packet->destination.len = pkt->source.len;
				if(pkt->source.len > 0)
					memcpy(sent_pkt->packet->destination.id, pkt->source.id, pkt->source.len);
				GList *temp = sent_pkt->packet->frames;
				imquic_frame *frame = NULL;
				while(temp) {
					frame = (imquic_frame *)temp->data;
					if(frame->type == IMQUIC_PADDING) {
						if(frame->size > token_len) {
							sent_pkt->packet_size -= token_len;
							frame->size -= token_len;
						}
						break;
					}
					temp = temp->next;
				}
			}
			imquic_retransmit_packet(conn, sent_pkt);
			/* Done */
			conn->last_activity = g_get_monotonic_time();
			return bytes;
		} else if(type == IMQUIC_0RTT) {
			conn = g_hash_table_lookup(connections, &pkt->destination);
#ifdef HAVE_QLOG
			if(conn != NULL && conn->qlog != NULL && conn->qlog->quic && bytes == tot) {
				conn->dgram_id_in++;
				imquic_qlog_udp_datagrams_received(conn->qlog, conn->dgram_id_in, bytes);
			}
#endif
			if(conn == NULL || !conn->is_server || conn->keys[ssl_encryption_early_data].remote.md == NULL) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Ignoring 0-RTT\n");
#ifdef HAVE_QLOG
				if(conn != NULL && conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header("0RTT",
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_GENERAL);
				}
#endif
				return bytes;
			}
		}
		uint8_t length = 0;
		if(type == IMQUIC_INITIAL) {
			/* TODO We don't support Tokens yet, we just skip them */
			uint64_t token_len = imquic_read_varint(&quic[offset], bytes-offset, &length);
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Token (len): %"SCNu64"\n", token_len);
			if(length > 0) {
				/* FIXME Skip token */
				imquic_print_hex(IMQUIC_LOG_HUGE, &quic[offset], length);
				offset += length;
			}
		}
		p_len = imquic_read_varint(&quic[offset], bytes-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Length:      %"SCNu64"\n", p_len);
		pkt->length_offset = offset;
		offset += length;
		/* Now we are where the packet number is, which we need for the sample */
		size_t pn_offset = offset;
		if(bytes-offset-4 < 16) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: not enough bytes for header protection sample\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		pkt->pkn_offset = pn_offset;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (protected)\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &quic[pn_offset], 4);

		/* Check which connection this is for */
		if(pkt->destination.len == 0 && pkt->source.len == 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: no source and no destination\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		conn = g_hash_table_lookup(connections, &pkt->destination);
		if(conn == NULL) {
			/* Connection not found: is this a new one? */
			if(!socket->is_server) {
				IMQUIC_LOG(IMQUIC_LOG_WARN, "Ignoring unknown connection on client socket\n");
				return -1;
			}
			char address[60];
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Creating new connection (%s)\n",
				imquic_network_address_str(sender, address, sizeof(address), TRUE));
			conn = imquic_connection_create(socket);
			memcpy(&conn->peer, sender, sizeof(conn->peer));
			if(pkt->destination.len > 0) {
				conn->initial_cid.len = pkt->destination.len;
				memcpy(conn->initial_cid.id, pkt->destination.id, pkt->destination.len);
				imquic_quic_connection_add(conn, &conn->initial_cid);
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic)
					imquic_qlog_set_odcid(conn->qlog, &conn->initial_cid);
#endif
			}
			uint64_t local_cid = imquic_random_uint64();
			conn->local_cid.len = sizeof(local_cid);
			memcpy(conn->local_cid.id, &local_cid, conn->local_cid.len);
			uint64_t st1 = imquic_random_uint64(), st2 = imquic_random_uint64();
			memcpy(conn->local_cid.token, &st1, sizeof(st1));
			memcpy(&conn->local_cid.token[sizeof(st1)], &st2, sizeof(st2));
			imquic_quic_connection_add(conn, &conn->local_cid);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				char src_ip[NI_MAXHOST] = { 0 }, dst_ip[NI_MAXHOST] = { 0 };
				imquic_qlog_connection_started(conn->qlog,
					imquic_network_address_str(&conn->socket->local_address, dst_ip, sizeof(dst_ip), FALSE), conn->socket->port,
					imquic_network_address_str(sender, src_ip, sizeof(src_ip), FALSE), imquic_network_address_port(sender));
				imquic_qlog_version_information(conn->qlog, 1, 1);
			}
#endif
		}
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic && bytes == tot) {
			conn->dgram_id_in++;
			imquic_qlog_udp_datagrams_received(conn->qlog, conn->dgram_id_in, bytes);
		}
#endif
		*pconn = conn;
		imquic_refcount_increase(&conn->ref);
		if(pkt->source.len > 0 && conn->remote_cid.len == 0) {
			conn->remote_cid.len = pkt->source.len;
			memcpy(conn->remote_cid.id, pkt->source.id, pkt->source.len);
		}

		/* Unprotect the header */
		if(conn->just_started) {
			if(pkt->is_protected && imquic_derive_initial_secret(&conn->keys[ssl_encryption_initial],
					pkt->destination.id, pkt->destination.len, conn->is_server) < 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "Error deriving initial secret\n");
				pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					json_t *ph = imquic_qlog_prepare_packet_header(imquic_encryption_level_str(pkt->level),
						&pkt->source, &pkt->destination);
					imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
				}
#endif
				return -1;
			}
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, TRUE),
					conn->keys[ssl_encryption_initial].local.key[0], conn->keys[ssl_encryption_initial].local.key_len, 0);
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, FALSE),
					conn->keys[ssl_encryption_initial].remote.key[0], conn->keys[ssl_encryption_initial].remote.key_len, 0);
			}
#endif
		}
		conn->just_started = FALSE;
		/* Check which key we should use */
		uint8_t *hp = conn->keys[pkt->level].remote.hp;
		size_t hp_len = conn->keys[pkt->level].remote.hp_len;
		if(pkt->is_protected && imquic_unprotect_header(quic, bytes, pn_offset, hp, hp_len) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Error unprotecting packet\n");
			pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *ph = imquic_qlog_prepare_packet_header(imquic_encryption_level_str(pkt->level),
					&pkt->source, &pkt->destination);
				imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
			}
#endif
			return -1;
		}
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "Header unprotected\n");
		pkt->is_protected = FALSE;
		uint8_t reserved = (quic[0] & 0x0C);
		pn_length = (quic[0] & 0x03) + 1;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Reserved:    %"SCNu8"\n", reserved);
		if(reserved != 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: reserved is not 0\n");
			pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *ph = imquic_qlog_prepare_packet_header(imquic_encryption_level_str(pkt->level),
					&pkt->source, &pkt->destination);
				imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_INVALID);
			}
#endif
			return -1;
		}
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (len):   %"SCNu8"\n", pn_length);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (unprotected)\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &quic[pn_offset], 4);
		/* Read the packet number and move to the payload */
		for(uint8_t i=0; i<pn_length; i++) {
			uint8_t t = quic[pn_offset+i];
			pn |= t << (pn_length-i-1)*8;
		}
		pkt->packet_number = imquic_full_packet_number(conn->largest[pkt->level], pn, pn_length*8);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Packet Num[%s]: %"SCNu64" (largest=%"SCNu64", pkn=%"SCNu64", pkn_len=%"SCNu8")\n",
			imquic_encryption_level_str(pkt->level), pkt->packet_number, conn->largest[pkt->level], pn, pn_length);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "QUIC Short Header\n");
		pkt->longheader = FALSE;
		/* Start from the header packet protection */
		uint8_t fb = (byte & 0x40) >> 6;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Fixed Bit:   %d\n", (fb ? 1 : 0));
		if(!fb) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Fixed Bit is not 1, invalid packet\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		pkt->spin_bit = (byte & 0x20) >> 5;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Spin Bit:    %d\n", (pkt->spin_bit ? 1 : 0));
		/* Set the encryption level */
		pkt->level = ssl_encryption_application;
		uint8_t tsb = byte & 0x1F;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Type Bits:   %02x (protected)\n", tsb);
		offset++;
		size_t dcid_len = 8;	/* FIXME */
		size_t dcid_offset = offset;
		offset += dcid_len;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Dest (len, already known):  %zu\n", dcid_len);
		if(dcid_len > 0) {
			imquic_print_hex(IMQUIC_LOG_HUGE, &quic[dcid_offset], dcid_len);
			memcpy(pkt->destination.id, &quic[dcid_offset], dcid_len);
			pkt->destination.len = dcid_len;
		}

		/* Now we are where the packet number is, which we need for the sample */
		size_t pn_offset = offset;
		if(bytes-offset-4 < 16) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: not enough bytes for header protection sample\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		pkt->pkn_offset = pn_offset;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (protected)\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &quic[pn_offset], 4);

		/* Check which connection this is for */
		if(pkt->destination.len == 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: no destination\n");
			pkt->is_valid = FALSE;
			return -1;
		}
		conn = g_hash_table_lookup(connections, &pkt->destination);
		if(conn == NULL) {
			/* Connection not found: is this a new one? */
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Dropping packet for unknown connection\n");
			pkt->is_valid = FALSE;
			return -1;
		}
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic && bytes == tot) {
			conn->dgram_id_in++;
			imquic_qlog_udp_datagrams_received(conn->qlog, conn->dgram_id_in, bytes);
		}
#endif
		*pconn = conn;
		imquic_refcount_increase(&conn->ref);

		/* Unprotect the header: check which key we should use */
		uint8_t *hp = conn->keys[pkt->level].remote.hp;
		size_t hp_len = conn->keys[pkt->level].remote.hp_len;
		if(pkt->is_protected && imquic_unprotect_header(quic, bytes, pn_offset, hp, hp_len) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error unprotecting packet\n");
			pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *ph = imquic_qlog_prepare_packet_header("1RTT",
					NULL, &pkt->destination);
				imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
			}
#endif
			return -1;
		}
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "Header unprotected\n");
		pkt->is_protected = FALSE;
		uint8_t reserved = (quic[0] & 0x18) >> 3;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Reserved:    %"SCNu8"\n", reserved);
		if(reserved != 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Invalid packet: reserved is not 0\n");
			pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *ph = imquic_qlog_prepare_packet_header("1RTT",
					NULL, &pkt->destination);
				imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_INVALID);
			}
#endif
			return -1;
		}
		pkt->key_phase = (quic[0] & 0x04) >> 2;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Key Phase:   %d\n", (pkt->key_phase ? 1 : 0));
		pn_length = (quic[0] & 0x03) + 1;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (len):   %"SCNu8"\n", pn_length);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- PKN (unprotected)\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &quic[pn_offset], 4);
		/* Read the packet number and move to the payload */
		for(uint8_t i=0; i<pn_length; i++) {
			uint64_t t = quic[pn_offset+i];
			pn |= t << (pn_length-i-1)*8;
		}
		pkt->packet_number = imquic_full_packet_number(conn->largest[pkt->level], pn, pn_length*8);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Packet Num[%s]: %"SCNu64" (largest=%"SCNu64", pkn=%"SCNu64", pkn_len=%"SCNu8")\n",
			imquic_encryption_level_str(pkt->level), pkt->packet_number, conn->largest[pkt->level], pn, pn_length);
		/* Check if there's a phase change */
		if(pkt->key_phase != conn->current_phase) {
			/* Key phase change, update the keys */
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Detected key update to phase %d\n", pkt->key_phase);
			imquic_update_keys(&conn->keys[ssl_encryption_application], pkt->key_phase);
			conn->current_phase = pkt->key_phase;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_application, conn->is_server),
					conn->keys[ssl_encryption_application].local.key[conn->current_phase],
					conn->keys[ssl_encryption_application].local.key_len, conn->current_phase);
				imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_application, !conn->is_server),
					conn->keys[ssl_encryption_application].remote.key[conn->current_phase],
					conn->keys[ssl_encryption_application].remote.key_len, conn->current_phase);
			}
#endif
		}
		/* There's no payload length in Short headers, so the rest of the data is payload */
		p_len = blen - pn_offset;
	}

	if(p_len > 0 && p_len > pn_length) {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Payload (encrypted, %"SCNu64")\n", p_len - pn_length);
		imquic_print_hex(IMQUIC_LOG_HUGE, &quic[offset+pn_length], p_len - pn_length);
		/* Decrypt the payload */
		pkt->payload_offset = offset+pn_length;
		/* Check which keys we should use */
		uint8_t *key = conn->keys[pkt->level].remote.key[conn->current_phase];
		size_t key_len = conn->keys[pkt->level].remote.key_len;
		uint8_t *iv = conn->keys[pkt->level].remote.iv[conn->current_phase];
		size_t iv_len = conn->keys[pkt->level].remote.iv_len;
		int dlen = imquic_decrypt_payload(&quic[pkt->payload_offset], p_len - pn_length,
			pkt->payload.buffer, sizeof(pkt->payload),
			&quic[0], pkt->payload_offset, pkt->packet_number, key, key_len, iv, iv_len);
		if(dlen < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "Error decrypting packet\n");
			pkt->is_valid = FALSE;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *ph = imquic_qlog_prepare_packet_header(imquic_encryption_level_str(pkt->level),
					(lh ? &pkt->source : NULL), &pkt->destination);
				imquic_qlog_packet_dropped(conn->qlog, ph, conn->dgram_id_in, bytes, IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE);
			}
#endif
			return -1;
		}
		pkt->payload.length = dlen;
		pkt->is_encrypted = FALSE;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Payload (decrypted, %zu)\n", pkt->payload.length);
		imquic_print_hex(IMQUIC_LOG_HUGE, pkt->payload.buffer, pkt->payload.length);

		/* If we got here, the packet is good */
		pkt->is_valid = TRUE;
		conn->recvd[pkt->level] = g_list_prepend(conn->recvd[pkt->level], imquic_dup_uint64(pkt->packet_number));
		if(conn->largest[pkt->level] <= pkt->packet_number) {
			conn->largest[pkt->level] = pkt->packet_number;
			conn->largest_time[pkt->level] = g_get_monotonic_time();
		}

		/* Now parse the frames in the payload */
		imquic_parse_frames(conn, pkt);

		/* Done: the rest is padding (or another packet?) */
		pkt->data.length = pkt->payload_offset + pkt->payload.length;
		memcpy(pkt->data.buffer, quic, pkt->data.length);
		offset += p_len;
	} else {
		/* FIXME Is a QUIC packet with no payload broken? */
		pkt->is_encrypted = FALSE;
		pkt->data.length = offset + pn_length;
		memcpy(pkt->data.buffer, quic, pkt->data.length);

		/* If we got here, the packet is good */
		pkt->is_valid = TRUE;
		conn->recvd[pkt->level] = g_list_prepend(conn->recvd[pkt->level], imquic_dup_uint64(pkt->packet_number));
		if(conn->largest[pkt->level] <= pkt->packet_number) {
			conn->largest[pkt->level] = pkt->packet_number;
			conn->largest_time[pkt->level] = g_get_monotonic_time();
		}
	}

	/* Return the size of this packet */
	conn->last_activity = g_get_monotonic_time();
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		json_t *ph = imquic_qlog_prepare_packet_header(
			imquic_encryption_level_str(pkt->level),
			(lh ? &pkt->source : NULL),
			&pkt->destination);
		json_object_set_new(ph, "packet_number", json_integer(pkt->packet_number));
		imquic_qlog_packet_received(conn->qlog, ph, pkt->qlog_frames, conn->dgram_id_in, offset);
		pkt->qlog_frames = NULL;
	}
	if(pkt->qlog_frames != NULL)
		json_decref(pkt->qlog_frames);
	pkt->qlog_frames = NULL;
#endif
	return offset;
}

/* Helpers to parse frames */
int imquic_parse_frames(imquic_connection *conn, imquic_packet *pkt) {
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing frames\n", imquic_get_connection_name(conn));
	uint8_t *bytes = pkt->payload.buffer;
	size_t blen = pkt->payload.length;
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
	size_t offset = 0, padding = 0, parsed = 0;
#ifdef HAVE_QLOG
	/* If QLOG is enabled, create an array to add parsed frames to */
	if(conn->qlog != NULL && conn->qlog->quic) {
		if(pkt->qlog_frames != NULL)
			json_decref(pkt->qlog_frames);
		pkt->qlog_frames = json_array();
	}
#endif
	/* Iterate on all frames */
	pkt->ack_eliciting = FALSE;
	while(blen > 0 && !g_atomic_int_get(&conn->closed)) {
		imquic_frame_type type = bytes[offset];
		if(type == IMQUIC_PADDING) {
			padding++;
		} else {
			if(padding > 0) {
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s (%02x), %zu items\n", imquic_frame_type_str(IMQUIC_PADDING), IMQUIC_PADDING, padding);
				padding = 0;
			}
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s (%02x)\n", imquic_frame_type_str(type), bytes[offset]);
		}
		if(type == IMQUIC_PADDING) {
			/* Nothing else to do */
			offset++;
			blen--;
		} else if(type == IMQUIC_PING) {
			/* Nothing to do */
			pkt->ack_eliciting = TRUE;
			offset++;
			blen--;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *frame = imquic_qlog_prepare_packet_frame("ping");
				json_array_append_new(pkt->qlog_frames, frame);
			}
#endif
		} else if(type == IMQUIC_ACK || type == IMQUIC_ACK_WITH_ECN) {
			/* Parse this ACK frame */
			parsed = imquic_payload_parse_ack(conn, pkt, &bytes[offset], blen, pkt->level);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_RESET_STREAM) {
			/* Parse this RESET_STREAM frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_reset_stream(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_STOP_SENDING) {
			/* Parse this STOP_SENDING frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_stop_sending(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_CRYPTO) {
			/* Parse this CRYPTO frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_crypto(conn, pkt, &bytes[offset], blen, pkt->level);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_NEW_TOKEN) {
			/* Parse this NEW_TOKEN frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_new_token(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type >= IMQUIC_STREAM && type <= IMQUIC_STREAM_OLF) {
			/* Parse this STREAM frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_stream(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_MAX_DATA) {
			/* Parse this MAX_DATA frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_max_data(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_MAX_STREAM_DATA) {
			/* Parse this MAX_STREAM_DATA frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_max_stream_data(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_MAX_STREAMS || type == IMQUIC_MAX_STREAMS_UNI) {
			/* Parse this MAX_STREAMS frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_max_streams(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_DATA_BLOCKED) {
			/* Parse this DATA_BLOCKED frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_data_blocked(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_STREAM_DATA_BLOCKED) {
			/* Parse this STREAM_DATA_BLOCKED frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_stream_data_blocked(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_STREAMS_BLOCKED || type == IMQUIC_STREAMS_BLOCKED_UNI) {
			/* Parse this STREAMS_BLOCKED frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_streams_blocked(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_NEW_CONNECTION_ID) {
			/* Parse this NEW_CONNECTION_ID frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_new_connection_id(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_RETIRE_CONNECTION_ID) {
			/* Parse this RETIRE_CONNECTION_ID frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_retire_connection_id(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_PATH_CHALLENGE) {
			/* Parse this PATH_CHALLENGE frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_path_challenge(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_PATH_RESPONSE) {
			/* Parse this PATH_RESPONSE frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_path_response(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_CONNECTION_CLOSE || type == IMQUIC_CONNECTION_CLOSE_APP) {
			/* Parse this CONNECTION_CLOSE frame */
			parsed = imquic_payload_parse_connection_close(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else if(type == IMQUIC_HANDSHAKE_DONE) {
			/* Nothing to do */
			pkt->ack_eliciting = TRUE;
			offset++;
			blen--;
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *frame = imquic_qlog_prepare_packet_frame("handshake_done");
				json_array_append_new(pkt->qlog_frames, frame);
			}
#endif
		} else if(type >= IMQUIC_DATAGRAM && type <= IMQUIC_DATAGRAM_L) {
			/* Parse this DATAGRAM frame */
			pkt->ack_eliciting = TRUE;
			parsed = imquic_payload_parse_datagram(conn, pkt, &bytes[offset], blen);
			offset += parsed;
			blen -= parsed;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Unsupported frame '%02x' (%d)\n", type, type);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				json_t *frame = imquic_qlog_prepare_packet_frame("unknown");
				imquic_qlog_event_add_raw(frame, "raw", &bytes[offset], blen);
				/* TODO Add frame_type_bytes */
				json_array_append_new(pkt->qlog_frames, frame);
			}
#endif
			return -1;
		}
	}
	if(padding > 0) {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- %s (%02x), %zu items\n", imquic_frame_type_str(IMQUIC_PADDING), IMQUIC_PADDING, padding);
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic) {
			json_t *frame = imquic_qlog_prepare_packet_frame("padding");
			imquic_qlog_event_add_raw(frame, "raw", NULL, padding);
			json_array_append_new(pkt->qlog_frames, frame);
		}
#endif
		padding = 0;
	}
	return 0;
}

size_t imquic_payload_parse_ack(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, enum ssl_encryption_level_t level) {
	if(bytes == NULL || blen < 5 || (bytes[0] != IMQUIC_ACK && bytes[0] != IMQUIC_ACK_WITH_ECN))
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t largest = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Largest ACKed:   %"SCNu64" (length %"SCNu8")\n", largest, length);
	if(largest >= conn->largest_acked[level])
		conn->largest_acked[level] = largest;
	uint64_t delay = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ACK Delay:       %"SCNu64" --> %"SCNu64"ms (exp=%"SCNu8", length %"SCNu8")\n",
		delay, (delay << conn->remote_params.ack_delay_exponent), conn->remote_params.ack_delay_exponent, length);
	uint64_t rcount = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ACK Range Count: %"SCNu64" (length %"SCNu8")\n", rcount, length);
	uint64_t far = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- First ACK Range: %"SCNu64" (length %"SCNu8")\n", far, length);
#ifdef HAVE_QLOG
	json_t *frame = NULL;
	json_t *array = NULL;
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		frame = imquic_qlog_prepare_packet_frame("ack");
		json_object_set_new(frame, "ack_delay", json_integer(delay << conn->remote_params.ack_delay_exponent));
		array = json_array();
		json_t *range = json_array();
		if(far > 0)
			json_array_append_new(range, json_integer(largest - far));
		json_array_append_new(range, json_integer(largest));
		json_array_append_new(array, range);
		json_object_set_new(frame, "acked_ranges", array);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* Let's figure out which packets were explicitly ACKed */
	GList *acked = NULL;
	imquic_sent_packet *sent_pkt = NULL, *new_largest = NULL;
	gboolean ack_eliciting = FALSE;
	uint64_t i = 0, j = 0, pkt_num = largest;
	if(pkt_num >= far) {
		for(i = 0; i<= far; i++) {
			/* Add this packet number to the list of packets that were explicitly ACK-ed */
			acked = g_list_prepend(acked, imquic_dup_uint64(pkt_num));
			sent_pkt = imquic_listmap_find(conn->sent_pkts[level], &largest);
			if(sent_pkt != NULL && new_largest == NULL) {
				new_largest = sent_pkt;
				ack_eliciting = sent_pkt->ack_eliciting;
			}
			if(pkt_num > 0)
				pkt_num--;
		}
	}
	/* Traverse all ACK ranges in the frame, if there's any */
	if(rcount > 0) {
		uint64_t gap = 0, arl = 0;
		for(uint64_t i=0; i<rcount; i++) {
			gap = imquic_read_varint(&bytes[offset], blen-offset, &length);
			offset += length;
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- -- [%"SCNu64"] Gap:              %"SCNu64" (length %"SCNu8")\n", i, gap, length);
			if(pkt_num >= gap) {
				for(j = 0; j<= gap; j++) {
					/* This is a packet numbers that we did NOT get an ACK for */
					if(pkt_num > 0)
						pkt_num--;
				}
			}
			arl = imquic_read_varint(&bytes[offset], blen-offset, &length);
			offset += length;
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- -- [%"SCNu64"] ACK Range Length: %"SCNu64" (length %"SCNu8")\n", i, arl, length);
			if(pkt_num >= arl) {
				for(j = 0; j<= arl; j++) {
					/* Add this packet number to the list of packets that were explicitly ACK-ed */
					acked = g_list_prepend(acked, imquic_dup_uint64(pkt_num));
					sent_pkt = imquic_listmap_find(conn->sent_pkts[level], &largest);
					if(sent_pkt != NULL && new_largest == NULL) {
						new_largest = sent_pkt;
						ack_eliciting = sent_pkt->ack_eliciting;
					}
					if(pkt_num > 0)
						pkt_num--;
				}
			}
#ifdef HAVE_QLOG
			if(array != NULL) {
				json_t *range = json_array();
				json_array_append_new(range, json_integer(pkt_num + 1));
				json_array_append_new(range, json_integer(pkt_num + arl + 1));
				json_array_insert_new(array, 0, range);
			}
#endif
		}
	}
	if(bytes[0] == IMQUIC_ACK_WITH_ECN) {
		/* TODO Actually process ECN */
		uint64_t ect0 = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ECT0 Count: %"SCNu64" (length %"SCNu8")\n", ect0, length);
		uint64_t ect1 = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ECT1 Count: %"SCNu64" (length %"SCNu8")\n", ect1, length);
		uint64_t ecn_ce = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ECN-CE Count: %"SCNu64" (length %"SCNu8")\n", ecn_ce, length);
	}
#ifdef HAVE_QLOG
	if(frame != NULL)
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
#endif
	/* Check if it's time to update the RTT */
	if(ack_eliciting && new_largest && new_largest->packet_number == conn->largest_acked[level]) {
		/* Update RTT estimation */
		imquic_connection_update_rtt(conn, new_largest->sent_time, delay);
	}
	/* Remove all acked packets from the list of sent packets */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- ACKed packets (%d)\n", g_list_length(acked));
	GList *temp = acked;
	while(temp != NULL) {
		uint64_t *pn = (uint64_t *)temp->data;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- -- %"SCNu64" (%s)\n", *pn, imquic_encryption_level_str(level));
		imquic_sent_packet *sent_pkt = (imquic_sent_packet *)imquic_listmap_find(conn->sent_pkts[level], pn);
		if(sent_pkt != NULL) {
			if(sent_pkt->ack_eliciting && conn->ack_eliciting_in_flight[sent_pkt->level] > 0)
				conn->ack_eliciting_in_flight[sent_pkt->level]--;
			imquic_listmap_remove(conn->sent_pkts[level], &sent_pkt->packet_number);
		}
		/* TODO This is also used for congestion control, see OnPacketsAdded
		 * https://quicwg.org/base-drafts/rfc9002.html#appendix-B.5 */
		temp = temp->next;
	}
	g_list_free_full(acked, (GDestroyNotify)g_free);
	/* Get the list of lost packets */
	GList *lost = imquic_connection_detect_lost(conn);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Lost packets (%d)\n", g_list_length(lost));
	temp = lost;
	while(temp != NULL) {
		imquic_sent_packet *sent_pkt = (imquic_sent_packet *)temp->data;
		if(sent_pkt != NULL) {
			/* Retransmit this packet if needed, or get rid of it */
			IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- -- %"SCNu64" (%s)\n",
				sent_pkt->packet_number, imquic_encryption_level_str(sent_pkt->level));
			imquic_retransmit_packet(conn, sent_pkt);
		}
		/* TODO This is also used for congestion control, see OnPacketsLost
		 * https://quicwg.org/base-drafts/rfc9002.html#appendix-B.8 */
		temp = temp->next;
	}
	g_list_free(lost);
	/* Reset the PTO and the loss detection timer */
	conn->pto_count = 0;
	imquic_connection_update_loss_timer(conn);
	/* Done */
	return offset;
}

size_t imquic_payload_parse_reset_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 4 || bytes[0] != IMQUIC_RESET_STREAM)
		return 0;
	/* Stream has been reset */
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t stream_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stream ID:  %"SCNu64" (length %"SCNu8")\n", stream_id, length);
	uint64_t error = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Error Code: %"SCNu64" (%s) (length %"SCNu8")\n", error,
		conn->http3 ? imquic_http3_error_code_str(error) : imquic_error_code_str(error), length);
	uint64_t final = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Final Size: %"SCNu64" (length %"SCNu8")\n", final, length);
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Stream %"SCNu64" has been reset by the peer\n", stream_id);
		if(stream->in_state != IMQUIC_STREAM_COMPLETE)
			stream->in_state = IMQUIC_STREAM_RESET;
	}
	imquic_mutex_unlock(&conn->mutex);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("reset_stream");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "error_code", json_integer(error));
		json_object_set_new(frame, "final_size", json_integer(final));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_stop_sending(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 3 || bytes[0] != IMQUIC_STOP_SENDING)
		return 0;
	/* We've been asked to stop sending on this stream */
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t stream_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stream ID:  %"SCNu64" (length %"SCNu8")\n", stream_id, length);
	uint64_t error = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Error Code: %"SCNu64" (%s) (length %"SCNu8")\n", error,
		conn->http3 ? imquic_http3_error_code_str(error) : imquic_error_code_str(error), length);
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream != NULL) {
		/* TODO Check if we should send a CC with STREAM_STATE_ERROR */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "We've been asked to stop sending on stream %"SCNu64"\n", stream_id);
		stream->can_send = FALSE;
	}
	imquic_mutex_unlock(&conn->mutex);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stop_sending");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "error_code", json_integer(error));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_crypto(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, enum ssl_encryption_level_t level) {
	if(bytes == NULL || blen < 3 || bytes[0] != IMQUIC_CRYPTO)
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t crypto_offset = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Offset: %"SCNu64" (length %"SCNu8")\n", crypto_offset, length);
	uint64_t crypto_length = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Length: %"SCNu64" (length %"SCNu8")\n", crypto_length, length);
	if(crypto_length > 0) {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Payload\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], crypto_length);
		/* Copy the portion of the crypto data to the buffer */
		if(conn->crypto_in[level] == NULL)
			conn->crypto_in[level] = imquic_buffer_create(0);
		imquic_buffer_put(conn->crypto_in[level], &bytes[offset], crypto_offset, crypto_length);
		/* Move on */
		offset += crypto_length;
	}
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("crypto");
		json_object_set_new(frame, "offset", json_integer(crypto_offset));
		json_object_set_new(frame, "length", json_integer(crypto_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* Check if there's anything we can pass to the stack now */
	imquic_check_incoming_crypto(conn);
	return offset;
}

size_t imquic_payload_parse_new_token(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || bytes[0] != IMQUIC_NEW_TOKEN)
		return 0;
	/* TODO Actually do something with this */
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t token_length = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Length: %"SCNu64" (length %"SCNu8")\n", token_length, length);
	if(token_length > 0) {
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Payload\n");
		imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], token_length);
		offset += token_length;
	}
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("new_token");
		/* TODO Add token type and details */
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || (bytes[0] < IMQUIC_STREAM && bytes[0] > IMQUIC_STREAM_OLF))
		return 0;
	uint8_t obit = (bytes[0] & 0x04) >> 2;
	uint8_t lbit = (bytes[0] & 0x02) >> 1;
	uint8_t fbit = (bytes[0] & 0x01);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- OFF bit: %"SCNu8"\n", obit);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- LEN bit: %"SCNu8"\n", lbit);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- FIN bit: %"SCNu8"\n", fbit);
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t stream_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	uint64_t actual_id = 0;
	gboolean client_initiated = FALSE, bidirectional = FALSE;
	imquic_parse_stream_id(stream_id, &actual_id, &client_initiated, &bidirectional);
	if(client_initiated == conn->is_server) {
		if(bidirectional) {
			/* Check if we need to send a MAX_STREAMS to extend the limit */
			uint64_t threshold = conn->flow_control.local_max_streams_bidi/2;
			if(actual_id >= threshold) {
				conn->flow_control.local_max_streams_bidi *= 2;
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_streams (bidirectional): %"SCNu64"\n",
					imquic_get_connection_name(conn), conn->flow_control.local_max_streams_bidi);
				imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_STREAMS, 0);
			}
		} else {
			/* Check if we need to send a MAX_STREAMS to extend the limit */
			uint64_t threshold = conn->flow_control.local_max_streams_uni/2;
			if(actual_id >= threshold) {
				conn->flow_control.local_max_streams_uni *= 2;
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_streams (unidirectional): %"SCNu64"\n",
					imquic_get_connection_name(conn), conn->flow_control.local_max_streams_uni);
				imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_STREAMS_UNI, 0);
			}
		}
	}
	/* Is this an existing stream or a new one? */
	gboolean new_stream = FALSE;
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream == NULL) {
		/* Make sure the stream wasn't previousy done */
		if(g_hash_table_lookup(conn->streams_done, &stream_id) != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got data on completed stream %"SCNu64", ignoring\n",
				imquic_get_connection_name(conn), stream_id);
		} else {
			/* New stream, take note of it */
			stream = imquic_stream_create(stream_id, conn->socket->is_server);
			if(conn->socket->is_server != stream->client_initiated) {
				/* FIXME */
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got a new %s initiated stream (%"SCNu64"), but we're a %s, ignoring\n",
					imquic_get_connection_name(conn),
					stream->client_initiated ? "client" : "server", stream_id,
					conn->socket->is_server ? "server" : "client");
				imquic_stream_destroy(stream);
				stream = NULL;
			} else {
				new_stream = TRUE;
				IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Got new %s initiated %s stream '%"SCNu64"'\n",
					imquic_get_connection_name(conn),
					stream->client_initiated ? "client" : "server",
					stream->bidirectional ? "bidirectional" : "unidirectional", stream_id);
				g_hash_table_insert(conn->streams, imquic_dup_uint64(stream_id), stream);
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					imquic_qlog_stream_state_updated(conn->qlog, stream_id,
						(bidirectional ? "bidirectional" : "unidirectional"),
						(!bidirectional ? "receiving" : NULL), "open");
				}
#endif
				/* Flow control */
				if(bidirectional) {
					stream->local_max_data = conn->local_params.initial_max_stream_data_bidi_remote;
					stream->remote_max_data = conn->remote_params.initial_max_stream_data_bidi_local;
				} else {
					stream->local_max_data = conn->local_params.initial_max_stream_data_uni;
					stream->remote_max_data = conn->remote_params.initial_max_stream_data_uni;
				}
			}
		}
	} else if(!stream->can_receive || stream->in_state == IMQUIC_STREAM_INACTIVE) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got data on unidirectional stream, ignoring\n",
			imquic_get_connection_name(conn));
		stream = NULL;
	} else if(stream->in_state == IMQUIC_STREAM_BLOCKED || stream->in_state == IMQUIC_STREAM_RESET || stream->in_state == IMQUIC_STREAM_COMPLETE) {
		/* Stream is in a state that prevents handling data, ignore */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got data on %s stream, ignoring\n",
			imquic_get_connection_name(conn), imquic_stream_state_str(stream->in_state));
		stream = NULL;
	}
	if(stream != NULL)
		imquic_refcount_increase(&stream->ref);
	imquic_mutex_unlock(&conn->mutex);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stream ID: %"SCNu64" (length %"SCNu8")\n", stream_id, length);
	uint64_t stream_offset = 0;
	if(obit) {
		stream_offset = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Offset: %"SCNu64" (length %"SCNu8")\n", stream_offset, length);
	}
	uint64_t stream_length = 0;
	if(lbit) {
		stream_length = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Length: %"SCNu64" (length %"SCNu8")\n", stream_length, length);
	}
	if(stream_length == 0)
		stream_length = blen-offset;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Payload: (%"SCNu64")\n", stream_length);
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], stream_length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stream");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "offset", json_integer(stream_offset));
		json_object_set_new(frame, "length", json_integer(stream_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset + stream_length);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* If we have a stream instance, pass the data to the buffer */
	if(stream == NULL)
		goto done;
	imquic_mutex_lock(&stream->mutex);
	if(!imquic_stream_can_receive(stream, stream_offset, stream_length, TRUE)) {
		imquic_mutex_unlock(&stream->mutex);
		imquic_refcount_decrease(&stream->ref);
		goto done;
	}
	uint64_t added = imquic_buffer_put(stream->in_data, &bytes[offset], stream_offset, stream_length);
	if(added > 0) {
		stream->in_size += added;
		conn->flow_control.in_size += added;
	}
	/* Check if flow control was exceeded */
	if(stream->in_size > stream->local_max_data) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Flow control exceeded for stream %"SCNu64" (%"SCNu64" > %"SCNu64")\n",
			imquic_get_connection_name(conn), stream_id, stream->in_size, stream->local_max_data);
		/* Flow control limits exceeded (stream) */
		imquic_mutex_unlock(&stream->mutex);
		imquic_refcount_decrease(&stream->ref);
		imquic_connection_close(conn, IMQUIC_FLOW_CONTROL_ERROR, IMQUIC_STREAM, "Flow control limits exceeded (stream)");
		goto done;
	}
	if(conn->flow_control.in_size > conn->flow_control.local_max_data) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Flow control exceeded for connection (%"SCNu64" > %"SCNu64")\n",
			imquic_get_connection_name(conn), conn->flow_control.in_size, conn->flow_control.local_max_data);
		/* Flow control limits exceeded (connection) */
		imquic_mutex_unlock(&stream->mutex);
		imquic_refcount_decrease(&stream->ref);
		imquic_connection_close(conn, IMQUIC_FLOW_CONTROL_ERROR, IMQUIC_STREAM, "Flow control limits exceeded (connection)");
		goto done;
	}
	if(fbit)
		imquic_stream_mark_complete(stream, TRUE);
	/* What should we do with the data now? */
	imquic_buffer_chunk *chunk = NULL;
	while((chunk = imquic_buffer_get(stream->in_data)) != NULL) {
		if(stream->in_finalsize > 0 && imquic_buffer_peek(stream->in_data) == NULL)
			stream->in_state = IMQUIC_STREAM_COMPLETE;
		imquic_mutex_unlock(&stream->mutex);
		if(conn->http3 != NULL) {
			/* Process the data as HTTP/3 */
			imquic_http3_process_stream_data(conn, stream, chunk, new_stream);
		} else {
			/* Pass the data to the application callback */
			imquic_connection_notify_stream_incoming(conn, stream, chunk->data, chunk->offset, chunk->length);
		}
		imquic_buffer_chunk_free(chunk);
		imquic_mutex_lock(&stream->mutex);
	}
	if(imquic_stream_is_done(stream)) {
		imquic_mutex_unlock(&stream->mutex);
		IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Stream %"SCNu64" is done, removing it\n",
			imquic_get_connection_name(conn), stream_id);
		/* FIXME */
		imquic_mutex_lock(&conn->mutex);
		g_hash_table_remove(conn->streams, &stream_id);
		g_hash_table_insert(conn->streams_done, imquic_dup_uint64(stream_id), GINT_TO_POINTER(1));
		imquic_mutex_unlock(&conn->mutex);
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic)
			imquic_qlog_stream_state_updated(conn->qlog, stream_id, NULL, NULL, "closed");
#endif
	} else {
		imquic_mutex_unlock(&stream->mutex);
	}
	if(stream != NULL)
		imquic_refcount_decrease(&stream->ref);
done:
	/* Move on */
	offset += stream_length;
	return offset;
}

size_t imquic_payload_parse_max_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || bytes[0] != IMQUIC_MAX_DATA)
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t maximum = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Maximum Data: %"SCNu64" (length %"SCNu8")\n", maximum, length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_data");
		json_object_set_new(frame, "maximum", json_integer(maximum));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Update the info we had */
	if(maximum > conn->flow_control.remote_max_data) {
		conn->flow_control.remote_max_data = maximum;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got new max_data from peer: %"SCNu64"\n",
			imquic_get_connection_name(conn), conn->flow_control.remote_max_data);
		/* Check if we can unblock any stream */
		imquic_mutex_lock(&conn->mutex);
		uint64_t *blocked_stream_id = NULL, stream_id = 0;
		gboolean found = FALSE;
		imquic_listmap_traverse(conn->blocked_streams);
		while((blocked_stream_id = imquic_listmap_next(conn->blocked_streams, &found)) != NULL && found) {
			stream_id = *blocked_stream_id;
			imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
			if(stream != NULL) {
				if(stream->out_size < stream->remote_max_data &&
						conn->flow_control.out_size < conn->flow_control.remote_max_data) {
					/* Unblock the stream so that we can send data again */
					imquic_listmap_prev(conn->blocked_streams, &found);
					imquic_listmap_remove(conn->blocked_streams, &stream->stream_id);
					g_queue_push_tail(conn->outgoing_data, imquic_dup_uint64(stream->stream_id));
				}
			}
		}
		imquic_mutex_unlock(&conn->mutex);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Ignoring new max_data from peer (%"SCNu64" <= %"SCNu64")\n",
			imquic_get_connection_name(conn), maximum, conn->flow_control.remote_max_data);
	}
	return offset;
}

size_t imquic_payload_parse_max_stream_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 3 || bytes[0] != IMQUIC_MAX_STREAM_DATA)
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t stream_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stream ID:    %"SCNu64" (length %"SCNu8")\n", stream_id, length);
	uint64_t maximum = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Maximum Data: %"SCNu64" (length %"SCNu8")\n", maximum, length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_stream_data");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "maximum", json_integer(maximum));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Update the info we had */
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream != NULL) {
		if(maximum > stream->remote_max_data) {
			stream->remote_max_data = maximum;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got new max_data for stream %"SCNu64" from peer: %"SCNu64"\n",
				imquic_get_connection_name(conn), stream_id, stream->remote_max_data);
			/* Check if we can unblock this stream */
			if(stream->out_size < stream->remote_max_data &&
					conn->flow_control.out_size < conn->flow_control.remote_max_data &&
					imquic_listmap_find(conn->blocked_streams, &stream->stream_id) != NULL) {
				/* Unblock the stream so that we can send data again */
				imquic_listmap_remove(conn->blocked_streams, &stream->stream_id);
				g_queue_push_tail(conn->outgoing_data, imquic_dup_uint64(stream->stream_id));
			}
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Ignoring new max_data for stream %"SCNu64" from peer (%"SCNu64" <= %"SCNu64")\n",
				imquic_get_connection_name(conn), stream_id, maximum, conn->flow_control.remote_max_data);
		}
	}
	imquic_mutex_unlock(&conn->mutex);
	return offset;
}

size_t imquic_payload_parse_max_streams(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || (bytes[0] != IMQUIC_MAX_STREAMS && bytes[0] != IMQUIC_MAX_STREAMS_UNI))
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t maximum = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Maximum Streams: %"SCNu64" (length %"SCNu8")\n", maximum, length);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Applied to:      %s\n", (bytes[0] == IMQUIC_MAX_STREAMS ? "bidirectional" : "unidirectional"));
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_streams");
		json_object_set_new(frame, "stream_type", json_string(bytes[0] == IMQUIC_MAX_STREAMS ? "bidirectional" : "unidirectional"));
		json_object_set_new(frame, "maximum", json_integer(maximum));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Update the info we had */
	if(bytes[0] == IMQUIC_MAX_STREAMS) {
		/* Update on bidirectional streams */
		if(maximum > conn->flow_control.remote_max_streams_bidi) {
			conn->flow_control.remote_max_streams_bidi = maximum;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got new bidirectional max_streams from peer: %"SCNu64"\n",
				imquic_get_connection_name(conn), conn->flow_control.remote_max_streams_bidi);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Ignoring new bidirectional max_streams from peer (%"SCNu64" <= %"SCNu64")\n",
				imquic_get_connection_name(conn), maximum, conn->flow_control.remote_max_streams_bidi);
		}
	} else {
		/* Update on unirectional streams */
		if(maximum > conn->flow_control.remote_max_streams_uni) {
			conn->flow_control.remote_max_streams_uni = maximum;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got new unirectional max_streams from peer: %"SCNu64"\n",
				imquic_get_connection_name(conn), conn->flow_control.remote_max_streams_uni);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Ignoring new unirectional max_streams from peer (%"SCNu64" <= %"SCNu64")\n",
				imquic_get_connection_name(conn), maximum, conn->flow_control.remote_max_streams_uni);
		}
	}
	return offset;
}

size_t imquic_payload_parse_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || bytes[0] != IMQUIC_DATA_BLOCKED)
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t limit = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Limited Data: %"SCNu64" (length %"SCNu8")\n", limit, length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("data_blocked");
		json_object_set_new(frame, "limit", json_integer(limit));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Let's react by giving more credit (TODO Should we involve the application?) */
	while(limit >= conn->flow_control.local_max_data)
		conn->flow_control.local_max_data *= 2;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_data: %"SCNu64"\n",
		imquic_get_connection_name(conn), conn->flow_control.local_max_data);
	imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_DATA, 0);
	return offset;
}

size_t imquic_payload_parse_stream_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 3 || bytes[0] != IMQUIC_STREAM_DATA_BLOCKED)
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t stream_id = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stream ID:    %"SCNu64" (length %"SCNu8")\n", stream_id, length);
	uint64_t limit = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Limited Data: %"SCNu64" (length %"SCNu8")\n", limit, length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stream_data_blocked");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "limit", json_integer(limit));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Let's react by giving more credit (TODO Should we involve the application?) */
	imquic_mutex_lock(&conn->mutex);
	imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
	if(stream != NULL) {
		while(limit >= stream->local_max_data)
			stream->local_max_data *= 2;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_data for stream %"SCNu64": %"SCNu64"\n",
			imquic_get_connection_name(conn), stream_id, stream->local_max_data);
		imquic_mutex_unlock(&conn->mutex);
		imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_STREAM_DATA, stream_id);
	} else {
		imquic_mutex_unlock(&conn->mutex);
	}
	return offset;
}

size_t imquic_payload_parse_streams_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || (bytes[0] != IMQUIC_STREAMS_BLOCKED && bytes[0] != IMQUIC_STREAMS_BLOCKED_UNI))
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t limit = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Limited Streams: %"SCNu64" (length %"SCNu8")\n", limit, length);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Applied to:      %s\n", (bytes[0] == IMQUIC_STREAMS_BLOCKED ? "bidirectional" : "unidirectional"));
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("streams_blocked");
		json_object_set_new(frame, "stream_type", json_string(bytes[0] == IMQUIC_STREAMS_BLOCKED ? "bidirectional" : "unidirectional"));
		json_object_set_new(frame, "limit", json_integer(limit));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* FIXME Let's react by giving more credit (TODO Should we involve the application?) */
	if(bytes[0] == IMQUIC_STREAMS_BLOCKED) {
		while(limit >= conn->flow_control.local_max_streams_bidi)
			conn->flow_control.local_max_streams_bidi *= 2;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_streams (bidirectional): %"SCNu64"\n",
			imquic_get_connection_name(conn), conn->flow_control.local_max_streams_bidi);
		imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_STREAMS, 0);
	} else {
		while(limit >= conn->flow_control.local_max_streams_uni)
			conn->flow_control.local_max_streams_uni *= 2;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Increasing max_streams (undirectional): %"SCNu64"\n",
			imquic_get_connection_name(conn), conn->flow_control.local_max_streams_uni);
		imquic_send_credits(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid), IMQUIC_MAX_STREAMS_UNI, 0);
	}
	return offset;
}

size_t imquic_payload_parse_new_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 20 || bytes[0] != IMQUIC_NEW_CONNECTION_ID)
		return 0;
	/* TODO Actually do something with this */
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t seq = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Sequence Number: %"SCNu64" (length %"SCNu8")\n", seq, length);
	uint64_t retire = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Retire Prior to: %"SCNu64" (length %"SCNu8")\n", retire, length);
	uint8_t cid_len = bytes[offset];
	if(cid_len < 1 || cid_len > 20) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid Length %"SCNu8"\n", cid_len);
		return 0;
	}
	offset++;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Length:          %"SCNu8"\n", cid_len);
	char cid[41];
	const char *cid_str = imquic_hex_str(&bytes[offset], cid_len, cid, sizeof(cid));
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Connection ID:   %s\n", cid_str);
	/* TODO Keep track of it */
	//~ imquic_connection_id new_remote_cid = { 0 };
	//~ new_remote_cid.seq = seq;
	//~ new_remote_cid.len = cid_len;
	//~ memcpy(new_remote_cid.id, &bytes[offset], cid_len);
	//~ if(g_hash_table_lookup(connections, &new_remote_cid) == NULL) {
		//~ g_hash_table_insert(connections, imquic_connection_id_dup(&new_remote_cid), conn);
		//~ imquic_refcount_increase(&conn->ref);
	//~ }
	offset += cid_len;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Stateless Reset Token\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], 16);
	//~ memcpy(new_remote_cid.token, &bytes[offset], 16);
	offset += 16;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("new_connection_id");
		json_object_set_new(frame, "sequence_number", json_integer(seq));
		json_object_set_new(frame, "retire_prior_to", json_integer(retire));
		json_object_set_new(frame, "connection_id", json_string(cid_str));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_retire_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || bytes[0] != IMQUIC_RETIRE_CONNECTION_ID)
		return 0;
	/* TODO Actually do something with this */
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t seq = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Sequence Number: %"SCNu64" (length %"SCNu8")\n", seq, length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("retire_connection_id");
		json_object_set_new(frame, "sequence_number", json_integer(seq));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_path_challenge(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 9 || bytes[0] != IMQUIC_PATH_CHALLENGE)
		return 0;
	/* TODO Actually do something with this */
	size_t offset = 1;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Data\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], 8);
	offset += 8;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("path_challenge");
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_path_response(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 9 || bytes[0] != IMQUIC_PATH_CHALLENGE)
		return 0;
	/* TODO Actually do something with this */
	size_t offset = 1;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Data\n");
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], 8);
	offset += 8;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("path_response");
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	return offset;
}

size_t imquic_payload_parse_connection_close(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 3 || (bytes[0] != IMQUIC_CONNECTION_CLOSE && bytes[0] != IMQUIC_CONNECTION_CLOSE_APP))
		return 0;
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t error = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Error Code: %"SCNu64" (%s) (length %"SCNu8")\n", error, imquic_error_code_str(error), length);
	uint64_t trigger = 0;
	if(bytes[0] == IMQUIC_CONNECTION_CLOSE) {
		trigger = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Frame Type: %"SCNu64" (length %"SCNu8")\n", trigger, length);
	}
	uint64_t rlen = imquic_read_varint(&bytes[offset], blen-offset, &length);
	offset += length;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Reason (len): %"SCNu64" (length %"SCNu8")\n", rlen, length);
	char reason[256];
	reason[0] = '\0';
	if(rlen > 0) {
		g_snprintf(reason, sizeof(reason), "%.*s", (int)rlen, &bytes[offset]);
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Reason Phrase: %s\n", reason);
		offset += rlen;
	}
#if HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		imquic_qlog_connection_closed(conn->qlog, FALSE,
			(bytes[0] == IMQUIC_CONNECTION_CLOSE ? error : 0),
			(bytes[0] == IMQUIC_CONNECTION_CLOSE_APP ? error : 0),
			(rlen > 0 ? reason : NULL));
		if(pkt != NULL && pkt->qlog_frames != NULL) {
			json_t *frame = imquic_qlog_prepare_packet_frame("connection_close");
			json_object_set_new(frame, "error_space", json_string(bytes[0] == IMQUIC_CONNECTION_CLOSE_APP ? "application" : "transport"));
			json_object_set_new(frame, "error_code", json_integer(error));
			if(rlen > 0)
				json_object_set_new(frame, "reason", json_string(reason));
			if(bytes[0] == IMQUIC_CONNECTION_CLOSE)
				json_object_set_new(frame, "trigger_frame_type", json_integer(trigger));
			imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
			json_array_append_new(pkt->qlog_frames, frame);
		}
	}
#endif
	/* Notify the application that the connection is gone */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Connection closed by peer%s%s\n",
		imquic_get_connection_name(conn), (rlen > 0 ? ": " : ""), (rlen > 0 ? reason : ""));
	conn->should_close = TRUE;
	/* Done */
	return offset;
}

size_t imquic_payload_parse_datagram(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	if(bytes == NULL || blen < 2 || (bytes[0] != IMQUIC_DATAGRAM && bytes[0] != IMQUIC_DATAGRAM_L))
		return 0;
	uint8_t lbit = (bytes[0] & 0x01);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- LEN bit: %"SCNu8"\n", lbit);
	size_t offset = 1;
	uint8_t length = 0;
	uint64_t datagram_length = 0;
	if(lbit) {
		datagram_length = imquic_read_varint(&bytes[offset], blen-offset, &length);
		offset += length;
		IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Length: %"SCNu64" (length %"SCNu8")\n", datagram_length, length);
	}
	if(datagram_length == 0)
		datagram_length = blen-offset;
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- -- Payload: (%"SCNu64")\n", datagram_length);
	imquic_print_hex(IMQUIC_LOG_HUGE, &bytes[offset], datagram_length);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL && pkt->qlog_frames != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("datagram");
		json_object_set_new(pkt->qlog_frames, "length", json_integer(datagram_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset + datagram_length + 1);
		json_array_append_new(pkt->qlog_frames, frame);
	}
#endif
	/* Pass the data to the application callback */
	imquic_connection_notify_datagram_incoming(conn, &bytes[offset], datagram_length);
	/* Move on */
	offset += datagram_length;
	return offset;
}

/* Helpers to add frames to a payload */
size_t imquic_payload_add_padding(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, size_t padding) {
	if(padding > blen) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Requested padding is larger than the available buffer, truncating\n");
		padding = blen;
	}
	if(padding > 0)
		memset(bytes, 0, padding);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("padding");
		imquic_qlog_event_add_raw(frame, "raw", NULL, padding);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return padding;
}

size_t imquic_payload_add_ping(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	bytes[0] = IMQUIC_PING;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("ping");
		imquic_qlog_event_add_raw(frame, "raw", NULL, 1);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return 1;
}

size_t imquic_payload_add_ack(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, GList *received, uint64_t delay, uint64_t *ecn_counts) {
	if(received == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Empty list, not adding any ACK frame\n");
		return 0;
	}
	size_t offset = 0;
	bytes[offset] = ecn_counts ? IMQUIC_ACK_WITH_ECN : IMQUIC_ACK;
	offset++;
	/* Traverse the list to build the list: the first is the largest received */
	uint64_t *pkn = (uint64_t *)received->data;
	offset += imquic_write_varint(*pkn, &bytes[offset], blen-offset);
	offset += imquic_write_varint(delay, &bytes[offset], blen-offset);
	/* Figure out how many ranges we need */
	uint64_t ranges = 0, first_range = 0, last_pkn = *pkn, *current_pkn = NULL;
	int16_t sequence = 0;
	GList *temp = received->next, *series = NULL;
	gboolean first = TRUE;
	while(temp && last_pkn > 0) {
		current_pkn = (uint64_t *)temp->data;
		if(*current_pkn == last_pkn - 1) {
			/* No gap from previous packet */
			if(first) {
				first_range++;
			} else {
				sequence++;
			}
		} else {
			/* There's a gap, we'll need a range */
			ranges++;
			if(!first)
				series = g_list_append(series, GINT_TO_POINTER(sequence));
			first = FALSE;
			sequence = -(last_pkn - *current_pkn - 1);
			series = g_list_append(series, GINT_TO_POINTER(sequence));
			sequence = 1;
		}
		last_pkn = *current_pkn;
		temp = temp->next;
	}
	if(!first)
		series = g_list_append(series, GINT_TO_POINTER(sequence >= 0 ? sequence : 0));
	offset += imquic_write_varint(ranges, &bytes[offset], blen-offset);
	offset += imquic_write_varint(first_range, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	json_t *array = NULL;
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		array = json_array();
		json_t *range = json_array();
		if(first_range > 0)
			json_array_append_new(range, json_integer(*pkn - first_range));
		json_array_append_new(range, json_integer(*pkn));
		json_array_append_new(array, range);
	}
	uint64_t index = *pkn - first_range;
#endif
	temp = series;
	while(temp) {
		int16_t seq = GPOINTER_TO_INT(temp->data);
		if(seq < 0) {
			seq = -seq;
			offset += imquic_write_varint((uint64_t)(seq - 1), &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
			if(array != NULL)
				index -= seq;
#endif
		} else {
			if(seq == 0)	/* FIXME */
				seq++;
			offset += imquic_write_varint((uint64_t)(seq - 1), &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
			if(array != NULL) {
				json_t *range = json_array();
				json_array_append_new(range, json_integer(index - seq));
				json_array_append_new(range, json_integer(index - 1));
				json_array_insert_new(array, 0, range);
				index -= seq;
			}
#endif
		}
		temp = temp->next;
	}
	g_list_free(series);
	if(ecn_counts) {
		offset += imquic_write_varint(ecn_counts[0], &bytes[offset], blen-offset);
		offset += imquic_write_varint(ecn_counts[1], &bytes[offset], blen-offset);
		offset += imquic_write_varint(ecn_counts[2], &bytes[offset], blen-offset);
	}
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("ack");
		json_object_set_new(frame, "ack_delay", json_integer(delay << conn->local_params.ack_delay_exponent));
		json_object_set_new(frame, "acked_ranges", array);
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_reset_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t error_code, uint64_t final_size) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_RESET_STREAM;
	offset++;
	offset += imquic_write_varint(stream_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error_code, &bytes[offset], blen-offset);
	offset += imquic_write_varint(final_size, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("reset_stream");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "error_code", json_integer(error_code));
		json_object_set_new(frame, "final_size", json_integer(final_size));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_stop_sending(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t error_code) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_STOP_SENDING;
	offset++;
	offset += imquic_write_varint(stream_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(error_code, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stop_sending");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "error_code", json_integer(error_code));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_crypto(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *crypto, size_t crypto_offset, size_t crypto_length) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_CRYPTO;
	offset++;
	offset += imquic_write_varint(crypto_offset, &bytes[offset], blen-offset);
	offset += imquic_write_varint(crypto_length, &bytes[offset], blen-offset);
	memcpy(&bytes[offset], crypto, crypto_length);
	offset += crypto_length;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("crypto");
		json_object_set_new(frame, "offset", json_integer(crypto_offset));
		json_object_set_new(frame, "length", json_integer(crypto_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_new_token(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *token, size_t token_length) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_NEW_TOKEN;
	offset++;
	offset += imquic_write_varint(token_length, &bytes[offset], blen-offset);
	memcpy(&bytes[offset], token, token_length);
	offset += token_length;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("new_token");
		/* TODO Add token type and details */
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_stream(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint8_t *stream, size_t stream_offset, size_t stream_length, gboolean complete, gboolean last) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_STREAM |
		(stream_offset > 0 ? 0x04 : 0x00) |
		(!last ? 0x02 : 0x00) |
		(complete ? 0x01 : 0x00);
	offset++;
	offset += imquic_write_varint(stream_id, &bytes[offset], blen-offset);
	if(stream_offset > 0)
		offset += imquic_write_varint(stream_offset, &bytes[offset], blen-offset);
	if(!last)
		offset += imquic_write_varint(stream_length, &bytes[offset], blen-offset);
	memcpy(&bytes[offset], stream, stream_length);
	offset += stream_length;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stream");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "offset", json_integer(stream_offset));
		json_object_set_new(frame, "length", json_integer(stream_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_max_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t max_data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_MAX_DATA;
	offset++;
	offset += imquic_write_varint(max_data, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_data");
		json_object_set_new(frame, "maximum", json_integer(max_data));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_max_stream_data(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t max_data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_MAX_STREAM_DATA;
	offset++;
	offset += imquic_write_varint(stream_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(max_data, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_stream_data");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "maximum", json_integer(max_data));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_max_streams(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, gboolean bidirectional, uint64_t max_streams) {
	size_t offset = 0;
	bytes[offset] = bidirectional ? IMQUIC_MAX_STREAMS : IMQUIC_MAX_STREAMS_UNI;
	offset++;
	offset += imquic_write_varint(max_streams, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("max_streams");
		json_object_set_new(frame, "stream_type", json_string(bidirectional ? "bidirectional" : "unidirectional"));
		json_object_set_new(frame, "maximum", json_integer(max_streams));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t max_data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_DATA_BLOCKED;
	offset++;
	offset += imquic_write_varint(max_data, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("data_blocked");
		json_object_set_new(frame, "limit", json_integer(max_data));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_stream_data_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t stream_id, uint64_t max_data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_STREAM_DATA_BLOCKED;
	offset++;
	offset += imquic_write_varint(stream_id, &bytes[offset], blen-offset);
	offset += imquic_write_varint(max_data, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("stream_data_blocked");
		json_object_set_new(frame, "stream_id", json_integer(stream_id));
		json_object_set_new(frame, "limit", json_integer(max_data));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_streams_blocked(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, gboolean bidirectional, uint64_t max_streams) {
	size_t offset = 0;
	bytes[offset] = bidirectional ? IMQUIC_STREAMS_BLOCKED : IMQUIC_STREAMS_BLOCKED_UNI;
	offset++;
	offset += imquic_write_varint(max_streams, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("streams_blocked");
		json_object_set_new(frame, "stream_type", json_string(bidirectional ? "bidirectional" : "unidirectional"));
		json_object_set_new(frame, "limit", json_integer(max_streams));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_new_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t seqnum, uint64_t retire_prior_to, imquic_connection_id *cid, uint8_t *reset_token) {
	if(cid == NULL || cid->len < 1 || cid->len > 20) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid connection ID, can't add frame\n");
		return 0;
	}
	size_t offset = 0;
	bytes[offset] = IMQUIC_NEW_CONNECTION_ID;
	offset++;
	offset += imquic_write_varint(seqnum, &bytes[offset], blen-offset);
	offset += imquic_write_varint(retire_prior_to, &bytes[offset], blen-offset);
	bytes[offset] = cid->len;
	offset++;
	memcpy(&bytes[offset], cid->id, cid->len);
	offset += cid->len;
	memcpy(&bytes[offset], reset_token, 16);
	offset += 16;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("new_connection_id");
		json_object_set_new(frame, "sequence_number", json_integer(seqnum));
		json_object_set_new(frame, "retire_prior_to", json_integer(retire_prior_to));
		char cid_str[41];
		json_object_set_new(frame, "connection_id", json_string(imquic_connection_id_str(cid, cid_str, sizeof(cid_str))));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_retire_connection_id(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint64_t seqnum) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_RETIRE_CONNECTION_ID;
	offset++;
	offset += imquic_write_varint(seqnum, &bytes[offset], blen-offset);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("retire_connection_id");
		json_object_set_new(frame, "sequence_number", json_integer(seqnum));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_path_challenge(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_PATH_CHALLENGE;
	memcpy(&bytes[offset], data, 8);
	offset += 8;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("path_challenge");
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_path_response(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *data) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_PATH_RESPONSE;
	memcpy(&bytes[offset], data, 8);
	offset += 8;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("path_response");
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_connection_close(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, imquic_error_code error_code, imquic_frame_type frame_type, const char *reason) {
	size_t offset = 0;
	bytes[offset] = frame_type ? IMQUIC_CONNECTION_CLOSE : IMQUIC_CONNECTION_CLOSE_APP;
	offset++;
	bytes[offset] = error_code;
	offset++;
	if(frame_type > 0) {
		bytes[offset] = frame_type;
		offset++;
	}
	size_t reason_len = reason ? strlen(reason) : 0;
	if(reason_len == 0) {
		bytes[offset] = 0;	/* No reason */
		offset++;
	} else {
		offset += imquic_write_varint(reason_len, &bytes[offset], 2);
		memcpy(&bytes[offset], reason, reason_len);
		offset += reason_len;
	}
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("connection_close");
		json_object_set_new(frame, "error_space", json_string(bytes[0] == IMQUIC_CONNECTION_CLOSE_APP ? "application" : "transport"));
		json_object_set_new(frame, "error_code", json_integer(error_code));
		if(reason != NULL)
			json_object_set_new(frame, "reason", json_string(reason));
		if(bytes[0] == IMQUIC_CONNECTION_CLOSE)
			json_object_set_new(frame, "trigger_frame_type", json_integer(frame_type));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

size_t imquic_payload_add_handshake_done(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen) {
	bytes[0] = IMQUIC_HANDSHAKE_DONE;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("handshake_done");
		imquic_qlog_event_add_raw(frame, "raw", NULL, 1);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return 1;
}

size_t imquic_payload_add_datagram(imquic_connection *conn, imquic_packet *pkt, uint8_t *bytes, size_t blen, uint8_t *datagram, size_t datagram_length, gboolean last) {
	size_t offset = 0;
	bytes[offset] = IMQUIC_DATAGRAM |
		(!last ? 0x01 : 0x00);
	offset++;
	if(!last)
		offset += imquic_write_varint(datagram_length, &bytes[offset], blen-offset);
	memcpy(&bytes[offset], datagram, datagram_length);
	offset += datagram_length;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic && pkt != NULL) {
		json_t *frame = imquic_qlog_prepare_packet_frame("datagram");
		json_object_set_new(pkt->qlog_frames, "length", json_integer(datagram_length));
		imquic_qlog_event_add_raw(frame, "raw", NULL, offset);
		if(pkt->qlog_frame != NULL)
			json_decref(pkt->qlog_frame);
		pkt->qlog_frame = frame;
	}
#endif
	return offset;
}

/* Helpers to add transport parameters to a buffer */
size_t imquic_transport_parameter_add_novalue(uint8_t *bytes, size_t blen, imquic_transport_parameter param) {
	if(bytes == NULL || blen == 0)
		return 0;
	return imquic_write_varint(param, &bytes[0], blen);
}
size_t imquic_transport_parameter_add_int(uint8_t *bytes, size_t blen, imquic_transport_parameter param, uint64_t number) {
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	uint8_t buffer[8];
	uint8_t length = imquic_write_varint(number, buffer, sizeof(buffer));
	offset += imquic_write_varint(length, &bytes[offset], blen-offset);
	if(length > blen-offset) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Insufficient buffer (%"SCNu8" > %zu), truncating...\n", length, blen-offset);
		length = blen-offset;
	}
	memcpy(&bytes[offset], buffer, length);
	offset += length;
	return offset;
}
size_t imquic_transport_parameter_add_data(uint8_t *bytes, size_t blen, imquic_transport_parameter param, uint8_t *buf, size_t buflen) {
	if(bytes == NULL || blen == 0)
		return 0;
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	uint8_t buffer[8];
	uint8_t length = imquic_write_varint(buflen, buffer, sizeof(buffer));
	memcpy(&bytes[offset], buffer, length);
	offset += length;
	if(buflen > 0) {
		memcpy(&bytes[offset], buf, buflen);
		offset += buflen;
	}
	return offset;
}
size_t imquic_transport_parameter_add_connection_id(uint8_t *bytes, size_t blen, imquic_transport_parameter param, imquic_connection_id *cid) {
	if(bytes == NULL || blen == 0 || cid == NULL)
		return 0;
	size_t offset = imquic_write_varint(param, &bytes[0], blen);
	uint8_t buffer[8];
	uint8_t length = imquic_write_varint(cid->len, buffer, sizeof(buffer));
	memcpy(&bytes[offset], buffer, length);
	offset += length;
	if(cid->len > 0) {
		memcpy(&bytes[offset], cid->id, cid->len);
		offset += cid->len;
	}
	return offset;
}

/* Parsers */
int imquic_parse_transport_parameters(imquic_connection *conn, uint8_t *bytes, size_t blen) {
	/* Store those transport parameters in the connection state */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Parsing transport parameters (%zu bytes)\n",
		imquic_get_connection_name(conn), blen);
	imquic_print_hex(IMQUIC_LOG_HUGE, bytes, blen);
#ifdef HAVE_QLOG
	/* Trace events, if needed */
	json_t *data = NULL;
	if(conn != NULL && conn->qlog != NULL && conn->qlog->quic) {
		/* TODO Set resumption properly */
		data = imquic_qlog_prepare_parameters_set(conn->qlog, FALSE, FALSE, conn->socket->tls->early_data);
	}
#endif
	int res = 0;
	size_t offset = 0, param_offset;
	uint8_t length = 0;
	uint64_t param = 0, p_len = 0;
	while(blen - offset > 0) {
		param_offset = offset;
		param = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		p_len = imquic_read_varint(bytes + offset, blen - offset, &length);
		offset += length;
		if(p_len > blen - offset) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Broken transport parameters at offset %zu (%"SCNu64" > %zu)\n",
				imquic_get_connection_name(conn), offset, p_len, blen - offset);
			imquic_print_hex(IMQUIC_LOG_HUGE, bytes + param_offset, blen - offset);
			res = -1;
			goto done;
		}
		switch(param) {
			case IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID:
			case IMQUIC_INITIAL_SOURCE_CONNECTION_ID:
			case IMQUIC_RETRY_SOURCE_CONNECTION_ID: {
				/* A connection ID */
				if(p_len > 20) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid connection ID (len=%"SCNu64")\n",
						imquic_get_connection_name(conn), p_len);
					imquic_print_hex(IMQUIC_LOG_HUGE, bytes + param_offset, p_len);
					res = -1;
					goto done;
				}
				if(conn != NULL && conn->is_server && param == IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] A client can't send 'original_destination_connection_id'\n",
						imquic_get_connection_name(conn));
					res = -1;
					goto done;
				}
				imquic_connection_id cid;
				cid.len = p_len;
				if(p_len > 0)
					memcpy(cid.id, bytes + offset, p_len);
				char cid_str[41];
				const char *cid_str_ = imquic_connection_id_str(&cid, cid_str, sizeof(cid_str));
				size_t cid_len = p_len * 2;
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %.*s\n",
					param, imquic_transport_parameter_str(param),
					p_len, (int)cid_len, cid_str_);
				/* TODO We should check if things match */
				if(conn != NULL && param == IMQUIC_INITIAL_SOURCE_CONNECTION_ID) {
					/* FIXME Replace the remote ID */
					memcpy(conn->remote_cid.id, cid.id, cid.len);
					conn->remote_cid.len = cid.len;
				}
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_string(cid_str_));
#endif
				break;
			}
			case IMQUIC_STATELESS_RESET_TOKEN: {
				/* A buffer */
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"]\n",
					param, imquic_transport_parameter_str(param), p_len);
				imquic_print_hex(IMQUIC_LOG_HUGE, bytes + offset, p_len);
#ifdef HAVE_QLOG
				if(data != NULL) {
					char st[33];
					const char *st_str = imquic_hex_str(bytes + offset, p_len, st, sizeof(st));
					json_object_set_new(data, imquic_transport_parameter_str(param), json_string(st_str));
				}
#endif
				break;
			}
			case IMQUIC_MAX_IDLE_TIMEOUT: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL)
					conn->remote_params.max_idle_timeout = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_MAX_UDP_PAYLOAD_SIZE: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(value < 1200 || value > 65527) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid 'max_udp_payload_size' %"SCNu64"\n",
						imquic_get_connection_name(conn), value);
					res = -1;
					goto done;
				}
				if(conn != NULL)
					conn->remote_params.max_udp_payload_size = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_DATA: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL) {
					conn->remote_params.initial_max_data = value;
					conn->flow_control.remote_max_data = value;
				}
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL)
					conn->remote_params.initial_max_stream_data_bidi_local = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL)
					conn->remote_params.initial_max_stream_data_bidi_remote = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_STREAM_DATA_UNI: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL)
					conn->remote_params.initial_max_stream_data_uni = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_STREAMS_BIDI: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL) {
					conn->remote_params.initial_max_streams_bidi = value;
					conn->flow_control.remote_max_streams_bidi = conn->remote_params.initial_max_streams_bidi;
				}
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_INITIAL_MAX_STREAMS_UNI: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL) {
					conn->remote_params.initial_max_streams_uni = value;
					conn->flow_control.remote_max_streams_uni = conn->remote_params.initial_max_streams_uni;
				}
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_ACK_DELAY_EXPONENT: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(value > 20) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid 'ack_delay_exponent' %"SCNu64"\n",
						imquic_get_connection_name(conn), value);
					res = -1;
					goto done;
				}
				if(conn != NULL)
					conn->remote_params.ack_delay_exponent = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_MAX_ACK_DELAY: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(value > 16384) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid 'max_ack_delay' %"SCNu64"\n",
						imquic_get_connection_name(conn), value);
					res = -1;
					goto done;
				}
				if(conn != NULL)
					conn->remote_params.max_ack_delay = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_DISABLE_ACTIVE_MIGRATION: {
				/* No value */
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"]\n",
					param, imquic_transport_parameter_str(param), p_len);
				if(conn != NULL)
					conn->remote_params.disable_active_migration = TRUE;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_true());
#endif
				break;
			}
			case IMQUIC_ACTIVE_CONNECTION_ID_LIMIT: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(conn != NULL)
					conn->remote_params.active_connection_id_limit = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			case IMQUIC_MAX_DATAGRAM_FRAME_SIZE: {
				/* An integer */
				uint64_t value = imquic_read_varint(bytes + offset, blen - offset, &length);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] %"SCNu64"\n",
					param, imquic_transport_parameter_str(param), p_len, value);
				if(value > 65536) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid 'max_datagram_frame_size' %"SCNu64"\n",
						imquic_get_connection_name(conn), value);
					res = -1;
					goto done;
				}
				if(value == 65536)	/* Make browsers happy */
					value = 65535;
				if(conn != NULL)
					conn->remote_params.max_datagram_frame_size = value;
#ifdef HAVE_QLOG
				if(data != NULL)
					json_object_set_new(data, imquic_transport_parameter_str(param), json_integer(value));
#endif
				break;
			}
			default:
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- [%"SCNu64"][%s][%"SCNu64"] ??\n",
					param, imquic_transport_parameter_str(param), p_len);
				imquic_print_hex(IMQUIC_LOG_HUGE, bytes +offset, p_len);
				break;
		}
		offset += p_len;
	}
done:
#ifdef HAVE_QLOG
	if(conn != NULL && conn->qlog != NULL && conn->qlog->quic) {
		if(res < 0 && data != NULL)
			json_decref(data);
		else
			imquic_qlog_parameters_set(conn->qlog, data);
	}
#endif
	return res;
}

/* Sending packets */
int imquic_send_ack(imquic_connection *conn, enum ssl_encryption_level_t level, imquic_connection_id *src, imquic_connection_id *dest) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	imquic_packet *pkt = imquic_packet_create();
	if(level == ssl_encryption_initial) {
		imquic_packet_long_init(pkt, IMQUIC_INITIAL, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	} else if(level == ssl_encryption_handshake) {
		imquic_packet_long_init(pkt, IMQUIC_HANDSHAKE, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	} else {
		imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	}
	pkt->level = level;
	pkt->packet_number = conn->pkn[pkt->level];
	conn->pkn[pkt->level]++;
	/* Since ACKs are not retransmitted, we don't add any frame here: we
	 * let the serialize function do that for us (along other frames, maybe) */
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	/* Send the message */
	imquic_send_packet(conn, pkt);
	/* FIXME Take note we don't currently need to send any ACK */
	conn->send_ack[level] = FALSE;
	return 0;
}

int imquic_send_pending_crypto(imquic_connection *conn, imquic_connection_id *src, imquic_connection_id *dest) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed) || !conn->send_crypto)
		return -1;
	imquic_packet *pkt = NULL;
	imquic_frame *frame = NULL;
	imquic_buffer_chunk *chunk = NULL;
	enum ssl_encryption_level_t level;
	uint8_t buffer[1200];
	size_t max_len = sizeof(buffer) - 10, size = 0;
	for(level = ssl_encryption_initial; level<= ssl_encryption_application; level++) {
		if(level == ssl_encryption_early_data || imquic_buffer_peek(conn->crypto_out[level]) == NULL)
			continue;
		/* Prepare one or more QUIC packets */
		while((chunk = imquic_buffer_peek(conn->crypto_out[level])) != NULL) {
			if(pkt == NULL)
				pkt = imquic_packet_create();
			if(chunk->length + pkt->frames_size < max_len) {
				/* Add the whole CRYPTO chunk */
				size = imquic_payload_add_crypto(conn, pkt, buffer, max_len,
					chunk->data, chunk->offset, chunk->length);
				imquic_buffer_get(conn->crypto_out[level]);
				imquic_buffer_chunk_free(chunk);
				/* Create a frame and append it to the packet */
				frame = imquic_frame_create(IMQUIC_CRYPTO, buffer, size);
#ifdef HAVE_QLOG
				frame->qlog_frame = pkt->qlog_frame;
				pkt->qlog_frame = NULL;
#endif
				pkt->frames = g_list_prepend(pkt->frames, frame);
				pkt->frames_size += frame->size;
			} else {
				/* We can only add a portion of it */
				size_t part_len = max_len - pkt->frames_size;
				size = imquic_payload_add_crypto(conn, pkt, buffer, max_len,
					chunk->data, chunk->offset, part_len);
				/* Create a frame and append it to the packet */
				frame = imquic_frame_create(IMQUIC_CRYPTO, buffer, size);
#ifdef HAVE_QLOG
				frame->qlog_frame = pkt->qlog_frame;
				pkt->qlog_frame = NULL;
#endif
				pkt->frames = g_list_prepend(pkt->frames, frame);
				pkt->frames_size += frame->size;
				/* Shift the chunk, so that we can continue from there later */
				conn->crypto_out[level]->base_offset += part_len;
				chunk->offset += part_len;
				chunk->length -= part_len;
				memmove(chunk->data, chunk->data + part_len, chunk->length);
			}
			if(pkt->frames_size >= max_len || imquic_buffer_peek(conn->crypto_out[level]) == NULL) {
				/* This packet is ready */
				if(conn->is_server && level == ssl_encryption_application && imquic_buffer_peek(conn->crypto_out[level]) == NULL) {
					/* Add a HANDSHAKE_DONE */
					size = imquic_payload_add_handshake_done(conn, pkt, buffer, max_len);
					/* Create a frame and append it to the packet */
					frame = imquic_frame_create(IMQUIC_HANDSHAKE_DONE, buffer, size);
#ifdef HAVE_QLOG
					frame->qlog_frame = pkt->qlog_frame;
					pkt->qlog_frame = NULL;
#endif
					pkt->frames = g_list_prepend(pkt->frames, frame);
					pkt->frames_size += frame->size;
				}
				if(level == ssl_encryption_initial || level == ssl_encryption_handshake) {
					/* Craft a long header packet */
					imquic_packet_long_init(pkt, (level == ssl_encryption_initial ? IMQUIC_INITIAL : IMQUIC_HANDSHAKE),
						&conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
					if(level == ssl_encryption_initial && pkt->frames_size < max_len) {
						/* Add padding to increase the size of this packet */
						frame = imquic_frame_create(IMQUIC_PADDING, NULL, max_len - pkt->frames_size);
#ifdef HAVE_QLOG
						if(conn->qlog != NULL && conn->qlog->quic) {
							frame->qlog_frame = imquic_qlog_prepare_packet_frame("padding");
							json_object_set_new(frame->qlog_frame, "payload_length", json_integer(max_len - pkt->frames_size));
						}
#endif
						pkt->frames = g_list_prepend(pkt->frames, frame);
						pkt->frames_size += frame->size;
					}
				} else {
					/* Craft a short header packet */
					imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
				}
				pkt->level = level;
				/* Set packet number */
				pkt->packet_number = conn->pkn[pkt->level];
				conn->pkn[pkt->level]++;
				/* Reorder the list of frames and serialize them */
				pkt->frames = g_list_reverse(pkt->frames);
				pkt->retransmit_if_lost = TRUE;
				if(imquic_serialize_packet(conn, pkt) < 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
						imquic_get_connection_name(conn));
					imquic_packet_destroy(pkt);
				} else {
					/* Send the message */
					imquic_send_packet(conn, pkt);
				}
				/* Prepare a new packet next */
				pkt = NULL;
			}
		}
		if(level == ssl_encryption_application) {
			/* Notify the application that the connection is ready */
			if(!conn->connected) {
				conn->connected = TRUE;
				imquic_listmap_clear(conn->sent_pkts[ssl_encryption_initial]);
				conn->ack_eliciting_in_flight[ssl_encryption_initial] = 0;
				conn->last_ack_eliciting_time[ssl_encryption_initial] = 0;
				imquic_listmap_clear(conn->sent_pkts[ssl_encryption_handshake]);
				conn->ack_eliciting_in_flight[ssl_encryption_handshake] = 0;
				conn->last_ack_eliciting_time[ssl_encryption_handshake] = 0;
				if(conn->http3 != NULL) {
					/* FIXME If this is an HTTP/3 connection, wait for a SETTINGS */
				} else if(conn->socket->new_connection) {
					conn->socket->new_connection(conn, conn->socket->user_data);
				}
			}
		}
	}
	conn->send_crypto = FALSE;
	return 0;
}

int imquic_send_keepalive(imquic_connection *conn, imquic_connection_id *dest) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	imquic_packet *pkt = imquic_packet_create();
	enum ssl_encryption_level_t level = ssl_encryption_application;
	imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	pkt->level = level;
	pkt->packet_number = conn->pkn[pkt->level];
	conn->pkn[pkt->level]++;
	/* Add a PING frame */
	imquic_frame *frame = imquic_frame_create(IMQUIC_PING, NULL, 1);
	imquic_payload_add_ping(conn, pkt, frame->buffer, frame->size);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic)
		frame->qlog_frame = imquic_qlog_prepare_packet_frame("ping");
#endif
	pkt->frames = g_list_append(pkt->frames, frame);
	pkt->frames_size += frame->size;
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	/* Send the message */
	imquic_send_packet(conn, pkt);
	return 0;
}

int imquic_send_credits(imquic_connection *conn, imquic_connection_id *dest, imquic_frame_type type, uint64_t stream_id) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	if(type != IMQUIC_MAX_DATA && type != IMQUIC_MAX_STREAMS && type != IMQUIC_MAX_STREAMS_UNI && type != IMQUIC_MAX_STREAM_DATA) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Can't grant more credits, invalid frame provided (%s)\n",
			imquic_get_connection_name(conn), imquic_frame_type_str(type));
		return -1;
	}
	imquic_packet *pkt = imquic_packet_create();
	enum ssl_encryption_level_t level = ssl_encryption_application;
	imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	pkt->level = level;
	pkt->packet_number = conn->pkn[pkt->level];
	conn->pkn[pkt->level]++;
	/* Check what frame we should send */
	imquic_frame *frame = NULL;
	uint8_t buffer[40];
	size_t max_len = sizeof(buffer), size = 0;
	if(type == IMQUIC_MAX_DATA) {
		/* Add a MAX_DATA frame */
		size = imquic_payload_add_max_data(conn, pkt, buffer, max_len, conn->flow_control.local_max_data);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_MAX_DATA, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("max_data");
				json_object_set_new(frame->qlog_frame, "maximum", json_integer(conn->flow_control.local_max_data));
			}
#endif
		}
	} else if(type == IMQUIC_MAX_STREAMS) {
		/* Add a MAX_STREAMS frame */
		size = imquic_payload_add_max_streams(conn, pkt, buffer, max_len, TRUE, conn->flow_control.local_max_streams_bidi);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_MAX_STREAMS, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("max_streams");
				json_object_set_new(frame->qlog_frame, "stream_type", json_string("bidirectional"));
				json_object_set_new(frame->qlog_frame, "maximum", json_integer(conn->flow_control.local_max_streams_bidi));
			}
#endif
		}
	} else if(type == IMQUIC_MAX_STREAMS_UNI) {
		/* Add a MAX_STREAMS frame (unidirectional) */
		size = imquic_payload_add_max_streams(conn, pkt, buffer, max_len, FALSE, conn->flow_control.local_max_streams_uni);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_MAX_STREAMS, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("max_streams");
				json_object_set_new(frame->qlog_frame, "stream_type", json_string("unidirectional"));
				json_object_set_new(frame->qlog_frame, "maximum", json_integer(conn->flow_control.local_max_streams_uni));
			}
#endif
		}
	} else if(type == IMQUIC_MAX_STREAM_DATA) {
		/* Add a MAX_STREAM_DATA frame */
		imquic_mutex_lock(&conn->mutex);
		imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
		if(stream != NULL) {
			gboolean bidirectional = stream->bidirectional;
			uint64_t maximum = stream->local_max_data;
			imquic_mutex_unlock(&conn->mutex);
			size = imquic_payload_add_max_stream_data(conn, pkt, buffer, max_len, stream_id, maximum);
			if(size > 0) {
				frame = imquic_frame_create(IMQUIC_MAX_STREAMS, buffer, size);
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					frame->qlog_frame = imquic_qlog_prepare_packet_frame("max_stream_data");
					json_object_set_new(frame->qlog_frame, "stream_type", json_string(bidirectional ? "bidirectional" : "unidirectional"));
					json_object_set_new(frame->qlog_frame, "maximum", json_integer(maximum));
				}
#endif
			}
		} else {
			imquic_mutex_unlock(&conn->mutex);
		}
	}
	if(frame == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Can't grant more credits, no frame prepared\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	pkt->frames = g_list_append(pkt->frames, frame);
	pkt->frames_size += frame->size;
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	/* Send the message */
	imquic_send_packet(conn, pkt);
	return 0;
}

int imquic_send_blocked(imquic_connection *conn, imquic_connection_id *dest, imquic_frame_type type, uint64_t stream_id) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	if(type != IMQUIC_DATA_BLOCKED && type != IMQUIC_STREAMS_BLOCKED && type != IMQUIC_STREAMS_BLOCKED_UNI && type != IMQUIC_STREAM_DATA_BLOCKED) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Can't ask for more credits, invalid frame provided (%s)\n",
			imquic_get_connection_name(conn), imquic_frame_type_str(type));
		return -1;
	}
	imquic_packet *pkt = imquic_packet_create();
	enum ssl_encryption_level_t level = ssl_encryption_application;
	imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	pkt->level = level;
	pkt->packet_number = conn->pkn[pkt->level];
	conn->pkn[pkt->level]++;
	/* Check what frame we should send */
	imquic_frame *frame = NULL;
	uint8_t buffer[40];
	size_t max_len = sizeof(buffer), size = 0;
	if(type == IMQUIC_DATA_BLOCKED) {
		/* Add a DATA_BLOCKED frame */
		size = imquic_payload_add_data_blocked(conn, pkt, buffer, max_len, conn->flow_control.remote_max_data);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_DATA_BLOCKED, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("data_blocked");
				json_object_set_new(frame->qlog_frame, "limit", json_integer(conn->flow_control.remote_max_data));
			}
#endif
		}
	} else if(type == IMQUIC_STREAMS_BLOCKED) {
		/* Add a STREAMS_BLOCKED frame */
		size = imquic_payload_add_streams_blocked(conn, pkt, buffer, max_len, TRUE, conn->flow_control.remote_max_streams_bidi);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_STREAMS_BLOCKED, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("streams_blocked");
				json_object_set_new(frame->qlog_frame, "stream_type", json_string("bidirectional"));
				json_object_set_new(frame->qlog_frame, "limit", json_integer(conn->flow_control.remote_max_streams_bidi));
			}
#endif
		}
	} else if(type == IMQUIC_STREAMS_BLOCKED_UNI) {
		/* Add a STREAMS_BLOCKED frame (unidirectional) */
		size = imquic_payload_add_streams_blocked(conn, pkt, buffer, max_len, FALSE, conn->flow_control.remote_max_streams_uni);
		if(size > 0) {
			frame = imquic_frame_create(IMQUIC_STREAMS_BLOCKED_UNI, buffer, size);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic) {
				frame->qlog_frame = imquic_qlog_prepare_packet_frame("streams_blocked");
				json_object_set_new(frame->qlog_frame, "stream_type", json_string("unidirectional"));
				json_object_set_new(frame->qlog_frame, "limit", json_integer(conn->flow_control.remote_max_streams_uni));
			}
#endif
		}
	} else if(type == IMQUIC_STREAM_DATA_BLOCKED) {
		/* Add a STREAM_DATA_BLOCKED frame */
		imquic_stream *stream = g_hash_table_lookup(conn->streams, &stream_id);
		if(stream != NULL) {
			gboolean bidirectional = stream->bidirectional;
			uint64_t limit = stream->remote_max_data;
			size = imquic_payload_add_stream_data_blocked(conn, pkt, buffer, max_len, stream_id, limit);
			if(size > 0) {
				frame = imquic_frame_create(IMQUIC_STREAM_DATA_BLOCKED, buffer, size);
#ifdef HAVE_QLOG
				if(conn->qlog != NULL && conn->qlog->quic) {
					frame->qlog_frame = imquic_qlog_prepare_packet_frame("stream_data_blocked");
					json_object_set_new(frame->qlog_frame, "stream_type", json_string(bidirectional ? "bidirectional" : "unidirectional"));
					json_object_set_new(frame->qlog_frame, "limit", json_integer(limit));
				}
#endif
			}
		}
	}
	if(frame == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Can't ask for more credits, no frame prepared\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	pkt->frames = g_list_append(pkt->frames, frame);
	pkt->frames_size += frame->size;
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	/* Send the message */
	imquic_send_packet(conn, pkt);
	return 0;
}

int imquic_send_pending_stream(imquic_connection *conn, imquic_connection_id *dest) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	/* FIXME Check the queue */
	imquic_packet *pkt = NULL;
	imquic_frame *frame = NULL;
	uint64_t *stream_id = NULL;
	imquic_stream *stream = NULL;
	imquic_buffer_chunk *chunk = NULL;
	enum ssl_encryption_level_t level = ssl_encryption_application;
	uint8_t buffer[1200];
	size_t buf_len = sizeof(buffer) - 10, max_len = 0, size = 0;
	imquic_mutex_lock(&conn->mutex);
	while(g_queue_get_length(conn->outgoing_data) > 0) {
		stream_id = g_queue_pop_head(conn->outgoing_data);
		if(imquic_listmap_find(conn->blocked_streams, stream_id) != NULL)
			continue;
		stream = g_hash_table_lookup(conn->streams, stream_id);
		if(stream != NULL) {
			imquic_refcount_increase(&stream->ref);
			imquic_mutex_lock(&stream->mutex);
		}
		g_free(stream_id);
		if(stream == NULL || imquic_buffer_peek(stream->out_data) == NULL) {
			if(stream != NULL) {
				imquic_mutex_unlock(&stream->mutex);
				imquic_refcount_decrease(&stream->ref);
			}
			continue;
		}
		/* FIXME Check if we reached any flow control limits */
		if(stream->out_size == stream->remote_max_data || conn->flow_control.out_size == conn->flow_control.remote_max_data) {
			/* We did, mark the stream as blocked for now */
			if(imquic_listmap_find(conn->blocked_streams, &stream->stream_id) == NULL)
				imquic_listmap_append(conn->blocked_streams, &stream->stream_id, imquic_uint64_dup(stream->stream_id));
			imquic_mutex_unlock(&stream->mutex);
			imquic_refcount_decrease(&stream->ref);
			continue;
		}
		/* Prepare one or more QUIC packets */
		if(pkt == NULL)
			pkt = imquic_packet_create();
		while((chunk = imquic_buffer_peek(stream->out_data)) != NULL) {
			/* FIXME Check if we reached any flow control limits */
			if(stream->out_size == stream->remote_max_data || conn->flow_control.out_size == conn->flow_control.remote_max_data)
				break;
			if(pkt == NULL)
				pkt = imquic_packet_create();
			/* FIXME Check if sending new data could overfloe the flow control limits */
			max_len = buf_len;
			if(stream->out_size + chunk->length > stream->remote_max_data) {
				/* We can't send everything, we reached the stream flow control limits */
				size_t diff = stream->remote_max_data - stream->out_size;
				max_len = pkt->frames_size + diff;
			}
			/* FIXME Check if we're in the flow control limits */
			if(conn->flow_control.out_size + chunk->length > conn->flow_control.remote_max_data) {
				/* We can't send everything, we reached the connection flow control limits */
				size_t diff = conn->flow_control.remote_max_data - conn->flow_control.out_size;
				max_len = pkt->frames_size + diff;
			}
			if(chunk->length + pkt->frames_size < max_len) {
				/* Add the whole STREAM chunk */
				imquic_buffer_get(stream->out_data);
				if(stream->out_finalsize > 0 && imquic_buffer_peek(stream->out_data) == NULL)
					stream->out_state = IMQUIC_STREAM_COMPLETE;
				stream->out_size += chunk->length;
				conn->flow_control.out_size += chunk->length;
				size = imquic_payload_add_stream(conn, pkt, buffer, buf_len,
					stream->stream_id, chunk->data, chunk->offset, chunk->length,
					(stream->out_state == IMQUIC_STREAM_COMPLETE), FALSE);
				imquic_buffer_chunk_free(chunk);
				/* Create a frame and append it to the packet */
				frame = imquic_frame_create(IMQUIC_STREAM, buffer, size);
#ifdef HAVE_QLOG
				frame->qlog_frame = pkt->qlog_frame;
				pkt->qlog_frame = NULL;
#endif
				pkt->frames = g_list_prepend(pkt->frames, frame);
				pkt->frames_size += frame->size;
			} else if(max_len > pkt->frames_size) {
				/* We can only add a portion of it */
				size_t part_len = max_len - pkt->frames_size;
				stream->out_size += part_len;
				conn->flow_control.out_size += part_len;
				size = imquic_payload_add_stream(conn, pkt, buffer, buf_len,
					stream->stream_id, chunk->data, chunk->offset, part_len, FALSE, FALSE);
				/* Create a frame and append it to the packet */
				frame = imquic_frame_create(IMQUIC_STREAM, buffer, size);
#ifdef HAVE_QLOG
				frame->qlog_frame = pkt->qlog_frame;
				pkt->qlog_frame = NULL;
#endif
				pkt->frames = g_list_prepend(pkt->frames, frame);
				pkt->frames_size += frame->size;
				/* Shift the chunk, so that we can continue from there later */
				stream->out_data->base_offset += part_len;
				chunk->offset += part_len;
				chunk->length -= part_len;
				memmove(chunk->data, chunk->data + part_len, chunk->length);
			}
			/* FIXME Check if we reached any flow control limits, and notify the peer in case */
			if(stream->out_size == stream->remote_max_data || conn->flow_control.out_size == conn->flow_control.remote_max_data) {
				/* We did, send one or more blocked messages and mark the stream as blocked */
				if(stream->out_size == stream->remote_max_data) {
					/* Add a STREAM_DATA_BLOCKED frame */
					size = imquic_payload_add_stream_data_blocked(conn, pkt, buffer, buf_len,
						stream->stream_id, stream->remote_max_data);
					/* Create a frame and append it to the packet */
					frame = imquic_frame_create(IMQUIC_STREAM_DATA_BLOCKED, buffer, size);
#ifdef HAVE_QLOG
					frame->qlog_frame = pkt->qlog_frame;
					pkt->qlog_frame = NULL;
#endif
					pkt->frames = g_list_prepend(pkt->frames, frame);
					pkt->frames_size += frame->size;
				}
				if(conn->flow_control.out_size == conn->flow_control.remote_max_data) {
					/* Add a DATA_BLOCKED frame */
					size = imquic_payload_add_data_blocked(conn, pkt, buffer, buf_len,
						conn->flow_control.remote_max_data);
					/* Create a frame and append it to the packet */
					frame = imquic_frame_create(IMQUIC_DATA_BLOCKED, buffer, size);
#ifdef HAVE_QLOG
					frame->qlog_frame = pkt->qlog_frame;
					pkt->qlog_frame = NULL;
#endif
					pkt->frames = g_list_prepend(pkt->frames, frame);
					pkt->frames_size += frame->size;
				}
				if(imquic_listmap_find(conn->blocked_streams, &stream->stream_id) == NULL)
					imquic_listmap_append(conn->blocked_streams, &stream->stream_id, imquic_uint64_dup(stream->stream_id));
			}
			if(pkt->frames != NULL && (pkt->frames_size >= buf_len || (imquic_buffer_peek(stream->out_data) == NULL && g_queue_get_length(conn->outgoing_data) == 0))) {
				/* This packet is ready, craft a short header packet */
				imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
				pkt->level = level;
				/* Set packet number */
				pkt->packet_number = conn->pkn[pkt->level];
				conn->pkn[pkt->level]++;
				/* Reorder the list of frames and serialize them */
				pkt->frames = g_list_reverse(pkt->frames);
				pkt->retransmit_if_lost = TRUE;
				if(imquic_serialize_packet(conn, pkt) < 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
						imquic_get_connection_name(conn));
					imquic_packet_destroy(pkt);
				} else {
					/* Send the response */
					imquic_send_packet(conn, pkt);
				}
				/* Prepare a new packet next */
				pkt = NULL;
			}
		}
		if(imquic_stream_is_done(stream)) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Stream %"SCNu64" is done, removing it\n",
				imquic_get_connection_name(conn), stream->stream_id);
			/* FIXME */
			g_hash_table_remove(conn->streams, &stream->stream_id);
			g_hash_table_insert(conn->streams_done, imquic_dup_uint64(stream->stream_id), GINT_TO_POINTER(1));
#ifdef QLOG
			if(conn->qlog != NULL && conn->qlog->quic)
				imquic_qlog_stream_state_updated(conn->qlog, stream_id, NULL, NULL, "closed");
#endif
		}
		imquic_mutex_unlock(&stream->mutex);
		imquic_refcount_decrease(&stream->ref);
	}
	if(pkt != NULL && pkt->frames != NULL) {
		/* There's a packet we didn't send yet, do it now */
		imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
		pkt->level = level;
		/* Set packet number */
		pkt->packet_number = conn->pkn[pkt->level];
		conn->pkn[pkt->level]++;
		/* Reorder the list of frames and serialize them */
		pkt->frames = g_list_reverse(pkt->frames);
		pkt->retransmit_if_lost = TRUE;
		if(imquic_serialize_packet(conn, pkt) < 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
				imquic_get_connection_name(conn));
			imquic_packet_destroy(pkt);
		} else {
			/* Send the response */
			imquic_send_packet(conn, pkt);
		}
	} else {
		imquic_packet_destroy(pkt);
	}
	imquic_mutex_unlock(&conn->mutex);
	return 0;
}

int imquic_send_pending_datagram(imquic_connection *conn, imquic_connection_id *dest) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	/* FIXME Check the queue */
	imquic_packet *pkt = NULL;
	imquic_frame *frame = NULL;
	enum ssl_encryption_level_t level = ssl_encryption_application;
	uint8_t buffer[1450];
	size_t max_len = sizeof(buffer) - 5, size = 0;
	imquic_data *data = NULL;
	gboolean send = FALSE;
	imquic_mutex_lock(&conn->mutex);
	while(g_queue_get_length(conn->outgoing_datagram) > 0) {
		/* Prepare one or more QUIC packets */
		while((data = g_queue_peek_head(conn->outgoing_datagram)) != NULL) {
			if(pkt == NULL)
				pkt = imquic_packet_create();
			if(data->buffer == NULL || data->length == 0) {
				g_queue_pop_head(conn->outgoing_datagram);
				imquic_data_destroy(data);
				continue;
			}
			if(data->length + pkt->frames_size < max_len) {
				/* Add the DATAGRAM */
				size = imquic_payload_add_datagram(conn, pkt, buffer, max_len,
					data->buffer, data->length, FALSE);
				g_queue_pop_head(conn->outgoing_datagram);
				imquic_data_destroy(data);
				/* Create a frame and append it to the packet */
				frame = imquic_frame_create(IMQUIC_DATAGRAM, buffer, size);
#ifdef HAVE_QLOG
				frame->qlog_frame = pkt->qlog_frame;
				pkt->qlog_frame = NULL;
#endif
				pkt->frames = g_list_prepend(pkt->frames, frame);
				pkt->frames_size += frame->size;
			} else {
				if(pkt->frames_size == 0) {
					IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Buffer too large to send on a DATAGRAM (%zu), dropping it...\n",
						imquic_get_connection_name(conn), data->length);
					g_queue_pop_head(conn->outgoing_datagram);
					imquic_data_destroy(data);
				} else {
					/* Send what we have */
					send = TRUE;
				}
			}
			if(send || pkt->frames_size >= max_len || g_queue_peek_head(conn->outgoing_datagram) == NULL) {
				/* This packet is ready, craft a short header packet */
				imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
				pkt->level = level;
				/* Set packet number */
				pkt->packet_number = conn->pkn[pkt->level];
				conn->pkn[pkt->level]++;
				/* Reorder the list of frames and serialize them */
				pkt->frames = g_list_reverse(pkt->frames);
				if(imquic_serialize_packet(conn, pkt) < 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
						imquic_get_connection_name(conn));
					imquic_packet_destroy(pkt);
				} else {
					/* Send the message */
					imquic_send_packet(conn, pkt);
				}
				/* Prepare a new packet next */
				pkt = NULL;
			}
		}
	}
	imquic_packet_destroy(pkt);
	imquic_mutex_unlock(&conn->mutex);
	return 0;
}

int imquic_send_close_connection(imquic_connection *conn, imquic_error_code error_code, imquic_frame_type frame_type, const char *reason) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	if(conn->just_started)
		return 0;
	/* Craft an Initial packet with a CONNECTION_CLOSE */
	imquic_packet *pkt = imquic_packet_create();
	if(conn->level == ssl_encryption_initial) {
		imquic_packet_long_init(pkt, IMQUIC_INITIAL, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	} else if(conn->level == ssl_encryption_handshake) {
		imquic_packet_long_init(pkt, IMQUIC_HANDSHAKE, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	} else {
		imquic_packet_short_init(pkt, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	}
	pkt->level = conn->level;
	/* Set packet number */
	pkt->packet_number = conn->pkn[pkt->level];
	/* Payload */
	uint8_t buffer[1200];
	size_t max_len = sizeof(buffer);
	size_t size = imquic_payload_add_connection_close(conn, pkt, buffer, max_len,
		error_code, frame_type, reason);	/* FIXME */
	/* Create a frame and append it to the packet */
	imquic_frame *frame = imquic_frame_create(IMQUIC_CONNECTION_CLOSE, buffer, size);
#ifdef HAVE_QLOG
	frame->qlog_frame = pkt->qlog_frame;
	pkt->qlog_frame = NULL;
#endif
	pkt->frames = g_list_append(pkt->frames, frame);
	pkt->frames_size += frame->size;
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n",
			imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		/* Notify the application */
		imquic_network_endpoint_remove_connection(conn->socket, conn, TRUE);
		return -1;
	}
	/* Send the message */
	imquic_send_packet(conn, pkt);
	/* Notify the application */
	imquic_network_endpoint_remove_connection(conn->socket, conn, TRUE);
	return 0;
}

int imquic_serialize_packet(imquic_connection *conn, imquic_packet *pkt) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	if(pkt == NULL || !pkt->is_valid)
		return -1;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Serializing packet %"SCNu64" (%s)\n",
		imquic_get_connection_name(conn), pkt->packet_number, imquic_encryption_level_str(pkt->level));
	memset(pkt->data.buffer, 0, sizeof(pkt->data.buffer));
	pkt->data.length = 0;
	/* FIXME badly */
	uint8_t pkn_len = 0;
	uint32_t pkn = pkt->packet_number;
	if((pkn & 0x000000FF) == pkt->packet_number)
		pkn_len = 1;
	else if((pkn & 0x0000FFFF) == pkt->packet_number)
		pkn_len = 2;
	else if((pkn & 0x00FFFFFF) == pkt->packet_number)
		pkn_len = 3;
	else if((pkn & 0xFFFFFFFF) == pkt->packet_number)
		pkn_len = 4;
	else
		IMQUIC_LOG(IMQUIC_LOG_WARN, "We need to rewrite the packet number\n");
	uint8_t pkn_bytes[4];
	pkn = htonl(pkn);
	memcpy(pkn_bytes, &pkn, sizeof(pkn_bytes));

	/* Serialize the list of frames to the payload */
	imquic_frame *frame = NULL;
	size_t offset = 0, max_len = 1200, size = 0;
	size_t p_len = sizeof(pkt->payload.buffer);
	GList *temp = pkt->frames;
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic) {
		if(pkt->qlog_frames != NULL)
			json_decref(pkt->qlog_frames);
		pkt->qlog_frames = json_array();
	}
#endif
	while(temp) {
		frame = (imquic_frame *)temp->data;
		if(frame->size > 0) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Added %s\n", imquic_frame_type_str(frame->type));
			memcpy(&pkt->payload.buffer[offset], frame->buffer, frame->size);
			offset += frame->size;
			if(!pkt->ack_eliciting && frame->type != IMQUIC_ACK &&
					frame->type != IMQUIC_PADDING &&
					frame->type != IMQUIC_CONNECTION_CLOSE)
				pkt->ack_eliciting = TRUE;
		}
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic && pkt->qlog_frames != NULL && frame->qlog_frame != NULL)
			json_array_append(pkt->qlog_frames, frame->qlog_frame);
#endif
		temp = temp->next;
	}
	/* Check if we need to (and can) add an ACK too */
	if(conn->send_ack[pkt->level]) {
		IMQUIC_LOG(IMQUIC_LOG_VERB, "  -- Added %s\n", imquic_frame_type_str(IMQUIC_ACK));
		uint64_t delay = (g_get_monotonic_time() - conn->largest_time[pkt->level]) >> conn->local_params.ack_delay_exponent;
		size = imquic_payload_add_ack(conn, pkt, &pkt->payload.buffer[offset], p_len - offset, conn->recvd[pkt->level], delay, NULL);
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic && pkt->qlog_frames != NULL && pkt->qlog_frame != NULL) {
			json_array_append_new(pkt->qlog_frames, pkt->qlog_frame);
			pkt->qlog_frame = NULL;
		}
#endif
		if(pkt->level == ssl_encryption_initial || offset + size <= max_len) {
			conn->send_ack[pkt->level] = FALSE;
			offset += size;
		}
	}
	/* To conclude, let's see if we need some padding */
	if(offset > 0) {
		if(offset < 12) {
			offset += imquic_payload_add_padding(conn, pkt, &pkt->payload.buffer[offset], p_len - offset, 12 - offset);
#ifdef HAVE_QLOG
			if(conn->qlog != NULL && conn->qlog->quic && pkt->qlog_frames != NULL && pkt->qlog_frame != NULL) {
				json_array_append_new(pkt->qlog_frames, pkt->qlog_frame);
				pkt->qlog_frame = NULL;
			}
#endif
		}
	}
	pkt->payload.length = offset;

	/* Serialize the header */
	offset = 0;
	if(pkt->longheader) {
		/* Long header */
		pkt->data.buffer[offset] = (1 << 7) | (1 << 6) | (pkt->type << 4) | (pkn_len-1);
		offset++;
		uint32_t version = 1;
		version = g_htonl(version);
		memcpy(&pkt->data.buffer[offset], &version, sizeof(version));
		offset += sizeof(version);
		pkt->data.buffer[offset] = pkt->destination.len;
		offset++;
		if(pkt->destination.len > 0) {
			memcpy(&pkt->data.buffer[offset], pkt->destination.id, pkt->destination.len);
			offset += pkt->destination.len;
		}
		pkt->data.buffer[offset] = pkt->source.len;
		offset++;
		if(pkt->source.len > 0) {
			memcpy(&pkt->data.buffer[offset], pkt->source.id, pkt->source.len);
			offset += pkt->source.len;
		}
		if(pkt->type == IMQUIC_INITIAL) {
			/* Check if we need to add a token */
			if(conn->retry_token.length == 0) {
				pkt->data.buffer[offset] = 0;
				offset++;
			} else {
				offset += imquic_write_varint(conn->retry_token.length, &pkt->data.buffer[offset], 4);
				memcpy(&pkt->data.buffer[offset], conn->retry_token.buffer, conn->retry_token.length);
				offset += conn->retry_token.length;
			}
		}
		/* Set the Length */
		pkt->length_offset = offset;
		uint64_t p_len = pkn_len + pkt->payload.length + 16;
		offset += imquic_write_varint(p_len, &pkt->data.buffer[pkt->length_offset], 4);
		/* Packet number */
		pkt->pkn_offset = offset;
		memcpy(&pkt->data.buffer[offset], pkn_bytes + (4-pkn_len), pkn_len);
		offset += pkn_len;
		/* This is where the payload starts */
		pkt->payload_offset = offset;
		pkt->data.length = offset;
	} else {
		/* Short header */
		pkt->data.buffer[offset] = (1 << 6) | (pkn_len-1);
		if(conn->current_phase)
			pkt->data.buffer[offset] += (1 << 2);
		offset++;
		if(pkt->destination.len > 0) {
			memcpy(&pkt->data.buffer[offset], pkt->destination.id, pkt->destination.len);
			offset += pkt->destination.len;
		}
		/* Packet number */
		pkt->pkn_offset = offset;
		memcpy(&pkt->data.buffer[offset], pkn_bytes + (4-pkn_len), pkn_len);
		offset += pkn_len;
		/* This is where the payload starts */
		pkt->payload_offset = offset;
		pkt->data.length = offset;
	}

	/* Encrypt the payload and put it after the header */
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Payload (decrypted, %"SCNu64")\n", pkt->payload.length);
	imquic_print_hex(IMQUIC_LOG_HUGE, pkt->payload.buffer, pkt->payload.length);
	/* Check which keys we should use */
	uint8_t *key = conn->keys[pkt->level].local.key[conn->current_phase];
	size_t key_len = conn->keys[pkt->level].local.key_len;
	uint8_t *iv = conn->keys[pkt->level].local.iv[conn->current_phase];
	size_t iv_len = conn->keys[pkt->level].local.iv_len;
	uint8_t *hp = conn->keys[pkt->level].local.hp;
	size_t hp_len = conn->keys[pkt->level].local.hp_len;
	int e_len = imquic_encrypt_payload(pkt->payload.buffer, pkt->payload.length,
		&pkt->data.buffer[pkt->payload_offset], sizeof(pkt->data.buffer) - pkt->payload_offset,
		pkt->data.buffer, pkt->payload_offset,
		pkt->packet_number, key, key_len, iv, iv_len);
	if(e_len < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error encrypting packet\n");
		return -1;
	}
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "  -- Payload (encrypted, %d)\n", e_len);
	imquic_print_hex(IMQUIC_LOG_HUGE, &pkt->data.buffer[pkt->payload_offset], e_len);
	pkt->data.length += e_len;

	/* Finally, let's protect the header */
	if(imquic_protect_header(pkt->data.buffer, pkt->data.length, pkt->pkn_offset, hp, hp_len) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Error protecting packet\n");
		return -1;
	}

	/* Done */
	return 0;
}

int imquic_send_packet(imquic_connection *conn, imquic_packet *pkt) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed))
		return -1;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Sending packet %"SCNu64" (%zu bytes, %s)\n",
		imquic_get_connection_name(conn), pkt->packet_number, pkt->data.length, imquic_encryption_level_str(pkt->level));
	//~ int res = 0;
	//~ if(pkt->packet_number != 6 && pkt->packet_number != 7 && pkt->packet_number != 9)
		//~ res = imquic_network_send(conn, pkt->data.buffer, pkt->data.length);
	int res = imquic_network_send(conn, pkt->data.buffer, pkt->data.length);
#ifdef HAVE_QLOG
	if(res > 0 && conn->qlog != NULL && conn->qlog->quic) {
		conn->dgram_id_out++;
		json_t *ph = imquic_qlog_prepare_packet_header(imquic_encryption_level_str(pkt->level),
			(pkt->longheader ? &pkt->source : NULL), &pkt->destination);
		json_object_set_new(ph, "packet_number", json_integer(pkt->packet_number));
		imquic_qlog_packet_sent(conn->qlog, ph, pkt->qlog_frames, conn->dgram_id_out, pkt->data.length);
		pkt->qlog_frames = NULL;
		imquic_qlog_udp_datagrams_sent(conn->qlog, conn->dgram_id_out, pkt->data.length);
	}
#endif
	/* Track when we sent this packet */
	if(pkt->retransmit_if_lost && !pkt->ack_eliciting)
		pkt->retransmit_if_lost = FALSE;
	int64_t now = g_get_monotonic_time();
	imquic_sent_packet *sent_pkt = g_malloc(sizeof(imquic_sent_packet));
	sent_pkt->conn = conn;
	sent_pkt->packet = pkt->retransmit_if_lost ? pkt : NULL;
	sent_pkt->level = pkt->level;
	sent_pkt->packet_number = pkt->packet_number;
	sent_pkt->packet_size = pkt->data.length;
	sent_pkt->ack_eliciting = pkt->ack_eliciting;
	sent_pkt->sent_time = now;
	imquic_listmap_append(conn->sent_pkts[pkt->level], &pkt->packet_number, sent_pkt);
	/* Keep track of when we sent the last ACK eliciting packet */
	if(pkt->ack_eliciting) {
		conn->ack_eliciting_in_flight[pkt->level]++;
		conn->last_ack_eliciting_time[pkt->level] = now;
	}
	if(pkt->retransmit_if_lost) {
		/* Update the loss detection timer */
		imquic_connection_update_loss_timer(conn);
	} else {
		/* We don't need this packet anymore */
		imquic_packet_destroy(pkt);
	}
	return res;
}

int imquic_retransmit_packet(imquic_connection *conn, imquic_sent_packet *sent_pkt) {
	if(conn == NULL || g_atomic_int_get(&conn->destroyed) || sent_pkt == NULL)
		return -1;
	imquic_packet *pkt = sent_pkt->packet;
	sent_pkt->packet = NULL;
	if(sent_pkt->ack_eliciting && conn->ack_eliciting_in_flight[sent_pkt->level] > 0)
		conn->ack_eliciting_in_flight[sent_pkt->level]--;
	imquic_listmap_remove(conn->sent_pkts[sent_pkt->level], &sent_pkt->packet_number);
	/* FIXME Should we really stop retransmitting after a level bump? */
	if(pkt == NULL || pkt->level < conn->level || !pkt->retransmit_if_lost) {
		imquic_packet_destroy(pkt);
		return -1;
	}
	uint64_t old_pkn = pkt->packet_number;
	pkt->packet_number = conn->pkn[pkt->level];
	conn->pkn[pkt->level]++;
	IMQUIC_LOG(IMQUIC_LOG_VERB, "[%s] Retransmitting packet number %"SCNu64" as %"SCNu64" (%zu bytes, %s)\n",
		imquic_get_connection_name(conn), old_pkn, pkt->packet_number, pkt->data.length, imquic_encryption_level_str(pkt->level));
	if(imquic_serialize_packet(conn, pkt) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing packet\n", imquic_get_connection_name(conn));
		imquic_packet_destroy(pkt);
		return -1;
	}
	/* Retransmit the message */
	return imquic_send_packet(conn, pkt);
}

/* Processing messages */
void imquic_process_message(imquic_network_endpoint *socket, imquic_network_address *sender, uint8_t *bytes, size_t blen) {
	/* Parse the packet(s) */
	size_t offset = 0, tot = blen;
	int ret = 0;
	imquic_packet pkt;
	imquic_connection *conn = NULL;
	while(blen > 0) {
		/* Parse the buffer as a QUIC packet */
		memset(&pkt, 0, sizeof(pkt));
		ret = imquic_parse_packet(socket, sender, &conn, &pkt, &bytes[offset], blen, tot);
		if(ret < 0 || !pkt.is_valid) {
			IMQUIC_LOG(IMQUIC_LOG_VERB, "Couldn't parse packet of size %zu, ignoring\n", blen);
			if(conn != NULL)
				imquic_refcount_decrease(&conn->ref);
			break;
		};
		/* Check if there's CRYPTO to pass to the stack */
		imquic_check_incoming_crypto(conn);
		/* Check if we have to ACK this */
		if(pkt.ack_eliciting)
			conn->send_ack[pkt.level] = TRUE;
		/* Check what else we need to do with this connection now */
		imquic_handle_event(conn);
		/* Check if the connection was closed by this request */
		if(conn->should_close)
			imquic_network_endpoint_remove_connection(conn->socket, conn, TRUE);
		/* Move on */
		offset += ret;
		blen -= ret;
		imquic_refcount_decrease(&conn->ref);
	}
}

void imquic_check_incoming_crypto(imquic_connection *conn) {
	enum ssl_encryption_level_t level;
	imquic_buffer_chunk *chunk = NULL;
	for(level = ssl_encryption_initial; level <= ssl_encryption_application; level++) {
		if(level == ssl_encryption_early_data)
			continue;
		while((chunk = imquic_buffer_get(conn->crypto_in[level])) != NULL) {
			if(level < conn->level) {
				imquic_buffer_chunk_free(chunk);
				continue;
			}
			/* Create a SSL stack if we still don't have one */
			gboolean new_stack = FALSE;
			if(conn->ssl == NULL) {
				if(level != ssl_encryption_initial) {
					imquic_buffer_chunk_free(chunk);
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Missing SSL stack at level %s\n",
						imquic_get_connection_name(conn), imquic_encryption_level_str(level));
					continue;
				}
				conn->ssl = imquic_tls_new_ssl(conn->socket->tls);
				if(conn->ssl == NULL) {
					imquic_buffer_chunk_free(chunk);
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error creating SSL: %s\n",
						imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
					continue;
				}
				SSL_set_app_data(conn->ssl, conn);
				new_stack = TRUE;
			}
			/* Pass the CRYPTO data as QUIC data to establish the TLS handshake */
			if(SSL_provide_quic_data(conn->ssl, level, chunk->data, chunk->length) == 0) {
				imquic_buffer_chunk_free(chunk);
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] SSL_provide_quic_data error: %s\n",
					imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
				continue;
			}
			imquic_buffer_chunk_free(chunk);
			if(level == ssl_encryption_initial && new_stack) {
				/* Set our transport parameters (FIXME these params should be configurable) */
				uint8_t local_params[200];
				size_t p_len = sizeof(local_params);
				memset(local_params, 0, p_len);
				size_t offset = 0;
				offset += imquic_transport_parameter_add_connection_id(&local_params[offset], p_len-offset, IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID, &conn->initial_cid);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_IDLE_TIMEOUT, conn->local_params.max_idle_timeout);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_UDP_PAYLOAD_SIZE, conn->local_params.max_udp_payload_size);
				offset += imquic_transport_parameter_add_data(&local_params[offset], p_len-offset, IMQUIC_STATELESS_RESET_TOKEN, conn->local_cid.token, sizeof(conn->local_cid.token));
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_DATA, conn->local_params.initial_max_data);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, conn->local_params.initial_max_stream_data_bidi_remote);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, conn->local_params.initial_max_stream_data_bidi_local);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_UNI, conn->local_params.initial_max_stream_data_uni);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAMS_BIDI, conn->local_params.initial_max_streams_bidi);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAMS_UNI, conn->local_params.initial_max_streams_uni);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_ACK_DELAY_EXPONENT, conn->local_params.ack_delay_exponent);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_ACK_DELAY, conn->local_params.max_ack_delay);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_ACTIVE_CONNECTION_ID_LIMIT, conn->local_params.active_connection_id_limit);
				offset += imquic_transport_parameter_add_connection_id(&local_params[offset], p_len-offset, IMQUIC_INITIAL_SOURCE_CONNECTION_ID, &conn->local_cid);
				offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_DATAGRAM_FRAME_SIZE, conn->local_params.max_datagram_frame_size);
				imquic_parse_transport_parameters(NULL, local_params, offset);
				IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Setting QUIC parameters (%zu)\n",
					imquic_get_connection_name(conn), offset);
				if(SSL_set_quic_transport_params(conn->ssl, local_params, offset) == 0) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error setting QUIC parameters: %s\n",
						imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
					continue;
				}
#ifdef HAVE_QLOG
				/* Trace events, if needed */
				if(conn->qlog != NULL && conn->qlog->quic) {
					/* TODO Set resumption properly */
					json_t *data = imquic_qlog_prepare_parameters_set(conn->qlog, TRUE, FALSE, conn->socket->tls->early_data);
					char cid[41];
					const char *cid_str = imquic_connection_id_str(&conn->initial_cid, cid, sizeof(cid));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_ORIGINAL_DESTINATION_CONNECTION_ID), json_string(cid_str));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_IDLE_TIMEOUT), json_integer(conn->local_params.max_idle_timeout));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_UDP_PAYLOAD_SIZE), json_integer(conn->local_params.max_udp_payload_size));
					cid_str = imquic_hex_str(conn->local_cid.token, sizeof(conn->local_cid.token), cid, sizeof(cid));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_STATELESS_RESET_TOKEN), json_string(cid_str));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_DATA), json_integer(conn->local_params.initial_max_data));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE), json_integer(conn->local_params.initial_max_stream_data_bidi_remote));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL), json_integer(conn->local_params.initial_max_stream_data_bidi_local));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_UNI), json_integer(conn->local_params.initial_max_stream_data_uni));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAMS_BIDI), json_integer(conn->local_params.initial_max_streams_bidi));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAMS_UNI), json_integer(conn->local_params.initial_max_streams_uni));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_ACK_DELAY_EXPONENT), json_integer(conn->local_params.ack_delay_exponent));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_ACK_DELAY), json_integer(conn->local_params.max_ack_delay));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_ACTIVE_CONNECTION_ID_LIMIT), json_integer(conn->local_params.active_connection_id_limit));
					cid_str = imquic_connection_id_str(&conn->local_cid, cid, sizeof(cid));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_SOURCE_CONNECTION_ID), json_string(cid_str));
					json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_DATAGRAM_FRAME_SIZE), json_integer(conn->local_params.max_datagram_frame_size));
					imquic_qlog_parameters_set(conn->qlog, data);
				}
#endif
			}
			if(level == ssl_encryption_application && !conn->is_server && !conn->connected) {
				imquic_connection_change_level(conn, level);
				conn->connected = TRUE;
				imquic_listmap_clear(conn->sent_pkts[ssl_encryption_initial]);
				conn->ack_eliciting_in_flight[ssl_encryption_initial] = 0;
				conn->last_ack_eliciting_time[ssl_encryption_initial] = 0;
				imquic_listmap_clear(conn->sent_pkts[ssl_encryption_handshake]);
				conn->ack_eliciting_in_flight[ssl_encryption_handshake] = 0;
				conn->last_ack_eliciting_time[ssl_encryption_handshake] = 0;
				/* Handle the new connection */
				if(conn->http3 != NULL) {
					/* FIXME If this is an HTTP/3 connection, send a SETTINGS */
					imquic_http3_prepare_settings(conn->http3);
				} else if(conn->socket->new_connection) {
					conn->socket->new_connection(conn, conn->socket->user_data);
				}
			}
			/* Perform the handshake */
			if(conn->is_server || level < ssl_encryption_application) {
				int res = SSL_do_handshake(conn->ssl);
				if(res != 1) {
					int sslerr = SSL_get_error(conn->ssl, res);
					if(sslerr != SSL_ERROR_WANT_READ) {
						IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][%s] SSL_do_handshake error: %d (%s)\n",
							imquic_get_connection_name(conn), imquic_encryption_level_str(level),
							sslerr, ERR_reason_error_string(ERR_get_error()));
					}
					continue;
				}
			} else if(!conn->is_server && level == ssl_encryption_application) {
				if(SSL_process_quic_post_handshake(conn->ssl) != 1) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s][%s] SSL_process_quic_post_handshake error: %s\n",
						imquic_get_connection_name(conn), imquic_encryption_level_str(level),
						ERR_reason_error_string(ERR_get_error()));
					continue;
				}
			}
			if(!conn->have_params) {
				/* Parse the peer transport params (take note of these and enforce them) */
				const uint8_t *params;
				size_t params_len = 0;
				SSL_get_peer_quic_transport_params(conn->ssl, &params, &params_len);
				if(params_len > 0) {
					conn->have_params = TRUE;
					imquic_parse_transport_parameters(conn, (uint8_t *)params, params_len);
				}
			}
		}
	}
	if(!conn->is_server && !conn->alpn_negotiated) {
		/* Check what ALPN was negotiated */
		char alpn[256];
		size_t alpn_len = sizeof(alpn);
		const unsigned char *data = NULL;
		unsigned int data_len = 0;
		SSL_get0_alpn_selected(conn->ssl, &data, &data_len);
		if(data == NULL || data_len == 0) {
			/* Try again later */
			return;
		}
		conn->alpn_negotiated = TRUE;
		g_snprintf(alpn, alpn_len, "%.*s", data_len, (char *)data);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Negotiated ALPN: %s\n",
			imquic_get_connection_name(conn), alpn);
#ifdef HAVE_QLOG
		if(conn->qlog != NULL && conn->qlog->quic)
			imquic_qlog_alpn_information(conn->qlog, NULL, 0, NULL, 0, alpn);
#endif
		if(conn->socket->webtransport && !strcasecmp(alpn, "h3"))
			conn->http3 = imquic_http3_connection_create(conn, conn->socket->subprotocol);
	}
}

gboolean imquic_handle_event(imquic_connection *conn) {
	if(conn == NULL)
		return G_SOURCE_REMOVE;
	/* FIXME We don't really process the event, we just check if there's things to do */
	/* FIXME Any CRYPTO to send? */
	if(conn->send_crypto)
		imquic_send_pending_crypto(conn, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	/* FIXME Any STREAM to send? */
	if(g_queue_get_length(conn->outgoing_data) > 0)
		imquic_send_pending_stream(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	/* FIXME Any DATAGRAM to send? */
	if(g_queue_get_length(conn->outgoing_datagram) > 0)
		imquic_send_pending_datagram(conn, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	/* FIXME Any ACK to send? */
	if(conn->send_ack[ssl_encryption_initial])
		imquic_send_ack(conn, ssl_encryption_initial, &conn->local_cid, (conn->remote_cid.len ? &conn->remote_cid : &conn->initial_cid));
	if(conn->send_ack[ssl_encryption_handshake])
		imquic_send_ack(conn, ssl_encryption_handshake, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	if(conn->send_ack[ssl_encryption_application])
		imquic_send_ack(conn, ssl_encryption_application, &conn->local_cid, (conn->new_remote_cid.len ? &conn->new_remote_cid : &conn->remote_cid));
	/* FIXME Done */
	conn->wakeup = FALSE;
	return G_SOURCE_CONTINUE;
}

/* Start a new client */
int imquic_start_quic_client(imquic_network_endpoint *socket) {
	if(socket == NULL || socket->is_server)
		return -1;
	/* Create a new connection */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating new connection\n");
	imquic_connection *conn = imquic_connection_create(socket);
	/* Generate a Destination and Source ID */
	uint64_t dest_id = imquic_random_uint64();
	conn->initial_cid.len = sizeof(dest_id);
	memcpy(conn->initial_cid.id, &dest_id, conn->initial_cid.len);
	conn->remote_cid.len = sizeof(dest_id);
	memcpy(conn->remote_cid.id, &dest_id, conn->remote_cid.len);
#ifdef HAVE_QLOG
	if(conn->qlog != NULL && conn->qlog->quic)
		imquic_qlog_set_odcid(conn->qlog, &conn->remote_cid);
#endif
	uint64_t local_cid = imquic_random_uint64();
	conn->local_cid.len = sizeof(local_cid);
	memcpy(conn->local_cid.id, &local_cid, conn->local_cid.len);
	uint64_t st1 = imquic_random_uint64(), st2 = imquic_random_uint64();
	memcpy(conn->local_cid.token, &st1, sizeof(st1));
	memcpy(&conn->local_cid.token[sizeof(st1)], &st2, sizeof(st2));
	imquic_quic_connection_add(conn, &conn->local_cid);
	/* Derive the initial secrets */
	if(imquic_derive_initial_secret(&conn->keys[ssl_encryption_initial],
			conn->remote_cid.id, conn->remote_cid.len, FALSE) < 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error deriving initial secret\n", imquic_get_connection_name(conn));
		return -1;
	}
	/* Create the TLS stack (which will trigger a new outgoing packet) */
	conn->ssl = imquic_tls_new_ssl(conn->socket->tls);
	if(conn->ssl == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error creating SSL: %s\n",
			imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	SSL_set_app_data(conn->ssl, conn);
	SSL_set_alpn_protos(conn->ssl, (const unsigned char *)conn->alpn.buffer, conn->alpn.length);
	SSL_set_tlsext_host_name(conn->ssl, socket->sni);
	memcpy(&conn->peer, &socket->remote_address, sizeof(socket->remote_address));
	uint8_t local_params[100];
	size_t p_len = sizeof(local_params);
	memset(local_params, 0, p_len);
	size_t offset = 0;
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_IDLE_TIMEOUT, conn->local_params.max_idle_timeout);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_UDP_PAYLOAD_SIZE, conn->local_params.max_udp_payload_size);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_DATA, conn->local_params.initial_max_data);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, conn->local_params.initial_max_stream_data_bidi_remote);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, conn->local_params.initial_max_stream_data_bidi_local);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAM_DATA_UNI, conn->local_params.initial_max_stream_data_uni);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAMS_BIDI, conn->local_params.initial_max_streams_bidi);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_INITIAL_MAX_STREAMS_UNI, conn->local_params.initial_max_streams_uni);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_ACK_DELAY_EXPONENT, conn->local_params.ack_delay_exponent);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_ACK_DELAY, conn->local_params.max_ack_delay);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_ACTIVE_CONNECTION_ID_LIMIT, conn->local_params.active_connection_id_limit);
	offset += imquic_transport_parameter_add_connection_id(&local_params[offset], p_len-offset, IMQUIC_INITIAL_SOURCE_CONNECTION_ID, &conn->local_cid);
	offset += imquic_transport_parameter_add_int(&local_params[offset], p_len-offset, IMQUIC_MAX_DATAGRAM_FRAME_SIZE, conn->local_params.max_datagram_frame_size);
	imquic_parse_transport_parameters(NULL, local_params, offset);
	IMQUIC_LOG(IMQUIC_LOG_HUGE, "[%s] Setting QUIC parameters (%zu)\n",
		imquic_get_connection_name(conn), offset);
	SSL_set_quic_use_legacy_codepoint(conn->ssl, 0);
	if(SSL_set_quic_transport_params(conn->ssl, local_params, offset) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error setting QUIC parameters: %s\n",
			imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
#ifdef HAVE_QLOG
	/* Trace events, if needed */
	if(conn->qlog != NULL && conn->qlog->quic) {
		char src_ip[NI_MAXHOST] = { 0 }, dst_ip[NI_MAXHOST] = { 0 };
		imquic_qlog_connection_started(conn->qlog,
			imquic_network_address_str(&conn->socket->local_address, src_ip, sizeof(src_ip), FALSE), conn->socket->port,
			imquic_network_address_str(&conn->socket->remote_address, dst_ip, sizeof(dst_ip), FALSE), conn->socket->remote_port);
		imquic_qlog_version_information(conn->qlog, 1, 1);
		imquic_qlog_alpn_information(conn->qlog, NULL, 0, conn->alpn.buffer, conn->alpn.length, 0);
		json_t *data = imquic_qlog_prepare_parameters_set(conn->qlog, TRUE, FALSE, conn->socket->tls->early_data);
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_IDLE_TIMEOUT), json_integer(conn->local_params.max_idle_timeout));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_UDP_PAYLOAD_SIZE), json_integer(conn->local_params.max_udp_payload_size));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_DATA), json_integer(conn->local_params.initial_max_data));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE), json_integer(conn->local_params.initial_max_stream_data_bidi_remote));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL), json_integer(conn->local_params.initial_max_stream_data_bidi_local));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAM_DATA_UNI), json_integer(conn->local_params.initial_max_stream_data_uni));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAMS_BIDI), json_integer(conn->local_params.initial_max_streams_bidi));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_MAX_STREAMS_UNI), json_integer(conn->local_params.initial_max_streams_uni));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_ACK_DELAY_EXPONENT), json_integer(conn->local_params.ack_delay_exponent));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_ACK_DELAY), json_integer(conn->local_params.max_ack_delay));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_ACTIVE_CONNECTION_ID_LIMIT), json_integer(conn->local_params.active_connection_id_limit));
		char cid[41];
		const char *cid_str = imquic_connection_id_str(&conn->local_cid, cid, sizeof(cid));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_INITIAL_SOURCE_CONNECTION_ID), json_string(cid_str));
		json_object_set_new(data, imquic_transport_parameter_str(IMQUIC_MAX_DATAGRAM_FRAME_SIZE), json_integer(conn->local_params.max_datagram_frame_size));
		imquic_qlog_parameters_set(conn->qlog, data);
		imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, FALSE),
			conn->keys[ssl_encryption_initial].local.key[0], conn->keys[ssl_encryption_initial].local.key_len, 0);
		imquic_qlog_key_updated(conn->qlog, imquic_encryption_key_type_str(ssl_encryption_initial, TRUE),
			conn->keys[ssl_encryption_initial].remote.key[0], conn->keys[ssl_encryption_initial].remote.key_len, 0);
	}
#endif
	/* Perform the handshake */
	int res = SSL_do_handshake(conn->ssl);
	if(res != 1 && SSL_get_error(conn->ssl, res) != SSL_ERROR_WANT_READ) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] SSL_do_handshake error: %s\n",
			imquic_get_connection_name(conn), ERR_reason_error_string(ERR_get_error()));
		return -1;
	}
	/* Done */
	conn->just_started = FALSE;
	g_atomic_int_set(&conn->wakeup, 1);
	imquic_loop_wakeup();
	return 0;
}
