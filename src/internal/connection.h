/*! \file   connection.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC connection abstraction (headers)
 * \details Abstraction of QUIC connections, during or after establishment.
 * This is where helper functions are exposed to the QUIC stack internals
 * for the purpose of creating STREAM ids, send data, and notify upper
 * layers about incoming data or shutdowns.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_CONNECTION_H
#define IMQUIC_CONNECTION_H

#include <stdint.h>

#include <glib.h>

#include "stream.h"
#include "buffer.h"
#include "crypto.h"
#include "network.h"
#include "http3.h"
#include "error.h"
#include "qlog.h"
#include "utils.h"
#include "listmap.h"
#include "refcount.h"

/*! \brief QUIC Connection ID */
typedef struct imquic_connection_id {
	/*! \brief Sequence number (FIXME currently unused) */
	uint64_t seq;
	/*! \brief Buffer containing the Connection ID */
	uint8_t id[20];
	/*! \brief Size of the Connection ID */
	size_t len;
	/*! \brief Stateless reset token (FIXME currently unused) */
	uint8_t token[16];
} imquic_connection_id;
/*! \brief Helper method to stringify a imquic_connection_id instance
 * @param[in] cid The imquic_connection_id instance to stringify
 * @param[out] buffer The buffer where the string will be written
 * @param[in] blen Size of the string output buffer
 * @returns A pointer to buffer, if successful, or NULL otherwise */
const char *imquic_connection_id_str(imquic_connection_id *cid, char *buffer, size_t blen);
/*! \brief Helper method to duplicate (copy) a imquic_connection_id instance
 * @param cid The imquic_connection_id instance to duplicate
 * @returns A pointer to a new imquic_connection_id instance with the same
 * data as the original, if successful, or NULL otherwise */
imquic_connection_id *imquic_connection_id_dup(imquic_connection_id *cid);
/*! \brief Helper method to check if two imquic_connection_id instances
 * are actually the same Connection ID
 * @note Helpful for using a imquic_connection_id instance as a key in hashtables.
 * @param a The Opaque pointer to the first imquic_connection_id instance to compare
 * @param b The Opaque pointer to the first imquic_connection_id instance to compare
 * @returns TRUE if the two IDs contain the same data, FALSE otherwise */
gboolean imquic_connection_id_equal(const void *a, const void *b);
/*! \brief Helper method to return a hash associated to a imquic_connection_id instance
 * @note Helpful for using a imquic_connection_id instance as a key in hashtables.
 * @param v The Opaque pointer to the imquic_connection_id instance to hash
 * @returns The hash computed from the ID */
guint imquic_connection_id_hash(gconstpointer v);

/*! \brief QUIC Transport parameters */
typedef struct imquic_connection_parameters {
	uint32_t max_idle_timeout;
	uint16_t max_udp_payload_size;
	uint16_t max_datagram_frame_size;
	uint64_t initial_max_data;
	uint64_t initial_max_stream_data_bidi_local;
	uint64_t initial_max_stream_data_bidi_remote;
	uint64_t initial_max_stream_data_uni;
	uint64_t initial_max_streams_bidi;
	uint64_t initial_max_streams_uni;
	uint8_t ack_delay_exponent;
	uint16_t max_ack_delay;
	gboolean disable_active_migration;
	uint16_t active_connection_id_limit;
} imquic_connection_parameters;
/*! \brief Helper method to reset/initialize a imquic_connection_parameters instance
 * @note This will set all properties to a default value, as per RFC 9000.
 * @param params The imquic_connection_parameters instance to initialize */
void imquic_connection_parameters_init(imquic_connection_parameters *params);

/*! \brief Round Trip Time (RTT) tracking */
typedef struct imquic_connection_rtt {
	/*! \brief Latest RTT, in milliseconds */
	uint16_t latest;
	/*! \brief Smoothed RTT */
	uint16_t smoothed;
	/*! \brief RTT variation */
	uint16_t rttvar;
	/*! \brief Minimum RTT */
	uint16_t min;
	/*! \brief Monotonic time of when we we obtained the first RTT sample */
	int64_t first_sample;
} imquic_connection_rtt;

/*! \brief Flow control tracking */
typedef struct imquic_connection_flow_control {
	/*! \brief Current values of local and remote max_data */
	uint64_t local_max_data, remote_max_data;
	/*! \brief Current values of local and remote bidirectional max_streams */
	uint64_t local_max_streams_bidi, remote_max_streams_bidi;
	/*! \brief Current values of local and remote unidirectional max_streams */
	uint64_t local_max_streams_uni, remote_max_streams_uni;
	/*! \brief Size of incoming and outgoing stream data so far */
	uint64_t in_size, out_size;
} imquic_connection_flow_control;

/*! \brief QUIC Connection */
struct imquic_connection {
	/*! \brief Name of this connection (for logging purposes) */
	char *name;
	/*! \brief Whether this is a server or a client connection (inherited from the endpoint) */
	gboolean is_server;
	/*! \brief Whether this connection has just started (e.g., to decide whether we need to derive initial secrets) */
	gboolean just_started;
	/*! \brief Whether we already received the peer QUIC transport parameters */
	gboolean have_params;
	/*! \brief Initial Connection ID */
	imquic_connection_id initial_cid;
	/*! \brief Local and remote Connection ID */
	imquic_connection_id local_cid, remote_cid;
	/*! \brief New remote Connection ID
	 * \todo We'll need to keep a map of Connection IDs, when receiving \c NEW_CONNECTION_ID */
	imquic_connection_id new_remote_cid;
	/*! \brief List of Connection IDs our peer has used */
	GList *connection_ids;
	/*! \brief Current encryption level */
	enum ssl_encryption_level_t level;
	/*! \brief Retry token, if any */
	imquic_data_fixed retry_token;
	/*! \brief Current outgoing packet number for each encryption level */
	uint64_t pkn[4];
	/*! \brief Transport parameters (local and remote) */
	imquic_connection_parameters local_params, remote_params;
	/*! \brief ALPN */
	imquic_data alpn;
	/*! \brief Next unidirectional and bidirectional stream we can create (as actual ID, not QUIC one) */
	uint64_t stream_next_uni, stream_next_bidi;
	/*! \brief Map of streams we're handling, and map of streams that are now done
	 * \todo We need a better, and less memory hungry, way of tracking streams, especially
	 * in cases where new streams are created and closed frequently */
	GHashTable *streams, *streams_done;
	/*! \brief Queued streams to process */
	GQueue *incoming_data;
	/*! \brief Queued data to send
	 * \todo The queueing of data needs to be improved considerably,
	 * along with a generic refactoring of the event loop (e.g., for
	 * congestion control, and/or the need to perform pacing/probing) */
	GQueue *outgoing_data, *outgoing_datagram;
	/*! \brief Listmap of blocked streams, in case we're waiting for credits
	 * \todo The queueing of data needs to be improved considerably,
	 * along with a generic refactoring of the event loop (e.g., for
	 * congestion control, and/or the need to perform pacing/probing) */
	imquic_listmap *blocked_streams;
	/*! \brief Trigger to wake the loop for this connection as part
	 * of the imquic_connection_source management */
	volatile gint wakeup;
	/*! \brief Different RTTs for this connection */
	imquic_connection_rtt rtt;
	/*! \brief Flow control state */
	imquic_connection_flow_control flow_control;
	/*! \brief List of received packet numbers, for each encryption level
	 * \todo We'll need a better and less memory hungry way of keeping
	 * track of packet numbers, as this list is currently never pruned */
	GList *recvd[4];
	/*! \brief Largest received packet numbers, for each encryption level */
	uint64_t largest[4];
	/*! \brief Number of ACK eliciting packets in flight, for each encryption level */
	size_t ack_eliciting_in_flight[4];
	/*! \brief Monotonic time of when we sent the last ACK eliciting packet, for each encryption level */
	int64_t last_ack_eliciting_time[4];
	/*! \brief Monotonic time of when we received the largest packet numbers,
	 * per each encryption level (for ACK delay purposes) */
	int64_t largest_time[4];
	/*! \brief Monotonic time of when the next packet can be considered,
	 * lost, per each encryption level */
	int64_t loss_time[4];
	/*! \brief Sent packets, per each encryption level */
	imquic_listmap *sent_pkts[4];
	/*! \brief Largest acked packet numbers, for each encryption level */
	uint64_t largest_acked[4];
	/*! \brief Whether we have ACKs to send for a specific encryption level */
	gboolean send_ack[5];
	/*! \brief Keys (protection, encryption) for each encryption level */
	imquic_protection keys[4];
	/*! \brief Current value of the key phase bit */
	gboolean current_phase;
	/*! \brief Encryption instance */
	SSL *ssl;
	/*! \brief Buffers for incoming and outgoing \c CRYPTO exchanges,
	 * at each encryption level */
	imquic_buffer *crypto_in[4], *crypto_out[4];
	/*! \brief Whether we have \c CRYPTO frames to send */
	gboolean send_crypto;
	/*! \brief Whether an ALPN has been negotiated */
	gboolean alpn_negotiated;
	/*! \brief Whether this connection has been established */
	gboolean connected;
	/*! \brief Networking instance for this connection */
	imquic_network_endpoint *socket;
	/*! \brief Network address of the peer */
	imquic_network_address peer;
	/*! \brief WebTransport context, if any */
	imquic_http3_connection *http3;
	/*! \brief Loss detection timer */
	imquic_source *ld_timer;
	/*! \brief Monotonic time of when we last got activity */
	int64_t last_activity;
	/*! \brief Idle timer */
	imquic_source *idle_timer;
	/*! \brief PTO count */
	uint8_t pto_count;
	/*! \brief Loop source */
	imquic_source *loop_source;
	/*! \brief Incoming and outgoing datagram IDs */
	uint32_t dgram_id_in, dgram_id_out;
#ifdef HAVE_QLOG
	/*! \brief QLOG instance, if any */
	imquic_qlog *qlog;
#endif
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether this connection should be closed */
	gboolean should_close;
	/*! \brief Whether this connection has been closed */
	volatile gint closed;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
};
/*! \brief Helper method to create a new imquic_connection instance owned by
 * a specific imquic_network_endpoint in the QUIC stack
 * @param socket The network endpoint this connection will be associated to
 * @returns A pointer to a new imquic_connection instance, if successful, or NULL otherwise */
imquic_connection *imquic_connection_create(imquic_network_endpoint *socket);
/*! \brief Helper method to destroy an existing imquic_connection instance
 * @param conn The imquic_connection instance to destroy */
void imquic_connection_destroy(imquic_connection *conn);

/** @name Loss detection and retransmissions
 */
///@{
/*! \brief Helper to change the current encryption level of a connection
 * @note This may result in resetting the loss detection state for the previous level
 * @param conn The imquic_connection instance to update
 * @param level The new SSL encryption level */
void imquic_connection_change_level(imquic_connection *conn, enum ssl_encryption_level_t level);
/*! \brief Helper method to update the RTT of a connection, when parsing ACKs
 * @param conn The imquic_connection instance to update
 * @param sent_time Monotonic time of when the largest acked packet was sent
 * @param ack_delay ACK delay value in the ACK frame */
void imquic_connection_update_rtt(imquic_connection *conn, int64_t sent_time, uint16_t ack_delay);
/*! \brief Helper method to detect lost packets
 * @param conn The imquic_connection instance to refer to
 * @returns A linked list of imquic_sent_packet packets, or NULL if there are none */
GList *imquic_connection_detect_lost(imquic_connection *conn);
/*! \brief Helper method to update the loss detection timer
 * @param conn The imquic_connection instance to update */
void imquic_connection_update_loss_timer(imquic_connection *conn);
/*! \brief Callback invoked when the loss detection timer fires
 * \note This is never invoked manually: only by the \c ld_timer timer
 * @param user_data Opaque pointer to the connection the timer refers to
 * @returns Always FALSE, since the next timer is always recreated from scratch */
gboolean imquic_connection_loss_detection_timeout(gpointer user_data);
///@}

/** @name Interacting with connections
 */
///@{
/*! \brief Helper to generate a new stream ID for this connection
 * @param[in] conn The imquic_connection instance to get a new stream ID from
 * @param[in] bidirectional Whether the new stream will be bidirectional
 * @param[out] stream_id Pointer to where the new stream ID will be placed
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_connection_new_stream_id(imquic_connection *conn, gboolean bidirectional, uint64_t *stream_id);
/*! \brief Helper method to send data on a QUIC DATAGRAM
 * @note Datagrams support must have been negotiated on the connection.
 * Notice that this method will queue the data for delivery, but not send
 * it right away. The event loop will take care of that internally.
 * @param[in] conn The imquic_connection to send data on
 * @param[in] bytes Buffer containing the data to send
 * @param[in] length Size of the buffer of data
 * @returns 0 if successful, a negative integer otherwise */
int imquic_connection_send_on_datagram(imquic_connection *conn, uint8_t *bytes, uint64_t length);
/*! \brief Helper method to send data on a QUIC STREAM
 * @note The stream ID must already be known by the stack, either because
 * created by the peer, or previously created via imquic_connection_new_stream_id.
 * Notice that this method will queue the data for delivery, but not send
 * it right away. The event loop will take care of that internally.
 * @param[in] conn The imquic_connection to send data on
 * @param[in] stream_id The QUIC stream to use for sending data
 * @param[in] bytes Buffer containing the data to send
 * @param[in] offset Offset value to put in the outgoing STREAM fragment
 * @param[in] length Size of the buffer of data
 * @param[in] complete Whether this (offset+length) is the end of the STREAM data
 * @returns 0 if successful, a negative integer otherwise */
int imquic_connection_send_on_stream(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete);
/*! \brief Helper to notify incoming \c DATAGRAM data to the application
 * @param conn The imquic_connection instance to notify the event for
 * @param data Buffer containing the new data
 * @param length Size of the new data buffer */
void imquic_connection_notify_datagram_incoming(imquic_connection *conn, uint8_t *data, uint64_t length);
/*! \brief Helper to notify incoming \c STREAM data to the application
 * @param conn The imquic_connection instance to notify the event for
 * @param stream The imquic_stream that originated the new data to notify about
 * @param data Buffer containing the new data
 * @param offset Offset in the overall \c STREAM this data is positioned at
 * @param length Size of the new data buffer */
void imquic_connection_notify_stream_incoming(imquic_connection *conn, imquic_stream *stream, uint8_t *data, uint64_t offset, uint64_t length);
/*! \brief Helper to flush a stream, in order to send data right away
 * @param conn The imquic_connection instance that owns the stream to flush
 * @param stream_id ID of the stream to flush */
void imquic_connection_flush_stream(imquic_connection *conn, uint64_t stream_id);
/*! \brief Helpers to close connections
 * @param conn The imquic_connection instance to close
 * @param error_code The error code to send back in the \c CONNECTION_CLOSE frame
 * @param frame_type The frame type that caused this connection to be closed
 * @param reason A verbose description of the error, if any */
void imquic_connection_close(imquic_connection *conn, uint64_t error_code, uint64_t frame_type, const char *reason);
///@}

#endif
