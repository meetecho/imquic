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
#include <picoquic_utils.h>

#include "stream.h"
#include "buffer.h"
#include "network.h"
#include "http3.h"
#include "error.h"
#include "qlog.h"
#include "utils.h"
#include "refcount.h"

/*! \brief Helper method to stringify a connection ID
 * @param[in] cid The connection ID to stringify
 * @param[out] buffer The buffer where the string will be written
 * @param[in] blen Size of the string output buffer
 * @returns A pointer to buffer, if successful, or NULL otherwise */
const char *imquic_connection_id_str(picoquic_connection_id_t *cid, char *buffer, size_t blen);

/*! \brief QUIC Connection */
struct imquic_connection {
	/*! \brief Name of this connection (for logging purposes) */
	char *name;
	/*! \brief Picoquic connection instance */
	picoquic_cnx_t *piconn;
	/*! \brief Whether this is a server or a client connection (inherited from the endpoint) */
	gboolean is_server;
	/*! \brief Whether this connection has just started (e.g., to decide whether we need to derive initial secrets) */
	gboolean just_started;
	/*! \brief Whether we already received the peer QUIC transport parameters */
	gboolean have_params;
	/*! \brief Initial Connection ID as a string
	 * \note This is only meant for debugging purposes, e.g., QLOG correlation */
	char initial_cid_str[41];
	/*! \brief Negotiated ALPN */
	char *chosen_alpn;
	/*! \brief Negotiated WebTransport protocol */
	char *chosen_wt_protocol;
	/*! \brief Next unidirectional and bidirectional stream we can create (as actual ID, not QUIC one) */
	uint64_t stream_next_uni, stream_next_bidi;
	/*! \brief Map of streams we're handling */
	GHashTable *streams;
	/*! \brief Queue of events in the loop and outgoing packets to send */
	GAsyncQueue *queued_events;
	/*! \brief Whether an ALPN has been negotiated */
	gboolean alpn_negotiated;
	/*! \brief Whether this connection has been established */
	gboolean connected, established;
	/*! \brief Networking instance for this connection */
	imquic_network_endpoint *socket;
	/*! \brief Network address of the peer */
	imquic_network_address peer;
	/*! \brief WebTransport context, if any */
	imquic_http3_connection *http3;
	/*! \brief Loop source */
	imquic_source *loop_source;
	/*! \brief Incoming and outgoing datagram IDs */
	uint32_t dgram_id_in, dgram_id_out;
#ifdef HAVE_QLOG
	/*! \brief QLOG instance, if any */
	imquic_qlog *qlog;
#endif
	/*! \brief User data associated to the connection (opaque to the library) */
	void *user_data;
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether this connection should be closed */
	gboolean should_close;
	/*! \brief Whether this connection is being closed or has been closed */
	volatile gint closing, closed;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
};
/*! \brief Helper method to create a new imquic_connection instance owned by
 * a specific imquic_network_endpoint in the QUIC stack
 * @param socket The network endpoint this connection will be associated to
 * @param piconn The picoquic connection this connection will be associated to (only for servers)
 * @returns A pointer to a new imquic_connection instance, if successful, or NULL otherwise */
imquic_connection *imquic_connection_create(imquic_network_endpoint *socket, picoquic_cnx_t *piconn);
/*! \brief Helper method to destroy an existing imquic_connection instance
 * @param conn The imquic_connection instance to destroy */
void imquic_connection_destroy(imquic_connection *conn);

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
 * @param[in] length Size of the buffer of data
 * @param[in] complete Whether this (offset+length) is the end of the STREAM data
 * @returns 0 if successful, a negative integer otherwise */
int imquic_connection_send_on_stream(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t length, gboolean complete);
/*! \brief Helper to notify incoming \c DATAGRAM data to the application
 * @param conn The imquic_connection instance to notify the event for
 * @param data Buffer containing the new data
 * @param length Size of the new data buffer */
void imquic_connection_notify_datagram_incoming(imquic_connection *conn, uint8_t *data, uint64_t length);
/*! \brief Helper to notify incoming \c STREAM data to the application
 * @param conn The imquic_connection instance to notify the event for
 * @param stream The imquic_stream that originated the new data to notify about
 * @param data Buffer containing the new data
 * @param length Size of the new data buffer */
void imquic_connection_notify_stream_incoming(imquic_connection *conn, imquic_stream *stream, uint8_t *data, uint64_t length);
/*! \brief Helper to reset a stream, sending a \c RESET_STREAM
 * @param conn The imquic_connection instance that owns the stream to reset
 * @param stream_id ID of the stream to reset
 * @param error_code The error code to add to the frame */
void imquic_connection_reset_stream(imquic_connection *conn, uint64_t stream_id, uint64_t error_code);
/*! \brief Helpers to close connections
 * @param conn The imquic_connection instance to close
 * @param error_code The error code to send back in the \c CONNECTION_CLOSE frame
 * @param reason A verbose description of the error, if any */
void imquic_connection_close(imquic_connection *conn, uint64_t error_code, const char *reason);
///@}

/** @name Connection events
 */
///@{
/*! \brief QUIC event */
typedef enum imquic_connection_event_type {
	IMQUIC_CONNECTION_EVENT_UNKNOWN = 0,
	IMQUIC_CONNECTION_EVENT_STREAM,
	IMQUIC_CONNECTION_EVENT_DATAGRAM,
	IMQUIC_CONNECTION_EVENT_RESET_STREAM,
	IMQUIC_CONNECTION_EVENT_CLOSE_CONN,
} imquic_connection_event_type;

/*! \brief QUIC event */
typedef struct imquic_connection_event {
	/* Type of event we're queueing */
	imquic_connection_event_type type;
	/* Stream ID, where applicable */
	uint64_t stream_id;
	/* Data buffer, where applicable */
	imquic_buffer *data;
	/* FIN, where applicable */
	gboolean fin;
	/* Error code, where applicable */
	uint64_t error_code;
	/* Reason string, where applicable */
	char *reason;
} imquic_connection_event;
/*! \brief Helper method to create a imquic_connection_event instance
 * @param type The imquic_connection_event_type of the event
 * @returns A pointer to a new imquic_connection_event instance, if successful, or NULL otherwise */
imquic_connection_event *imquic_connection_event_create(imquic_connection_event_type type);
/*! \brief Helper method to destroy a imquic_connection_event instance
 * @param event The imquic_connection_event instance to destroy */
void imquic_connection_event_destroy(imquic_connection_event *event);
///@}

#endif
