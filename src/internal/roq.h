/*! \file   roq.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  RTP Over QUIC (RoQ) stack (headers)
 * \details Implementation of the RTP Over QUIC (RoQ) stack as part
 * of the library itself. At the time of writing, this implements (most
 * of) version -10 of the protocol.
 *
 * \note This is the internal implementation of RoQ in the library. You're
 * still free to only use imquic as the underlying QUIC/WebTransport library,
 * and take care of the RoQ implementation on your own instead: in order
 * to do that, use the generic imquic client/server creation utilities,
 * rather than the RoQ specific ones.
 *
 * \ingroup RoQ Core
 */

#ifndef IMQUIC_ROQ_INTERNAL_H
#define IMQUIC_ROQ_INTERNAL_H

#include <glib.h>

#include "../imquic/roq.h"
#include "qlog.h"
#include "refcount.h"

#define IMQUIC_ROQ		7499633

/*! \brief Initialize the native RoQ stack at startup */
void imquic_roq_init(void);
/*! \brief Uninitialize the native RoQ stack */
void imquic_roq_deinit(void);

/*! \brief RoQ endpoint instance */
typedef struct imquic_roq_endpoint {
	/*! \brief Associated QUIC connection */
	imquic_connection *conn;
	/*! \brief Stream flows, indexed by stream ID */
	GHashTable *stream_flows_in, *stream_flows_out;
	/*! \brief Current packet buffer, indexed by stream ID */
	GHashTable *packets;
	/*! \brief Mutex */
	imquic_mutex mutex;
} imquic_roq_endpoint;

/*! \brief RoQ stream (when using the same stream for multiple packets) */
typedef struct imquic_roq_stream {
	/*! \brief QUIC Stream ID */
	uint64_t stream_id;
	/*! \brief RoQ Flow ID */
	uint64_t flow_id;
	/*! \brief Whether this is a new stream */
	gboolean new_stream;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_roq_stream;

/*! \brief RoQ public callbacks */
typedef struct imquic_roq_callbacks {
	/*! \brief Callback function to be notified about new RoQ connections */
	void (* new_connection)(imquic_connection *conn, void *user_data);
	/*! \brief Callback function to be notified about incoming RTP packets */
	void (* rtp_incoming)(imquic_connection *conn, imquic_roq_multiplexing multiplexing,
		uint64_t flow_id, uint8_t *bytes, size_t blen);
	/*! \brief Callback function to be notified about RoQ connections being closed */
	void (* connection_gone)(imquic_connection *conn);
} imquic_roq_callbacks;

/** @name Internal callbacks for RoQ endpoints
 */
///@{
/*! \brief Callback the core invokes when a new QUIC connection using RoQ is available
 * @param conn The imquic_connection instance that is now available
 * @param user_data Optional user data the user/application may have
 * associated to the endpoint this connection belongs to */
void imquic_roq_new_connection(imquic_connection *conn, void *user_data);
/*! \brief Callback the core invokes when there's new incoming data on a \c STREAM
 * @param conn The imquic_connection instance for which new \c STREAM data is available
 * @param stream_id The QUIC Stream ID for which new data is available
 * @param bytes The new data that is available
 * @param length Size of the new data
 * @param complete Whether this data marks the end of this \c STREAM */
void imquic_roq_stream_incoming(imquic_connection *conn, uint64_t stream_id,
	uint8_t *bytes, uint64_t length, gboolean complete);
/*! \brief Callback the core invokes when there's new incoming data on a \c DATAGRAM
 * @param conn The imquic_connection instance for which new \c DATAGRAM data is available
 * @param bytes The new data that is available
 * @param length Size of the new data */
void imquic_roq_datagram_incoming(imquic_connection *conn, uint8_t *bytes, uint64_t length);
/*! \brief Callback the core invokes when an existing RoQ connection is not available anymore
 * @param conn The imquic_connection instance that is now gone */
void imquic_roq_connection_gone(imquic_connection *conn);
///@}

#ifdef HAVE_QLOG
/** @name QLOG events tracing for RoQ
 */
///@{
/*! \brief Helper to add fields for RtpPacket to an event
 * @param data The data object to add the properties to
 * @param flow_id The RoQ flow ID to add
 * @param length The length of the RTP packet */
void imquic_roq_qlog_add_rtp_packet(json_t *data, uint64_t flow_id, uint64_t length);
/*! \brief Add a \c stream_opened event
 * @param qlog The imquic_qlog instance to add the event to
 * @param stream_id The Stream ID that was opened
 * @param flow_id The RoQ flow ID used in the stream */
void imquic_roq_qlog_stream_opened(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id);
/*! \brief Add a \c stream_packet_created event
 * @param qlog The imquic_qlog instance to add the event to
 * @param stream_id The Stream ID used for the packet
 * @param flow_id The RoQ flow ID used in the stream
 * @param bytes The content of the RTP packet
 * @param length The length of the RTP packet */
void imquic_roq_qlog_stream_packet_created(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id, uint8_t *bytes, size_t length);
/*! \brief Add a \c stream_packet_parsed event
 * @param qlog The imquic_qlog instance to add the event to
 * @param stream_id The Stream ID used for the packet
 * @param flow_id The RoQ flow ID used in the stream
 * @param bytes The content of the RTP packet
 * @param length The length of the RTP packet */
void imquic_roq_qlog_stream_packet_parsed(imquic_qlog *qlog, uint64_t stream_id, uint64_t flow_id, uint8_t *bytes, size_t length);
/*! \brief Add a \c datagram_packet_created event
 * @param qlog The imquic_qlog instance to add the event to
 * @param flow_id The RoQ flow ID used in the datagram
 * @param bytes The content of the RTP packet
 * @param length The length of the RTP packet */
void imquic_roq_qlog_datagram_packet_created(imquic_qlog *qlog, uint64_t flow_id, uint8_t *bytes, size_t length);
/*! \brief Add a \c datagram_packet_parsed event
 * @param qlog The imquic_qlog instance to add the event to
 * @param flow_id The RoQ flow ID used in the datagram
 * @param bytes The content of the RTP packet
 * @param length The length of the RTP packet */
void imquic_roq_qlog_datagram_packet_parsed(imquic_qlog *qlog, uint64_t flow_id, uint8_t *bytes, size_t length);
///@}
#endif

#endif
