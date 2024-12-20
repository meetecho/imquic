/*! \file   roq.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic RoQ public interface (headers)
 * \details Public interface to the RTP Over QUIC (RoQ) native support
 * in the imquic library. This is where public functions are callbacks to
 * interact with the RoQ features of the library are defined.
 *
 * \ingroup API RoQ Core
 *
 * \page roqapi Native support for RTP Over QUIC (RoQ)
 *
 * As explained in the \ref publicapi, \ref imquic_create_server and \ref imquic_create_client
 * are the methods you can use to create a new, generic, QUIC server or
 * client, with the related callbacks to be notified about what happens
 * on new or existing connections. That API assumes you'll be entirely
 * responsible of the application level protocol details, though.
 *
 * Out of the box, imquic provides native support for a few specific
 * protocols, meaning it can deal with the lower level details of the
 * application level protocol, while exposing a simpler and higher level
 * API to use the protocol features programmatically. RTP Over QUIC is
 * one of those protocols.
 *
 * When you want to use the native RoQ features of imquic, you must not
 * use the generic functions and callbacks, but will need to use the RoQ
 * variants defined in this page instead. Specifically, to create a RoQ
 * server you won't use \ref imquic_create_server, but will use \ref imquic_create_roq_server
 * instead; likewise, a \ref imquic_create_roq_client variant exists for creating
 * RoQ clients too.
 *
 * The same applies to callbacks for incoming events. Attempting to use
 * the generic callback setters on a RoQ endpoint will do nothing, and
 * show an error on the logs: you'll need to use the RoQ specific callbacks.
 * This means that to be notified about a new RoQ connection (whether
 * you're a client or a server), you'll use \ref imquic_set_new_roq_connection_cb,
 * while to be notified about connections being closed you'll need to
 * use \ref imquic_set_roq_connection_gone_cb instead. The same considerations
 * made on reference-counting connections in generic callbacks applies
 * here too, since the same structs are used for endpoints and connections:
 * it's just the internals that are different. Starting the endpoint after
 * configuring the callbacks, instead, works exactly the same way as in
 * the generic API, meaning you'll be able to use \ref imquic_start_endpoint.
 *
 * Being notified about incoming RTP packets is much easier as well, as
 * rather than having to worry about handling incoming \c STREAM or
 * \c DATAGRAM data, and potentially demultiplex/reconstruct RTP packets
 * across multiple \c STREAM chunks, using \ref imquic_set_rtp_incoming_cb
 * you can be notified about full RTP packets instead, independently of
 * how they were multiplexed by the sender. The callback will also notify
 * you about the flow ID associated with the packet, making it much easier
 * to just handle the application level specifics (e.g., mapping incoming
 * packets to a specific session).
 *
 * Sending RTP packets follows the same simplification, since all you need
 * to do is use \ref imquic_roq_send_rtp and specify which multiplexing mode
 * you want to use for encapsulating the RTP packet on top of QUIC. Depending
 * on whether \c DATAGRAM or \c STREAM are used, the RoQ stack will handle
 * that internally for you: when using \c STREAM , it's up to you to tell
 * the stack when to close the stream, thus allowing you to choose how
 * many packets to send over the same stream (e.g., all packets on the
 * same stream, one stream per packet, or anything in between).
 */

#ifndef IMQUIC_ROQ_H
#define IMQUIC_ROQ_H

#include "imquic.h"

/** @name RoQ endpoints management
 */
///@{
/*! \brief Method to create a new RoQ server, using variable arguments to dictate
 * what the server should do (e.g., port to bind to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_server *server = imquic_create_roq_server("roq-server",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_LOCAL_PORT, 9000,
		IMQUIC_CONFIG_DONE, NULL);
 \endverbatim
 * to create a QUIC server that will automatically negotiate RoQ. Again,
 * as with imquic_create_server, this will only create the resource, but
 * not actually start the server: before doing that, you'll need to
 * configure the callbacks for the events you're interested in (in this
 * case, RoQ specific), and then use imquic_start_endpoint to start the
 * QUIC server (which will wait for incoming connections).
 * @note This will create a full, internal, RoQ stack on top of imquic,
 * meaning that the RoQ protocol will be handled natively by imquic for
 * you, providing a high level interface to the features of the protocol
 * itself. If you want to only use imquic as a QUIC/WebTrasport protocol,
 * and implement RoQ yourself, then you'll need to use imquic_create_server
 * or imquic_create_client instead.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_server object, if successful, NULL otherwise */
imquic_server *imquic_create_roq_server(const char *name, ...);
/*! \brief Method to create a new RoQ client, using variable arguments to dictate
 * what the client should do (e.g., address to connect to, ALPN, etc.). Variable
 * arguments are in the form of a sequence of name-value started with
 * a \c IMQUIC_CONFIG_INIT and ended by a \c IMQUIC_CONFIG_DONE , e.g.:
 \verbatim
	imquic_client *client = imquic_create_roq_client("roq-client",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, cert_pem,
		IMQUIC_CONFIG_TLS_KEY, cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, cert_pwd,
		IMQUIC_CONFIG_REMOTE_HOST, "127.0.0.1",
		IMQUIC_CONFIG_REMOTE_PORT, 9000,
		IMQUIC_CONFIG_DONE, NULL);
 \endverbatim
 * to create a QUIC client that will automatically negotiate RoQ. Again,
 * as with imquic_create_client, this will only create the resource, but
 * not actually start the connection: before doing that, you'll need to
 * configure the callbacks for the events you're interested in (in this
 * case, RoQ specific), and then use imquic_start_endpoint to start the
 * start the QUIC client (which will attempt a connection).
 * @note This will create a full, internal, RoQ stack on top of imquic,
 * meaning that the RoQ protocol will be handled natively by imquic for
 * you, providing a high level interface to the features of the protocol
 * itself. If you want to only use imquic as a QUIC/WebTrasport protocol,
 * and implement RoQ yourself, then you'll need to use imquic_create_server
 * or imquic_create_client instead.
 * @param[in] name The endpoint name (if NULL, a default value will be set)
 * @returns A pointer to a imquic_client object, if successful, NULL otherwise */
imquic_client *imquic_create_roq_client(const char *name, ...);

/*! \brief Configure the callback function to be notified about new RoQ connections
 * on the configured endpoint. For a server, it will be triggered any time
 * a client successfully connects to the server; for a client, it will
 * be triggered when the client successfully connects to the server.
 * @note This is a good place to obtain the first reference to a connection.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param new_roq_connection Pointer to the function that will be invoked on the new RoQ connection */
void imquic_set_new_roq_connection_cb(imquic_endpoint *endpoint,
	void (* new_roq_connection)(imquic_connection *conn, void *user_data));
/*! \brief Configure the callback function to be notified about incoming
 * RTP packets, independently of the multiplexing mode. The callback function
 * will only include the relevant data, that is the RoQ flow ID and a
 * buffer containing the RTP packet itself.
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param rtp_incoming Pointer to the function that will be invoked when there's a new incoming RTP packet */
void imquic_set_rtp_incoming_cb(imquic_endpoint *endpoint,
	void (* rtp_incoming)(imquic_connection *conn, uint64_t flow_id, uint8_t *bytes, size_t blen));
/*! \brief Configure the callback function to be notified when an existing
 * RoQ connection handled by this endpoint has been closed/shut down.
 * @note This is a good place to release the last reference to the connection
 * @param endpoint The imquic_endpoint (imquic_server or imquic_client) to configure
 * @param roq_connection_gone Pointer to the function that will be invoked when a RoQ connection is gone */
void imquic_set_roq_connection_gone_cb(imquic_endpoint *endpoint,
	void (* roq_connection_gone)(imquic_connection *conn));
///@}

/*! \brief RTP Over QUIC multiplexing modes */
typedef enum imquic_roq_multiplexing {
	/*! \brief RTP packet over \c DATAGRAM */
	IMQUIC_ROQ_DATAGRAM,
	/*! \brief One or more RTP packets over a \c STREAM */
	IMQUIC_ROQ_STREAM,
} imquic_roq_multiplexing;
/*! \brief Helper function to serialize to string the name of a imquic_roq_multiplexing property.
 * @param type The imquic_roq_multiplexing property
 * @returns The type name as a string, if valid, or NULL otherwise */
const char *imquic_roq_multiplexing_str(imquic_roq_multiplexing type);

/** @name Using the RoQ API
 */
///@{
/*! \brief Helper to send RTP packets over QUIC, using one of the supported
 * imquic_roq_multiplexing modes. The method only requires the flow ID
 * (to allow the recipient to identify the RTP session) and the RTP packet
 * to send (buffer and size). The stack will then internally frame the
 * packet as needed, using the right multiplexing mode and optionally
 * creating a new \c STREAM for the purpose.
 * @param[in] conn The RoQ connection to send the RTP packet on
 * @param[in] multiplexing The imquic_roq_multiplexing mode to use for sending this packet
 * @param[in] flow_id The RoQ flow ID
 * @param[in] bytes The buffer containing the RTP packet
 * @param[in] blen The size of the buffer to send
 * @param[in] close_stream Whether the \c STREAM should be closed after sending
 * this packet (ignored when using \c DATAGRAM as a multiplexing mode)
 * @returns The size of the RoQ message being sent, if successful, or 0 otherwise */
size_t imquic_roq_send_rtp(imquic_connection *conn, imquic_roq_multiplexing multiplexing,
	uint64_t flow_id, uint8_t *bytes, size_t blen, gboolean close_stream);
///@}

#endif
