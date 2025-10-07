/*! \file   network.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Networking utilities (headers)
 * \details Implementation of the networking functionality of the QUIC
 * stack. This is where client and server instances are allocated and
 * managed, taking care of actually sending data out, and to notify upper
 * layers about new connections or data coming in. The networking stack
 * relies on a separate event loop for polling the sockets.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_NETWORK_H
#define IMQUIC_NETWORK_H

#include <stdint.h>
#include <sys/socket.h>

#include "../imquic/imquic.h"
#include "configuration.h"
#include "loop.h"
#include "crypto.h"
#include "moq.h"
#include "roq.h"
#include "refcount.h"

/*! \brief Initialize the network stack at startup */
void imquic_network_init(void);
/*! \brief Uninitialize the network stack */
void imquic_network_deinit(void);

/*! \brief Abstraction of a network address */
typedef struct imquic_network_address {
	/*! \brief Network address */
	struct sockaddr_storage addr;
	/*! \brief Size of the network address */
	socklen_t addrlen;
} imquic_network_address;
/*! \brief Helper to serialize a network address to a string
 * @param[in] address The imquic_network_address instance to serialize
 * @param[out] output The buffer to put the serialized string into
 * @param[in] outlen The size of the output buffer
 * @param[in] add_port Whether the port should be added to the string
 * @returns A pointer to output, if successful, or NULL otherwise */
char *imquic_network_address_str(imquic_network_address *address, char *output, size_t outlen, gboolean add_port);
/*! \brief Helper to return the port used by a network address
 * @param[in] address The imquic_network_address instance to query
 * @returns A port number, if successful, or -1 otherwise */
uint16_t imquic_network_address_port(imquic_network_address *address);

/*! \brief Abstraction of a network endpoint (client or server) */
typedef struct imquic_network_endpoint {
	/*! brief Opaque pointer to the source owning this socket (to handle it in the loop) */
	void *source;
	/*! \brief Name of this endpoint */
	char *name;
	/*! \brief Whether this is a client or a server */
	gboolean is_server;
	/*! \brief Socket */
	int fd;
	/*! \brief Local and remote ports */
	uint16_t port, remote_port;
	/*! \brief Local address */
	imquic_network_address local_address;
	/*! \brief Remote address of the peer (clients only) */
	imquic_network_address remote_address;
	/*! \brief TLS stack */
	imquic_tls *tls;
	/*! \brief SNI the client will use */
	char *sni;
	/*! \brief Whether raw QUIC should be supported */
	gboolean raw_quic;
	/*! \brief ALPN this endpoint will negotiate, when using raw QUIC */
	char *alpn;
	/*! \brief Whether WebTransport should be supported */
	gboolean webtransport;
	/*! \brief For WebTransport clients, the path to \c CONNECT to (\c / by default) */
	char *h3_path;
	/*! \brief In case WebTransport is used, array of protocols to negotiate */
	char **wt_protocols;
	/*! \brief List of connections handled by this socket (may be more than one for servers) */
	GHashTable *connections;
	/*! \brief Number of connections handled by this socket (may be more than one for servers) */
	uint64_t conns_num;
	/*! \brief Whether this endpoint has internal generic callbacks (true for the native RoQ and MoQ stacks) */
	gboolean internal_callbacks;
	/*! \brief Callback to invoke when a new connection is available on this endpoint */
	void (* new_connection)(imquic_connection *conn, void *user_data);
	/*! \brief Callback to invoke when new \c STREAM data is available on one of the connections handled by this endpoint */
	void (* stream_incoming)(imquic_connection *conn, uint64_t stream_id,
		uint8_t *bytes, uint64_t offset, uint64_t length, gboolean complete);
	/*! \brief Callback to invoke when new \c DATAGRAM data is available on one of the connections handled by this endpoint */
	void (* datagram_incoming)(imquic_connection *conn, uint8_t *bytes, uint64_t length);
	/*! \brief Callback to invoke when new one of the connections handled by this endpoint is closed */
	void (* connection_gone)(imquic_connection *conn);
	/*! \brief Callback to invoke when a client connection attempt fails */
	void (* connection_failed)(void *user_data);
	/*! \brief User data to pass in the \c new_connection callback, to correlate a connection to the endpoint it's coming from */
	void *user_data;
	/*! \brief (Sub-)Protocol this endpoint uses, in case imquic is handling a protocol natively */
	uint64_t protocol;
	/*! \brief (Sub-)Protocol specific callbacks (at the time of writing, RoQ and MoQ only) */
	union {
		imquic_moq_callbacks moq;
		imquic_roq_callbacks roq;
	} callbacks;
	/*! \brief Path to save QLOG files to, if needed/supported: a filename for clients, a folder for servers */
	char *qlog_path;
	/*! \brief Whether sequential JSON should be used for the QLOG file, instead of regular JSON  */
	gboolean qlog_sequential;
	/*! \brief Whether QUIC and/or HTTP/3 and/or RoQ and/or MoQT events should be saved to QLOG, if supported */
	gboolean qlog_quic, qlog_http3, qlog_roq, qlog_moq;
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether this connection has been started */
	volatile gint started;
	/*! \brief Whether this connection is being shut down */
	volatile gint shutting;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_network_endpoint;
/*! \brief Helper to create a new imquic_network_endpoint instance from a imquic_configuration object
 * @param config The imquic_configuration object to use to configure and create the new endpoint
 * @returns A pointer to a new imquic_network_endpoint instance, if successful, or NULL otherwise */
imquic_network_endpoint *imquic_network_endpoint_create(imquic_configuration *config);
/*! \brief Helper to add a new connection to the list of connections originated by this endpoint
 * @param ne The imquic_network_endpoint instance to add the connection to
 * @param conn The imquic_connection instance to add to the endpoint
 * @param lock_mutex Whether the endpoint mutex should be used to protect the action (to avoid double locks) */
void imquic_network_endpoint_add_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex);
/*! \brief Helper to remove an existing connection from the list of connections originated by this endpoint
 * @param ne The imquic_network_endpoint instance to remove the connection from
 * @param conn The imquic_connection instance to remove from the endpoint
 * @param lock_mutex Whether the endpoint mutex should be used to protect the action (to avoid double locks) */
void imquic_network_endpoint_remove_connection(imquic_network_endpoint *ne, imquic_connection *conn, gboolean lock_mutex);
/*! \brief Helper to shutdown an existing endpoint
 * @param ne The imquic_network_endpoint instance to shut down */
void imquic_network_endpoint_shutdown(imquic_network_endpoint *ne);
/*! \brief Helper to destroy an existing endpoint instance
 * @param ne The imquic_network_endpoint instance to destroy */
void imquic_network_endpoint_destroy(imquic_network_endpoint *ne);

/*! \brief Helper to send data on a connection
 * @param conn The imquic_connection instance to send the data on
 * @param bytes The data to send
 * @param blen the size of the data to send
 * @returns 0 in case of success, a negative integer otherwise */
int imquic_network_send(imquic_connection *conn, uint8_t *bytes, size_t blen);

#endif
