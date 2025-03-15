/*! \file   configuration.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  imquic public interface
 * \details imquic configuration, to creare clients and servers.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_CONFIGURATION_H
#define IMQUIC_CONFIGURATION_H

#include <stdint.h>

#include <glib.h>

/*! \brief imquic initialization state */
typedef enum imquic_init_state {
	IMQUIC_UNINITIALIZED = -1,
	IMQUIC_NOT_INITIALIZED = 0,
	IMQUIC_INITIALIZING,
	IMQUIC_INITIALIZED
} imquic_init_state;
extern volatile int initialized;

/*! \brief A client/server configuration */
typedef struct imquic_configuration {
	/*! \brief Name of the endpoint */
	const char *name;
	/*! \brief Whether this is a server or a client */
	gboolean is_server;
	/*! \brief Interface or IP address to bind to */
	const char *ip;
	/*! \brief Local port of the endpoint */
	uint16_t local_port;
	/*! \brief Remote address to connect to (client-only) */
	const char *remote_host;
	/*! \brief Remote port to connect to (client-only) */
	uint16_t remote_port;
	/*! \brief SNI to force, if any (will use localhost otherwise) */
	const char *sni;
	/*! \brief ALPN to negotiate for raw QUIC */
	const char *alpn;
	/*! \brief Whether raw QUIC should be offered
	 * \note In case both \c raw_quic and \c webtranport are set to \c FALSE
	 * the configuration will automatically default to raw QUIC only */
	gboolean raw_quic;
	/*! \brief Whether WebTransport should be offered */
	gboolean webtransport;
	/*! \brief In case WebTransport is used, the HTTP/3 path to connect to (client-only) */
	const char *h3_path;
	/*! \brief In case WebTransport is used, the subprotocol to negotiate (currently unused) */
	const char *subprotocol;
	/*! \brief Path to save QLOG files to, if needed/supported: a filename for clients, a folder for servers */
	const char *qlog_path;
	/*! \brief Whether sequential JSON should be used for the QLOG file, instead of regular JSON  */
	gboolean qlog_sequential;
	/*! \brief Whether QUIC and/or RoQ and/or MoQT events should be saved to QLOG, if supported */
	gboolean qlog_quic, qlog_roq, qlog_moq;
	/*! \brief Path to the certificate file to use for TLS */
	const char *cert_pem;
	/*! \brief Path to the key file to use for TLS */
	const char *cert_key;
	/*! \brief Password needed to access the certificate for TLS, if any */
	const char *cert_pwd;
	/*! \brief Whether early data should be supported */
	gboolean early_data;
	/*! \brief File to use for session tickets, when doing early data */
	const char *ticket_file;
	/*! \brief Optional user data, to pass back when notifying new connections associated to this endpoint */
	void *user_data;
} imquic_configuration;

#endif
