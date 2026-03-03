/*! \file   quic.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC management (headers)
 * \details Implementation of the QUIC life cycle management, leveraging
 * methods and callbacks provided by picoquic to manage connections
 *
 * \ingroup Core
 *  */

#ifndef IMQUIC_QUIC_H
#define IMQUIC_QUIC_H

#include "loop.h"
#include "network.h"
#include "connection.h"

/*! \brief Initialize the QUIC stack at startup
 * @param secrets_log File to use to store QUIC secret, e.g., for Wireshark debugging (see SSLKEYLOGFILE) */
void imquic_quic_init(const char *secrets_log);
/*! \brief Uninitialize the QUIC stack */
void imquic_quic_deinit(void);

/*! \brief Helper method to return the SSLKEYLOGFILE, if configured
 * @returns The SSLKEYLOGFILE, if configured, or NULL otherwise */
const char *imquic_quic_sslkeylog_file(void);

/*! \brief Helper method to create a picoquic context for an endpoint
 * @param endpoint The imquic_network_endpoint instance associated with the picoquic context
 * @param config The imquic_configuration instance used to configure the new endpoint
 * @returns 0, if successful, or a negative integer otherwise */
int imquic_quic_create_context(imquic_network_endpoint *endpoint, imquic_configuration *config);

/*! \brief Helper method to process incoming UDP messages
 * @param endpoint The imquic_network_endpoint instance the message came from
 * @param buffer The message data
 * @param len The message size
 * @param sender The imquic_network_address the message came from */
void imquic_quic_incoming_packet(imquic_network_endpoint *endpoint, uint8_t *buffer, size_t len, imquic_network_address *sender);

/*! \brief Callback fired when there's a queued event to process for a
 * connection, to process and trigger via picoquic in a thread-safe way
 * @param conn The imquic_connection the event is for
 * @param event The imquic_connection_event instance to handle
 * @returns G_SOURCE_CONTINUE if the event should be fired again in
 * the future, G_SOURCE_REMOVE otherwise */
gboolean imquic_quic_queued_event(imquic_connection *conn, imquic_connection_event *event);

/*! \brief Helper to schedule the next picoquic lifecycle iteration
 * @param endpoint The imquic_network_endpoint instance to update */
void imquic_quic_next_step(imquic_network_endpoint *endpoint);

#endif
