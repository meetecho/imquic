/*! \file   qlog.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QLOG support (headers)
 * \details Implementation of QLOG support (JSON serialization) via the
 * Jansson library.
 *
 * \note Jansson is an optional dependency, meaning that the functionality
 * exposed by this code may not be available at runtime. When attempting
 * to enable QLOG usage in that case, a warning will be shown on the
 * console.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_QLOG_H
#define IMQUIC_QLOG_H

#include <glib.h>

/*! \brief Helper method to check if QLOG is supported at runtime
 * @returns TRUE if supported, FALSE otherwise */
gboolean imquic_qlog_is_supported(void);

#ifdef HAVE_QLOG
#include <jansson.h>

#include "refcount.h"
#include "mutex.h"

/** @name QLOG properties definitions
 */
///@{
/*! \brief Trigger definitions */
#define IMQUIC_QLOG_TRIGGER_INTERNAL_ERROR			"internal_error"
#define IMQUIC_QLOG_TRIGGER_REJECTED				"rejected"
#define IMQUIC_QLOG_TRIGGER_UNSUPPORTED				"unsupported"
#define IMQUIC_QLOG_TRIGGER_INVALID					"invalid"
#define IMQUIC_QLOG_TRIGGER_DUPLICATE				"duplicate"
#define IMQUIC_QLOG_TRIGGER_CONNECTION_UNKNOWN		"connection_unknown"
#define IMQUIC_QLOG_TRIGGER_DECRYPTION_FAILURE		"decryption_failure"
#define IMQUIC_QLOG_TRIGGER_KEY_UNAVAILABLE			"key_unavailable"
#define IMQUIC_QLOG_TRIGGER_GENERAL					"general"
///@}

/** @name QLOG management
 */
///@{
/*! \brief QLOG instance */
typedef struct imquic_qlog {
	/*! \brief Instance ID */
	char *id;
	/*! \brief Whether sequential JSON will be used, instead of regular JSON */
	gboolean sequential;
	/*! \brief Whether this is for a client or server connection */
	gboolean is_server;
	/*! \brief Whether QUIC and/or HTTP/3 and/or RoQ and/or MoQT events should be saved */
	gboolean quic, http3, roq, moq;
	/*! \brief Jansson JSON instance */
	json_t *root;
	/*! \brief Reference to the common fields entry */
	json_t *common;
	/*! \brief Reference to the events array */
	json_t *events;
	/*! \brief Path to where the JSON file should be saved */
	char *filename;
	/*! \brief File to save the JSON file to */
	FILE *file;
	/*! \brief Mutex */
	imquic_mutex mutex;
	/*! \brief Whether this instance has been destroyed (reference counting) */
	volatile gint destroyed;
	/*! \brief Reference counter */
	imquic_refcount ref;
} imquic_qlog;

/*! \brief Helper method to initialize a new QLOG instance
 * @note This method will try to create the file right away, and will
 * fail and give up immediately if that doesn't succeed for whatever
 * reason. It will not create the folders part of the filename if the
 * related folders don't exist already, which means those should be
 * created by the application using the library, in case
 * @param id ID of the log (ends in the title property)
 * @param sequential Whether sequential JSON should be used, instead of regular JSON
 * @param is_server Whether this is for a client or server connection
 * @param filename Path to where the JSON file should be saved
 * @param quic Whether QUIC events should be added to the QLOG
 * @param http3 Whether HTTP/3 events should be added to the QLOG
 * @param roq Whether RoQ events should be added to the QLOG
 * @param moq Whether MoQT events should be added to the QLOG
 * @returns A pointer to a new imquic_qlog instance, if successful, or NULL otherwise */
imquic_qlog *imquic_qlog_create(char *id, gboolean sequential, gboolean is_server,
	char *filename, gboolean quic, gboolean http3, gboolean roq, gboolean moq);
/*! \brief Set/update the Original Destination Connection ID
 * @param qlog The imquic_qlog instance to update
 * @param odcid The Original Destination Connection ID to write, as a imquic_connection_id instance */
void imquic_qlog_set_odcid(imquic_qlog *qlog, void *odcid);
/*! \brief Save the current status of the QLOG structure to JSON
 * @note This does not close the file, as other events may arrive later.
 * This function is called automatically before destroying the instance
 * @param qlog The imquic_qlog instance to save to file
 * @returns 0 if successful, a negative integer otherwise */
int imquic_qlog_save_to_file(imquic_qlog *qlog);
/*! \brief Helper method to destroy an existing QLOG instance
 * @note Destroying the instance will write the file to disk
 * @param qlog The imquic_qlog instance to destroy */
void imquic_qlog_destroy(imquic_qlog *qlog);
///@}

/** @name QLOG events tracing
 */
///@{
/*! \brief Helper to create a new QLOG event by name
 * @note This automatically fills in the \c time property
 * @param name The name of the event
 * @returns An event instance to fill in before appending it, if successful, or NULL otherwise */
json_t *imquic_qlog_event_prepare(const char *name);
/*! \brief Helper to add a \c data object to an event and return a pointer to it
 * @param event The event to add the data object to
 * @returns A pointer to the data object, if successful, or NULL otherwise */
json_t *imquic_qlog_event_add_data(json_t *event);
/*! \brief Helper to add/append a \c raw object to the specified object or array
 * @param parent The object or array to add/append the raw info to
 * @param name Name to give to the raw object, if the parent is an object (ignored for arrays)
 * @param bytes The content of the raw data, if needed
 * @param length The size of the raw data */
void imquic_qlog_event_add_raw(json_t *parent, const char *name, uint8_t *bytes, size_t length);
/*! \brief Helper to add/append a PathEndpointInfo object to the specified object or array
 * @note The method automatically fills in either the v4 or v6 info by looking at the address
 * @param parent The object or array to add/append the info to
 * @param name Name to give to the object, if the parent is an object (ignored for arrays)
 * @param ip The IP address
 * @param port The port */
void imquic_qlog_event_add_path_endpoint_info(json_t *parent, const char *name, const char *ip, uint16_t port);
/*! \brief Helper to add a complete event object to an existing QLOG instance
 * @param qlog The imquic_qlog instance to add the event to
 * @param event The event to add to the QLOG instance */
void imquic_qlog_append_event(imquic_qlog *qlog, json_t *event);
/*! \brief Add a \c connection_started event
 * @param qlog The imquic_qlog instance to add the event to
 * @param local_ip The local address the connection
 * @param local_port The local port the connection
 * @param remote_ip The remote address the connection
 * @param remote_port The remote port the connection */
void imquic_qlog_connection_started(imquic_qlog *qlog, const char *local_ip, uint16_t local_port, const char *remote_ip, uint16_t remote_port);
/*! \brief Add a \c connection_closed event
 * @param qlog The imquic_qlog instance to add the event to
 * @param local Whether this is a local or remote event
 * @param cc_code The connection code in the Connection Close message, if any
 * @param app_code The application code in the Connection Close message, if any
 * @param reason The reason text in the Connection Close message, if any */
void imquic_qlog_connection_closed(imquic_qlog *qlog, gboolean local, uint32_t cc_code, uint32_t app_code, const char *reason);
/*! \brief Add a \c version_information event
 * @param qlog The imquic_qlog instance to add the event to
 * @param version The version we support (just one, right now)
 * @param chosen The chosen version */
void imquic_qlog_version_information(imquic_qlog *qlog, uint32_t version, uint32_t chosen);
/*! \brief Add a \c alpn_information event
 * @param qlog The imquic_qlog instance to add the event to
 * @param server_alpn The buffer containing the list of server ALPNs, if any
 * @param server_alpn_len The size of the server ALPN buffer
 * @param client_alpn The buffer containing the list of client ALPNs, if any
 * @param client_alpn_len The size of the client ALPN buffer
 * @param chosen The chosen ALPN */
void imquic_qlog_alpn_information(imquic_qlog *qlog, uint8_t *server_alpn, size_t server_alpn_len,
	uint8_t *client_alpn, size_t client_alpn_len, char *chosen);
/*! \brief Prepare a \c parameters_set object, but don't add it yet
 * @note This is needed to prepare an object that calls that can be
 * filled in externally, and then be passed to imquic_qlog_parameters_set
 * @param qlog The imquic_qlog instance to prepare the data for
 * @param local Whether this is a local or remote parameters set
 * @param resumption Whether the \c resumption_allowed property should be set to TRUE
 * @param early_data Whether the \c early_data_enabled property should be set to TRUE
 * @returns A pointer to the parameters set object, if successful, or NULL otherwise */
json_t *imquic_qlog_prepare_parameters_set(imquic_qlog *qlog, gboolean local, gboolean resumption, gboolean early_data);
/*! \brief Add a \c parameters_set event
 * @param qlog The imquic_qlog instance to add the event to
 * @param params Pointer to a previously filled parameters set data object */
void imquic_qlog_parameters_set(imquic_qlog *qlog, json_t *params);
/*! \brief Prepare a \c header object, but don't add it yet
 * @note This is needed to prepare an object that calls that can be
 * filled in externally, and then be passed to events that involve packets
 * @param type The packet type
 * @param scid Opaque pointer to the source imquic_connection_id, if any
 * @param dcid Opaque pointer to the destination imquic_connection_id, if any
 * @returns A pointer to the header object, if successful, or NULL otherwise */
json_t *imquic_qlog_prepare_packet_header(const char *type, void *scid, void *dcid);
/*! \brief Prepare a \c frames object, but don't add it yet
 * @note This is needed to prepare an object that can be filled in
 * externally, and then be passed to events that involve packets
 * @param type The frame type
 * @returns A pointer to the new object, if successful, or NULL otherwise */
json_t *imquic_qlog_prepare_packet_frame(const char *type);
/*! \brief Add a \c packet_sent event
 * @param qlog The imquic_qlog instance to add the event to
 * @param header The QUIC packet header info, if any
 * @param frames The QUIC packet frames, if any
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was sent */
void imquic_qlog_packet_sent(imquic_qlog *qlog, json_t *header, json_t *frames, uint32_t id, size_t length);
/*! \brief Add a \c packet_received event
 * @param qlog The imquic_qlog instance to add the event to
 * @param header The QUIC packet header info
 * @param frames The QUIC packet frames, if any
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was received */
void imquic_qlog_packet_received(imquic_qlog *qlog, json_t *header, json_t *frames, uint32_t id, size_t length);
/*! \brief Add a \c packet_dropped event
 * @param qlog The imquic_qlog instance to add the event to
 * @param header The QUIC packet header info, if any
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was received
 * @param trigger What caused the packet to be dropped */
void imquic_qlog_packet_dropped(imquic_qlog *qlog, json_t *header, uint32_t id, size_t length, const char *trigger);
/*! \brief Add a \c udp_datagrams_sent event
 * @param qlog The imquic_qlog instance to add the event to
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was sent */
void imquic_qlog_udp_datagrams_sent(imquic_qlog *qlog, uint32_t id, size_t length);
/*! \brief Add a \c udp_datagrams_received event
 * @param qlog The imquic_qlog instance to add the event to
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was sent */
void imquic_qlog_udp_datagrams_received(imquic_qlog *qlog, uint32_t id, size_t length);
/*! \brief Add a \c udp_datagrams_dropped event
 * @param qlog The imquic_qlog instance to add the event to
 * @param id The ID of the datagram, if any
 * @param length The size of the datagram that was dropped */
void imquic_qlog_udp_datagrams_dropped(imquic_qlog *qlog, uint32_t id, size_t length);
/*! \brief Add a \c stream_state_updated event
 * @param qlog The imquic_qlog instance to add the event to
 * @param id The ID of the stream
 * @param type The stream type (bidirectional/unidirectional), if any
 * @param side The stream side (sending/receiving), if any
 * @param state The new stream state, if any */
void imquic_qlog_stream_state_updated(imquic_qlog *qlog, uint64_t id, const char *type, const char *side, const char *state);
/*! \brief Add a \c key_updated event
 * @param qlog The imquic_qlog instance to add the event to
 * @param type The key type
 * @param key Pointer to the key value
 * @param key_len Size of the key value
 * @param key_phase The key phase */
void imquic_qlog_key_updated(imquic_qlog *qlog, const char *type, uint8_t *key, size_t key_len, uint64_t key_phase);
///@}

#endif

#endif
