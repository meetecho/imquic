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
#define IMQUIC_QLOG_TRIGGER_KEY_UNAVAILABLE			"key_unavailable"
#define IMQUIC_QLOG_TRIGGER_UNKNOWN_CONNECTION_ID	"unknown_connection_id"
#define IMQUIC_QLOG_TRIGGER_DECRYPT_ERROR			"decrypt_error"
#define IMQUIC_QLOG_TRIGGER_UNSUPPORTED_VERSION		"unsupported_version"
///@}

/** @name QLOG management
 */
///@{
/*! \brief QLOG instance */
typedef struct imquic_qlog {
	/*! \brief Instance ID */
	char *id;
	/*! \brief Whether this is for a client or server connection */
	gboolean is_server;
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
 * @param is_server Whether this is for a client or server connection
 * @param filename Path to where the JSON file should be saved
 * @returns A pointer to a new imquic_qlog instance, if successful, or NULL otherwise */
imquic_qlog *imquic_qlog_create(char *id, gboolean is_server, char *filename);
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
/*! \brief Add a \c version_information event
 * @param qlog The imquic_qlog instance to add the event to
 * @param version The version we support (just one, right now)
 * @param chosen The chosen version */
void imquic_qlog_transport_version_information(imquic_qlog *qlog, uint32_t version, uint32_t chosen);
/*! \brief Add a \c alpn_information event
 * @param qlog The imquic_qlog instance to add the event to
 * @param server_alpn The buffer containing the list of server ALPNs, if any
 * @param server_alpn_len The size of the server ALPN buffer
 * @param client_alpn The buffer containing the list of client ALPNs, if any
 * @param client_alpn_len The size of the client ALPN buffer
 * @param chosen The chosen ALPN */
void imquic_qlog_transport_alpn_information(imquic_qlog *qlog, uint8_t *server_alpn, size_t server_alpn_len,
	uint8_t *client_alpn, size_t client_alpn_len, char *chosen);
/*! \brief Prepare a \c parameters_set object, but don't add it yet
 * @note This is needed to prepare an object that calls that can be
 * filled in externally, and then be passed to imquic_qlog_transport_parameters_set
 * @param qlog The imquic_qlog instance to prepare the data for
 * @param local Whether this is a local or remote parameters set
 * @param resumption Whether the \c resumption_allowed property should be set to TRUE
 * @param early_data Whether the \c early_data_enabled property should be set to TRUE
 * @returns A pointer to the parameters set object, if successful, or NULL otherwise */
json_t *imquic_qlog_transport_prepare_parameters_set(imquic_qlog *qlog, gboolean local, gboolean resumption, gboolean early_data);
/*! \brief Add a \c parameters_set event
 * @param qlog The imquic_qlog instance to add the event to
 * @param params Pointer to a previously filled parameters set data object */
void imquic_qlog_transport_parameters_set(imquic_qlog *qlog, json_t *params);
/*! \brief Add a \c udp_datagrams_sent event
 * @param qlog The imquic_qlog instance to add the event to
 * @param length The size of the datagram that was sent */
void imquic_qlog_transport_udp_datagrams_sent(imquic_qlog *qlog, size_t length);
/*! \brief Add a \c udp_datagrams_received event
 * @param qlog The imquic_qlog instance to add the event to
 * @param length The size of the datagram that was sent */
void imquic_qlog_transport_udp_datagrams_received(imquic_qlog *qlog, size_t length);
/*! \brief Add a \c key_updated event
 * @param qlog The imquic_qlog instance to add the event to
 * @param type The key type
 * @param key Pointer to the key value
 * @param key_len Size of the key value
 * @param key_phase The key phase */
void imquic_qlog_security_key_updated(imquic_qlog *qlog, const char *type, uint8_t *key, size_t key_len, uint64_t key_phase);

///@}

#endif

#endif
