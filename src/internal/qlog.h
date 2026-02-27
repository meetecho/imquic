/*! \file   qlog.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QLOG support (headers)
 * \details Implementation of QLOG support (JSON serialization) via the
 * Jansson library. This implementation only allows to create QLOG files
 * for the HTTP/3, RoQ and MoQ layers: QUIC QLOG files will be created,
 * in a separate file, by picoquic instead, when required.
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
	/*! \brief Whether HTTP/3 and/or RoQ and/or MoQT events should be saved */
	gboolean http3, roq, roq_packets, moq, moq_messages, moq_objects;
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
 * @param cid Initial Connection ID
 * @param folder Path to the folder where the JSON file should be saved
 * @param sequential Whether sequential JSON should be used, instead of regular JSON
 * @param is_server Whether this is for a client or server connection
 * @param http3 Whether HTTP/3 events should be added to the QLOG
 * @param roq Whether RoQ events should be added to the QLOG
 * @param roq_packets Whether RoQ packets should be added to the QLOG
 * @param moq Whether MoQT events should be added to the QLOG
 * @param moq_messages Whether MoQT messages should be added to the QLOG
 * @param moq_objects Whether MoQT objects should be added to the QLOG
 * @returns A pointer to a new imquic_qlog instance, if successful, or NULL otherwise */
imquic_qlog *imquic_qlog_create(char *id, char *cid,
	char *folder, gboolean sequential, gboolean is_server,
	gboolean http3, gboolean roq, gboolean roq_packets,
	gboolean moq, gboolean moq_messages, gboolean moq_objects);
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
/*! \brief Helper to add a complete event object to an existing QLOG instance
 * @param qlog The imquic_qlog instance to add the event to
 * @param event The event to add to the QLOG instance */
void imquic_qlog_append_event(imquic_qlog *qlog, json_t *event);
///@}

#endif

#endif
