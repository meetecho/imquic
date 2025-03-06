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

/*! \brief QLOG instance */
typedef struct imquic_qlog {
	/*! \brief Instance ID */
	char *id;
	/*! \brief Jansson JSON instance */
	json_t *root;
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
 * @param id ID of the log (ends in the ODCID property)
 * @param is_server Whether this is for a client or server connection
 * @param filename Path to where the JSON file should be saved
 * @returns A pointer to a new imquic_log instance, if successful, or NULL otherwise */
imquic_qlog *imquic_qlog_create(char *id, gboolean is_server, char *filename);
/*! \brief Helper method to destroy an existing QLOG instance
 * @note Destroying the instance will write the file to disk
 * @param qlog The imquic_log instance to destroy */
void imquic_qlog_destroy(imquic_qlog *qlog);

/*! \brief Save the current status of the QLOG structure to JSON
 * @note This does not close the file, as other events may arrive later.
 * This function is called automatically before destroying the instance
 * @param qlog The imquic_log instance to save to file
 * @returns 0 if successful, a negative integer otherwise */
int imquic_qlog_save_to_file(imquic_qlog *qlog);

#endif

#endif
