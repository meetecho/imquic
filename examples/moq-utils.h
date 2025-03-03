/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * A few helpers and utilities that are helpful in most/all MoQ examples
 *
 */

#ifndef MOQ_UTILS
#define MOQ_UTILS

#include <glib.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

/* Helper to stringify a namespace (optionally the whole tuple) */
const char *imquic_moq_namespace_str(imquic_moq_namespace *tns, char *buffer, size_t blen, gboolean tuple);

/* Helper to stringify a track name */
const char *imquic_moq_track_str(imquic_moq_name *tn, char *buffer, size_t blen);

/* Helper to duplicate an object */
imquic_moq_object *imquic_moq_object_duplicate(imquic_moq_object *object);

/* Helper to destroy a duplicated object */
void imquic_moq_object_cleanup(imquic_moq_object *object);

/* Helper to destroy an object extension */
void imquic_moq_object_extension_free(imquic_moq_object_extension *extension);

#endif
