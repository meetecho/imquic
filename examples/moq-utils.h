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

/* Helper to duplicate an object */
imquic_moq_object *imquic_moq_object_duplicate(imquic_moq_object *object);

/* Helper to destroy a duplicated object */
void imquic_moq_object_cleanup(imquic_moq_object *object);

/* Helper to destroy an object extension */
void imquic_moq_object_extension_free(imquic_moq_object_extension *extension);

#endif
