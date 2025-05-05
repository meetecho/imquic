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

/* Helpers to deal with auth info */
int imquic_moq_auth_info_to_bytes(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t *authlen);
void imquic_moq_print_auth_info(imquic_connection *conn, uint8_t *auth, size_t authlen);
gboolean imquic_moq_check_auth_info(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t authlen);

#endif
