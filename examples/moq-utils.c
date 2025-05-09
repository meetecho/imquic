/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * A few helpers and utilities that are helpful in most/all MoQ examples
 *
 */

#include "moq-utils.h"

/* Helper to duplicate an object */
imquic_moq_object *imquic_moq_object_duplicate(imquic_moq_object *object) {
	if(object == NULL)
		return NULL;
	imquic_moq_object *new_obj = g_malloc(sizeof(imquic_moq_object));
	memcpy(new_obj, object, sizeof(imquic_moq_object));
	if(object->payload_len == 0) {
		new_obj->payload = NULL;
	} else {
		new_obj->payload = g_malloc(object->payload_len);
		memcpy(new_obj->payload, object->payload, object->payload_len);
	}
	if(object->extensions_len == 0) {
		new_obj->extensions = NULL;
	} else {
		new_obj->extensions = g_malloc(object->extensions_len);
		memcpy(new_obj->extensions, object->extensions, object->extensions_len);
	}
	return new_obj;
}

/* Helper to destroy a duplicated object */
void imquic_moq_object_cleanup(imquic_moq_object *object) {
	if(object) {
		g_free(object->payload);
		g_free(object->extensions);
		g_free(object);
	}
}

/* Helper to destroy an object extension */
void imquic_moq_object_extension_free(imquic_moq_object_extension *extension) {
	if(extension != NULL) {
		if(extension->value.data.buffer != NULL)
			g_free(extension->value.data.buffer);
		g_free(extension);
	}
}

/* Helpers to deal with auth info */
int imquic_moq_auth_info_to_bytes(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t *authlen) {
	if(conn == NULL || auth_info == NULL || auth == NULL || authlen == 0)
		return -1;
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_11) {
		/* Just copy the string to the buffer */
		*authlen = strlen(auth_info);
		memcpy(auth, auth_info, *authlen);
	} else {
		/* Serialize the token using the USE_VALUE alias type */
		imquic_moq_auth_token token = { 0 };
		token.alias_type = IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE;
		token.token_type_set = TRUE;
		token.token_type = 1;	/* FIXME */
		token.token_value.buffer = (uint8_t *)auth_info;
		token.token_value.length = strlen(auth_info);
		size_t offset = imquic_moq_build_auth_token(&token, auth, *authlen);
		if(offset == 0)
			return -1;
		*authlen = offset;
	}
	return 0;
}

void imquic_moq_print_auth_info(imquic_connection *conn, uint8_t *auth, size_t authlen) {
	if(conn == NULL || auth == NULL || authlen == 0)
		return;
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_11) {
		/* String */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %.*s\n",
			imquic_get_connection_name(conn), (int)authlen, auth);
	} else {
		/* Data (hex) */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: ",
			imquic_get_connection_name(conn));
		for(size_t i=0; i<authlen; ++i)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "%02x", auth[i]);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
	}
}

gboolean imquic_moq_check_auth_info(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t authlen) {
	if(auth_info == NULL)
		return TRUE;
	if(conn == NULL || auth == NULL || authlen == 0)
		return FALSE;
	char auth_str[257];
	auth_str[0] = '\0';
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_11) {
		/* Interpret as a string */
		g_snprintf(auth_str, sizeof(auth_str), "%.*s", (int)authlen, auth);
	} else {
		/* Unpack the token */
		imquic_moq_auth_token token = { 0 };
		if(imquic_moq_parse_auth_token(auth, authlen, &token) < 0)
			return FALSE;
		if(token.alias_type != IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] This demo currently only supports %s as an auth token alias type, ignoring %s\n",
				imquic_get_connection_name(conn),
				imquic_moq_auth_token_alias_type_str(IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE),
				imquic_moq_auth_token_alias_type_str(token.alias_type));
			return FALSE;
		}
		/* Interpret the token value as a string */
		g_snprintf(auth_str, sizeof(auth_str), "%.*s", (int)token.token_value.length, token.token_value.buffer);
	}
	/* Compare as strings */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Parsed Authorization Token Value: %s\n",
		imquic_get_connection_name(conn), auth_str);
	return !strcmp(auth_info, auth_str);
}
