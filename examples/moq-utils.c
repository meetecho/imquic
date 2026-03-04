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
	new_obj->properties = imquic_moq_properties_duplicate(object->properties);
	return new_obj;
}

/* Helper to print a list of properties */
void imquic_moq_properties_print(GList *properties) {
	GList *temp = properties;
	while(temp) {
		imquic_moq_property *prop = (imquic_moq_property *)temp->data;
		const char *prop_name = imquic_moq_property_type_str(prop->id);
		if(prop->id % 2 == 0) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  >> Property '%"SCNu32"' (%s) = %"SCNu64"\n",
				prop->id, (prop_name ? prop_name : "unknown"), prop->value.number);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  >> Property '%"SCNu32"' (%s) = %.*s\n",
				prop->id, (prop_name ? prop_name : "unknown"), (int)prop->value.data.length, prop->value.data.buffer);
		}
		temp = temp->next;
	}
}

/* Helper to duplicate a list of properties */
GList *imquic_moq_properties_duplicate(GList *properties) {
	if(properties == NULL)
		return NULL;
	GList *new_properties = NULL;
	GList *temp = properties;
	while(temp) {
		imquic_moq_property *prop = (imquic_moq_property *)temp->data;
		imquic_moq_property *new_prop = g_malloc0(sizeof(imquic_moq_property));
		new_prop->id = prop->id;
		if(prop->id % 2 == 0) {
			new_prop->value.number = prop->value.number;
		} else {
			new_prop->value.data.length = prop->value.data.length;
			if(prop->value.data.length > 0) {
				new_prop->value.data.buffer = g_malloc(prop->value.data.length);
				memcpy(new_prop->value.data.buffer, prop->value.data.buffer, prop->value.data.length);
			}
		}
		new_properties = g_list_prepend(new_properties, new_prop);
		temp = temp->next;
	}
	new_properties = g_list_reverse(new_properties);
	return new_properties;
}

/* Helper to destroy a duplicated object */
void imquic_moq_object_cleanup(imquic_moq_object *object) {
	if(object) {
		g_free(object->payload);
		g_list_free_full(object->properties, (GDestroyNotify)(imquic_moq_property_cleanup));
		g_free(object);
	}
}

/* Helper to destroy an object propertie */
void imquic_moq_property_cleanup(imquic_moq_property *property) {
	if(property != NULL) {
		if(property->value.data.buffer != NULL)
			g_free(property->value.data.buffer);
		g_free(property);
	}
}

/* Helpers to deal with auth info */
int imquic_moq_auth_info_to_bytes(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t *authlen) {
	if(conn == NULL || auth_info == NULL || auth == NULL || authlen == 0)
		return -1;
	/* Serialize the token using the USE_VALUE alias type */
	imquic_moq_auth_token token = { 0 };
	token.alias_type = IMQUIC_MOQ_AUTH_TOKEN_USE_VALUE;
	token.token_type_set = TRUE;
	token.token_type = 0;	/* FIXME */
	token.token_value.buffer = (uint8_t *)auth_info;
	token.token_value.length = strlen(auth_info);
	size_t offset = imquic_moq_build_auth_token(&token, auth, *authlen);
	if(offset == 0)
		return -1;
	*authlen = offset;
	return 0;
}

void imquic_moq_print_auth_info(imquic_connection *conn, uint8_t *auth, size_t authlen) {
	if(conn == NULL || auth == NULL || authlen == 0)
		return;
	/* Data (hex) */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: ",
		imquic_get_connection_name(conn));
	for(size_t i=0; i<authlen; ++i)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "%02x", auth[i]);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
}

gboolean imquic_moq_check_auth_info(imquic_connection *conn, const char *auth_info, uint8_t *auth, size_t authlen) {
	if(auth_info == NULL)
		return TRUE;
	if(conn == NULL || auth == NULL || authlen == 0)
		return FALSE;
	char auth_str[257];
	auth_str[0] = '\0';
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
	/* Compare as strings */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Parsed Authorization Token Value: %s\n",
		imquic_get_connection_name(conn), auth_str);
	return !strcmp(auth_info, auth_str);
}
