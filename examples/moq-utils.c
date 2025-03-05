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

/* Helper to stringify a namespace (optionally the whole tuple) */
const char *imquic_moq_namespace_str(imquic_moq_namespace *tns, char *buffer, size_t blen, gboolean tuple) {
	if(tns == NULL || tns->buffer == 0 || tns->length == 0)
		return NULL;
	*buffer = '\0';
	char temp[256];
	size_t offset = 0;
	while(tns != NULL && tns->buffer != NULL) {
		if(blen - offset == 0)
			goto trunc;
		if(offset > 0) {
			buffer[offset] = '/';
			offset++;
			buffer[offset] = '\0';
		}
		g_snprintf(temp, sizeof(temp), "%.*s", (int)tns->length, tns->buffer);
		if(blen - offset < strlen(temp))
			goto trunc;
		offset = g_strlcat(buffer, temp, blen);
		if(offset >= blen)
			goto trunc;
		if(!tuple)
			break;
		tns = tns->next;
	}
	return buffer;
trunc:
	IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render namespace(s) as a string (truncation would occur)\n");
	return NULL;
}

/* Helper to stringify a track name */
const char *imquic_moq_track_str(imquic_moq_name *tn, char *buffer, size_t blen) {
	if(tn == NULL || tn->buffer == 0 || tn->length == 0)
		return NULL;
	*buffer = '\0';
	char temp[256];
	size_t offset = 0;
	g_snprintf(temp, sizeof(temp), "%.*s", (int)tn->length, tn->buffer);
	if(blen - offset < strlen(temp))
		goto trunc;
	offset = g_strlcat(buffer, temp, blen);
	if(offset >= blen)
		goto trunc;
	return buffer;
trunc:
	IMQUIC_LOG(IMQUIC_LOG_ERR, "Insufficient buffer to render track name as a string (truncation would occur)\n");
	return NULL;
}

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
