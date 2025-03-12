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
