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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "internal/qlog.h"
#include "internal/version.h"
#include "imquic/debug.h"

gboolean imquic_qlog_is_supported(void) {
#ifdef HAVE_QLOG
	return TRUE;
#else
	return FALSE;
#endif
}

/* The implementation is only available if Jansson was found */
#ifdef HAVE_QLOG

/* JSON serialization options */
static size_t json_format = JSON_INDENT(3) | JSON_PRESERVE_ORDER;

/* QLOG instance initialization and management */
static void imquic_qlog_free(const imquic_refcount *qlog_ref) {
	imquic_qlog *qlog = imquic_refcount_containerof(qlog_ref, imquic_qlog, ref);
	g_free(qlog->id);
	json_decref(qlog->root);
	g_free(qlog->filename);
	g_free(qlog);
}

imquic_qlog *imquic_qlog_create(char *id, gboolean is_server, char *filename) {
	if(id == NULL || filename == NULL)
		return NULL;
	imquic_qlog *qlog = g_malloc0(sizeof(imquic_qlog));
	qlog->file = fopen(filename, "wt");
	if(qlog->file == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error opening QLOG file '%s' for writing: %d (%s)\n",
			id, filename, errno, g_strerror(errno));
		g_free(qlog);
		return NULL;
	}
	qlog->id = g_strdup(id);
	qlog->filename = g_strdup(filename);
	/* Initialize the QLOG structure */
	qlog->root = json_object();
	json_object_set_new(qlog->root, "qlog_format", json_string("JSON"));
	json_object_set_new(qlog->root, "qlog_version", json_string("0.9"));
	json_t *traces = json_array();
	json_object_set_new(qlog->root, "traces", traces);
	json_t *trace = json_object();
	json_t *common = json_object();
	json_object_set_new(common, "ODCID", json_string(id));	/* FIXME */
	json_object_set_new(trace, "common_fields", common);
	json_t *vantage = json_object();
	char name[256];
	g_snprintf(name, sizeof(name), "%s %s", imquic_name, imquic_version_string_full);
	json_object_set_new(vantage, "name", json_string(name));
	json_object_set_new(vantage, "type", json_string(is_server ? "server" : "client"));
	json_object_set_new(trace, "vantage_point", vantage);
	qlog->events = json_array();
	json_object_set_new(trace, "events", qlog->events);
	json_array_append_new(traces, trace);
	/* Done */
	imquic_refcount_init(&qlog->ref, imquic_qlog_free);
	/* Save the skeleton to file */
	if(imquic_qlog_save_to_file(qlog) < 0) {
		imquic_qlog_destroy(qlog);
		return NULL;
	}
	return qlog;
}

void imquic_qlog_destroy(imquic_qlog *qlog) {
	if(qlog && g_atomic_int_compare_and_exchange(&qlog->destroyed, 0, 1)) {
		/* Save the QLOG to JSON before cleaning up */
		imquic_qlog_save_to_file(qlog);
		fclose(qlog->file);
		imquic_refcount_decrease(&qlog->ref);
	}
}

/* Save the QLOG to JSON */
int imquic_qlog_save_to_file(imquic_qlog *qlog) {
	if(qlog == NULL || qlog->root == NULL)
		return -1;
	/* Generate the JSON string */
	imquic_mutex_lock(&qlog->mutex);
	char *json = json_dumps(qlog->root, json_format);
	if(json == NULL) {
		imquic_mutex_unlock(&qlog->mutex);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing QLOG to JSON\n", qlog->id);
		return -2;
	}
	/* Save the string to file */
	fseek(qlog->file, 0, SEEK_SET);
	int res = 0;
	size_t length = strlen(json), tot = length;
	while(tot > 0) {
		res = fwrite(json+length-tot, sizeof(char), tot, qlog->file);
		if(res <= 0) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error saving QLOG file: %d (%s)\n",
				qlog->id, errno, g_strerror(errno));
			imquic_mutex_unlock(&qlog->mutex);
			return -3;
		}
		tot -= res;
	}
	fflush(qlog->file);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] QLOG saved to '%s'\n", qlog->id, qlog->filename);
	imquic_mutex_unlock(&qlog->mutex);
	free(json);
	/* Done */
	return 0;
}

#endif
