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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "internal/qlog.h"
#include "internal/connection.h"
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
static size_t json_format = JSON_COMPACT | JSON_INDENT(0);

/* QLOG instance initialization and management */
static void imquic_qlog_free(const imquic_refcount *qlog_ref) {
	imquic_qlog *qlog = imquic_refcount_containerof(qlog_ref, imquic_qlog, ref);
	g_free(qlog->id);
	json_decref(qlog->root);
	g_free(qlog->filename);
	g_free(qlog);
}

imquic_qlog *imquic_qlog_create(char *id, char *cid,
		char *folder, gboolean sequential, gboolean is_server,
		gboolean http3, gboolean roq, gboolean roq_packets,
		gboolean moq, gboolean moq_messages, gboolean moq_objects) {
	if(id == NULL || cid == NULL || folder == NULL)
		return NULL;
	if(!http3 && !roq && !moq) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Can't create QLOG instance, at least one of HTTP/3, RoQ and MoQ should be enabled\n", id);
		return NULL;
	}
	char filename[1024];
	g_snprintf(filename, sizeof(filename), "%s/%s.%s.imquic.%s",
		folder, cid,
		is_server ? "server" : "client",
		sequential ? "sqlog" : "qlog");
	imquic_qlog *qlog = g_malloc0(sizeof(imquic_qlog));
	qlog->file = fopen(filename, "wt");
	if(qlog->file == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error opening QLOG file '%s' for writing: %d (%s)\n",
			id, filename, errno, g_strerror(errno));
		g_free(qlog);
		return NULL;
	}
	qlog->id = g_strdup(id);
	qlog->sequential = sequential;
	qlog->is_server = is_server;
	qlog->filename = g_strdup(filename);
	qlog->http3 = http3;
	qlog->roq = roq;
	qlog->roq_packets = roq_packets;
	qlog->moq = moq;
	qlog->moq_messages = moq_messages;
	qlog->moq_objects = moq_objects;
	/* Initialize the QLOG structure */
	qlog->root = json_object();
	json_object_set_new(qlog->root, "file_schema", json_string(sequential ?
		"urn:ietf:params:qlog:file:sequential" : "urn:ietf:params:qlog:file:contained"));
	json_object_set_new(qlog->root, "serialization_format", json_string(sequential ?
		"application/qlog+json-seq" : "application/qlog+json"));
	json_object_set_new(qlog->root, "title", json_string(id));
	json_t *common = json_object();
	json_t *protocols = json_array();
	json_t *schemas = json_array();
	if(http3) {
		json_array_append_new(schemas, json_string("urn:ietf:params:qlog:events:http3-10"));
		json_array_append_new(protocols, json_string("HTTP/3"));
	}
	if(roq) {
		json_array_append_new(schemas, json_string("urn:ietf:params:qlog:events:roq-00"));
		json_array_append_new(protocols, json_string("ROQ"));
	}
	if(moq) {
		json_array_append_new(schemas, json_string("urn:ietf:params:qlog:events:moqt-00"));
		json_array_append_new(protocols, json_string("MOQT"));
	}
	json_object_set_new(qlog->root, "event_schemas", schemas);
	json_object_set_new(common, "protocol_types", protocols);
	json_object_set_new(common, "time_format", json_string("relative_to_epoch"));
	json_object_set_new(common, "ODCID", json_string(cid));
	json_t *reference = json_object();
	json_object_set_new(reference, "clock_type", json_string("system"));
	json_object_set_new(reference, "epoch", json_string("1970-01-01T00:00:00.000Z"));
	json_object_set_new(common, "reference_time", reference);
	json_t *traces = NULL;
	if(!sequential) {
		traces = json_array();
		json_object_set_new(qlog->root, "traces", traces);
	}
	json_t *trace = json_object();
	json_object_set_new(trace, "common_fields", common);
	qlog->common = common;
	json_t *vantage = json_object();
	char name[256];
	g_snprintf(name, sizeof(name), "%s %s", imquic_name, imquic_version_string_full);
	json_object_set_new(vantage, "name", json_string(name));
	json_object_set_new(vantage, "type", json_string(is_server ? "server" : "client"));
	json_object_set_new(trace, "vantage_point", vantage);
	if(!sequential) {
		qlog->events = json_array();
		json_object_set_new(trace, "events", qlog->events);
		json_array_append_new(traces, trace);
	} else {
		json_object_set_new(qlog->root, "trace", trace);
	}
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
		/* Save the QLOG to JSON before cleaning up (unless it's a sequential JSON) */
		if(!qlog->sequential)
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
	if(qlog->sequential) {
		/* Add a Record Separator (0x1E) first */
		char rs = 0x1E;
		fwrite(&rs, sizeof(char), 1, qlog->file);
	}
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
	if(qlog->sequential) {
		/* Add a line feed */
		char lf = '\n';
		fwrite(&lf, sizeof(char), 1, qlog->file);
	}
	fflush(qlog->file);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] QLOG saved to '%s'\n", qlog->id, qlog->filename);
	imquic_mutex_unlock(&qlog->mutex);
	free(json);
	/* Done */
	return 0;
}

/* Events tracing helpers */
json_t *imquic_qlog_event_prepare(const char *name) {
	json_t *event = json_object();
	json_object_set_new(event, "name", json_string(name));
	double timestamp = (double)g_get_real_time() / (double)1000;
	json_object_set_new(event, "time", json_real(timestamp));
	return event;
}

json_t *imquic_qlog_event_add_data(json_t *event) {
	if(event == NULL)
		return NULL;
	json_t *data = json_object();
	json_object_set_new(event, "data", data);
	return data;
}

void imquic_qlog_event_add_raw(json_t *parent, const char *name, uint8_t *bytes, size_t length) {
	if(parent == NULL || (!json_is_object(parent) && !json_is_array(parent)) || (json_is_object(parent) && name == NULL))
		return;
	json_t *raw = json_object();
	/* FIXME We should add the payload_length property too */
	json_object_set_new(raw, "length", json_integer(length));
	if(bytes != NULL && length > 0) {
		char b_str[81];
		if(length > 40)
			length = 40;	/* Truncate */
		json_object_set_new(raw, "data", json_string(imquic_hex_str(bytes, length, b_str, sizeof(b_str))));
	}
	if(json_is_object(parent))
		json_object_set_new(parent, name, raw);
	else
		json_array_append_new(parent, raw);
}

void imquic_qlog_append_event(imquic_qlog *qlog, json_t *event) {
	if(qlog == NULL || event == NULL) {
		if(event != NULL)
			json_decref(event);
		return;
	}
	imquic_mutex_lock(&qlog->mutex);
	if(!qlog->sequential) {
		/* Regular JSON, add to the list of events */
		json_array_append_new(qlog->events, event);
	} else {
		/* Sequential JSON, convert the event to JSON to save it */
		char *json = json_dumps(event, json_format);
		json_decref(event);
		if(json == NULL) {
			imquic_mutex_unlock(&qlog->mutex);
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error serializing QLOG event to JSON\n", qlog->id);
			return;
		}
		/* Add a Record Separator (0x1E) first */
		char rs = 0x1E;
		fwrite(&rs, sizeof(char), 1, qlog->file);
		/* Now append the event JSON */
		int res = 0;
		size_t length = strlen(json), tot = length;
		while(tot > 0) {
			res = fwrite(json+length-tot, sizeof(char), tot, qlog->file);
			if(res <= 0) {
				IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Error saving QLOG event to file: %d (%s)\n",
					qlog->id, errno, g_strerror(errno));
				imquic_mutex_unlock(&qlog->mutex);
				return;
			}
			tot -= res;
		}
		free(json);
		/* Add a line feed */
		char lf = '\n';
		fwrite(&lf, sizeof(char), 1, qlog->file);
		/* Done */
		fflush(qlog->file);
	}
	imquic_mutex_unlock(&qlog->mutex);
}

#endif
