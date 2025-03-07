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
static size_t json_format = JSON_INDENT(3);

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
	qlog->is_server = is_server;
	qlog->filename = g_strdup(filename);
	/* Initialize the QLOG structure */
	qlog->root = json_object();
	json_object_set_new(qlog->root, "qlog_format", json_string("JSON"));
	json_object_set_new(qlog->root, "qlog_version", json_string("0.9"));
	json_object_set_new(qlog->root, "title", json_string(id));
	json_t *traces = json_array();
	json_object_set_new(qlog->root, "traces", traces);
	json_t *trace = json_object();
	json_t *common = json_object();
	json_t *protocols = json_array();
	json_array_append_new(protocols, json_string("QUIC"));
	json_object_set_new(common, "protocol_types", protocols);
	json_object_set_new(common, "ODCID", json_string("xxx"));	/* Needs to be the Original Connection ID */
	json_object_set_new(common, "time_format", json_string("relative_to_epoch"));
	json_t *reference = json_object();
	json_object_set_new(reference, "clock_type", json_string("system"));
	json_object_set_new(reference, "epoch", json_string("1970-01-01T00:00:00.000Z"));
	json_object_set_new(common, "reference_time", reference);
	json_object_set_new(trace, "common_fields", common);
	qlog->common = common;
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

void imquic_qlog_set_odcid(imquic_qlog *qlog, void *odcid) {
	if(qlog == NULL || odcid == NULL)
		return;
	char cid[41];
	const char *cid_str = imquic_connection_id_str((imquic_connection_id *)odcid, cid, sizeof(cid));
	imquic_mutex_lock(&qlog->mutex);
	json_object_set_new(qlog->common, "ODCID", json_string(cid_str));
	imquic_mutex_unlock(&qlog->mutex);
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

/* Events tracing helpers */
static json_t *imquic_qlog_event_prepare(const char *name) {
	json_t *event = json_object();
	json_object_set_new(event, "name", json_string(name));
	double timestamp = (double)g_get_real_time() / (double)1000;
	json_object_set_new(event, "time", json_real(timestamp));
	return event;
}

static json_t *imquic_qlog_event_add_data(json_t *event) {
	if(event == NULL)
		return NULL;
	json_t *data = json_object();
	json_object_set_new(event, "data", data);
	return data;
}

static json_t *imquic_qlog_event_add_raw(json_t *data, size_t length) {
	if(data == NULL)
		return NULL;
	json_t *raw = json_object();
	/* FIXME We should add the payload_length property too */
	json_object_set_new(raw, "length", json_integer(length));
	json_object_set_new(data, "raw", raw);
	return data;
}

static void imquic_qlog_append_event(imquic_qlog *qlog, json_t *event) {
	if(qlog == NULL || event == NULL) {
		if(event != NULL)
			json_decref(event);
		return;
	}
	imquic_mutex_lock(&qlog->mutex);
	json_array_append_new(qlog->events, event);
	imquic_mutex_unlock(&qlog->mutex);
}

/* Events tracing */
void imquic_qlog_transport_version_information(imquic_qlog *qlog, uint32_t version, uint32_t chosen) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("transport:version_information");
	json_t *data = imquic_qlog_event_add_data(event);
	json_t *vs = json_array();
	json_array_append_new(vs, json_integer(GPOINTER_TO_UINT(version)));
	json_object_set_new(data, (qlog->is_server ? "server_versions" : "client_versions"), vs);
	if(chosen > 0)
		json_object_set_new(data, "chosen_version", json_integer(chosen));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_transport_alpn_information(imquic_qlog *qlog, uint8_t *server_alpn, size_t server_alpn_len,
		uint8_t *client_alpn, size_t client_alpn_len, char *chosen) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("transport:alpn_information");
	json_t *data = imquic_qlog_event_add_data(event);
	if(server_alpn != NULL && server_alpn_len > 0) {
		json_t *list = json_array();
		char alpn[256];
		size_t alpn_len = sizeof(alpn);
		uint8_t *p = server_alpn, lp = 0;
		while(server_alpn_len > 0) {
			lp = *p;
			if(lp == 0)
				break;
			p++;
			g_snprintf(alpn, alpn_len, "%.*s", lp, (char *)p);
			json_array_append_new(list, json_string(alpn));
			server_alpn_len -= (lp + 1);
			p += lp;
		}
		json_object_set_new(data, "server_alpns", list);
	}
	if(client_alpn != NULL && client_alpn_len > 0) {
		json_t *list = json_array();
		char alpn[256];
		size_t alpn_len = sizeof(alpn);
		uint8_t *p = client_alpn, lp = 0;
		while(client_alpn_len > 0) {
			lp = *p;
			if(lp == 0)
				break;
			p++;
			g_snprintf(alpn, alpn_len, "%.*s", lp, (char *)p);
			json_array_append_new(list, json_string(alpn));
			client_alpn_len -= (lp + 1);
			p += lp;
		}
		json_object_set_new(data, "client_alpns", list);
	}
	if(chosen != NULL)
		json_object_set_new(data, "chosen_alpn", json_string(chosen));
	imquic_qlog_append_event(qlog, event);
}

json_t *imquic_qlog_transport_prepare_parameters_set(imquic_qlog *qlog, gboolean local, gboolean resumption, gboolean early_data) {
	json_t *params = json_object();
	json_object_set_new(params, "owner", json_string(local ? "local" : "remote"));
	if(resumption)
		json_object_set_new(params, "resumption_allowed", json_true());
	if(early_data)
		json_object_set_new(params, "early_data_enabled", json_true());
	return params;
}

void imquic_qlog_transport_parameters_set(imquic_qlog *qlog, json_t *params) {
	if(qlog == NULL || params == NULL) {
		if(params != NULL)
			json_decref(params);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("transport:parameters_set");
	json_object_set_new(event, "data", params);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_transport_udp_datagrams_sent(imquic_qlog *qlog, size_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("transport:udp_datagrams_sent");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "count", json_integer(1));
	imquic_qlog_event_add_raw(data, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_transport_udp_datagrams_received(imquic_qlog *qlog, size_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("transport:udp_datagrams_received");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "count", json_integer(1));
	imquic_qlog_event_add_raw(data, length);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_security_key_updated(imquic_qlog *qlog, const char *type, uint8_t *key, size_t key_len, uint64_t key_phase) {
	if(qlog == NULL || type == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("security:key_updated");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "key_type", json_string(type));
	if(key != NULL && key_len > 0) {
		char key_str[65];
		json_object_set_new(data, "new", json_string(imquic_hex_str(key, key_len, key_str, sizeof(key_str))));
	}
	json_object_set_new(data, "key_phase", json_integer(key_phase));
	json_object_set_new(data, "trigger", json_string("tls"));
	imquic_qlog_append_event(qlog, event);
}

#endif
