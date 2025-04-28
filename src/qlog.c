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
static size_t json_format = JSON_COMPACT | JSON_INDENT(0);

/* QLOG instance initialization and management */
static void imquic_qlog_free(const imquic_refcount *qlog_ref) {
	imquic_qlog *qlog = imquic_refcount_containerof(qlog_ref, imquic_qlog, ref);
	g_free(qlog->id);
	json_decref(qlog->root);
	g_free(qlog->filename);
	g_free(qlog);
}

imquic_qlog *imquic_qlog_create(char *id, gboolean sequential, gboolean is_server,
		char *filename, gboolean quic, gboolean http3, gboolean roq, gboolean moq) {
	if(id == NULL || filename == NULL)
		return NULL;
	if(!quic && !http3 && !roq && !moq) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Can't create QLOG instance, at least one of QUIC, HTTP/3, RoQ and MoQ should be enabled\n", id);
		return NULL;
	}
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
	qlog->quic = quic;
	qlog->http3 = http3;
	qlog->roq = roq;
	qlog->moq = moq;
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
	if(quic) {
		json_array_append_new(schemas, json_string("urn:ietf:params:qlog:events:quic-10"));
		json_array_append_new(protocols, json_string("QUIC"));
	}
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

void imquic_qlog_event_add_path_endpoint_info(json_t *parent, const char *name, const char *ip, uint16_t port) {
	if(parent == NULL || ip == NULL || (!json_is_object(parent) && !json_is_array(parent)) || (json_is_object(parent) && name == NULL))
		return;
	gboolean ipv6 = (strstr(ip, ":") != NULL);
	json_t *info = json_object();
	json_object_set_new(info, (ipv6 ? "ip_v6" : "ip_v4"), json_string(ip));
	json_object_set_new(info, (ipv6 ? "port_v6" : "port_v4"), json_integer(port));
	if(json_is_object(parent))
		json_object_set_new(parent, name, info);
	else
		json_array_append_new(parent, info);
}

static json_t *imquic_qlog_event_add_datagram_ids(json_t *data, uint32_t id) {
	if(data == NULL)
		return NULL;
	json_t *d_ids = json_array();
	json_array_append_new(d_ids, json_integer(id));
	json_object_set_new(data, "datagram_ids", d_ids);
	return data;
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

/* Events tracing */
void imquic_qlog_connection_started(imquic_qlog *qlog, const char *local_ip, uint16_t local_port, const char *remote_ip, uint16_t remote_port) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:connection_started");
	json_t *data = imquic_qlog_event_add_data(event);
	imquic_qlog_event_add_path_endpoint_info(data, "local", local_ip, local_port);
	imquic_qlog_event_add_path_endpoint_info(data, "remote", remote_ip, remote_port);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_connection_closed(imquic_qlog *qlog, gboolean local, uint32_t cc_code, uint32_t app_code, const char *reason) {
	if(qlog == NULL)
		return;
	/* TODO Just a placeholder for now */
	json_t *event = imquic_qlog_event_prepare("quic:connection_closed");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "owner", json_string(local ? "local" : "remote"));
	if(cc_code > 0)
		json_object_set_new(data, "connection_code", json_integer(cc_code));
	if(app_code > 0)
		json_object_set_new(data, "application_code", json_integer(app_code));
	if(reason != NULL)
		json_object_set_new(data, "reason", json_string(reason));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_version_information(imquic_qlog *qlog, uint32_t version, uint32_t chosen) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:version_information");
	json_t *data = imquic_qlog_event_add_data(event);
	json_t *vs = json_array();
	json_array_append_new(vs, json_integer(GPOINTER_TO_UINT(version)));
	json_object_set_new(data, (qlog->is_server ? "server_versions" : "client_versions"), vs);
	if(chosen > 0)
		json_object_set_new(data, "chosen_version", json_integer(chosen));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_alpn_information(imquic_qlog *qlog, uint8_t *server_alpn, size_t server_alpn_len,
		uint8_t *client_alpn, size_t client_alpn_len, char *chosen) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:alpn_information");
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

json_t *imquic_qlog_prepare_parameters_set(imquic_qlog *qlog, gboolean local, gboolean resumption, gboolean early_data) {
	if(qlog == NULL)
		return NULL;
	json_t *params = json_object();
	json_object_set_new(params, "owner", json_string(local ? "local" : "remote"));
	if(resumption)
		json_object_set_new(params, "resumption_allowed", json_true());
	if(early_data)
		json_object_set_new(params, "early_data_enabled", json_true());
	return params;
}

void imquic_qlog_parameters_set(imquic_qlog *qlog, json_t *params) {
	if(qlog == NULL || params == NULL) {
		if(params != NULL)
			json_decref(params);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("quic:parameters_set");
	json_object_set_new(event, "data", params);
	imquic_qlog_append_event(qlog, event);
}

json_t *imquic_qlog_prepare_packet_header(const char *type, void *scid, void *dcid) {
	if(type == NULL)
		return NULL;
	json_t *header = json_object();
	json_object_set_new(header, "packet_type", json_string(type));
	char cid[41];
	imquic_connection_id *source = (imquic_connection_id *)scid;
	if(source != NULL) {
		json_object_set_new(header, "scil", json_integer(source->len));
		if(source->len > 0) {
			const char *cid_str = imquic_connection_id_str(source, cid, sizeof(cid));
			if(cid_str != NULL)
				json_object_set_new(header, "scid", json_string(cid_str));
		}
	}
	imquic_connection_id *dest = (imquic_connection_id *)dcid;
	if(dest != NULL) {
		json_object_set_new(header, "dcil", json_integer(dest->len));
		if(dest->len > 0) {
			const char *cid_str = imquic_connection_id_str(dest, cid, sizeof(cid));
			if(cid_str != NULL)
				json_object_set_new(header, "dcid", json_string(cid_str));
		}
	}
	return header;
}

json_t *imquic_qlog_prepare_packet_frame(const char *type) {
	if(type == NULL)
		return NULL;
	json_t *frame = json_object();
	json_object_set_new(frame, "frame_type", json_string(type));
	return frame;
}

void imquic_qlog_packet_sent(imquic_qlog *qlog, json_t *header, json_t *frames, uint32_t id, size_t length) {
	if(qlog == NULL || header == NULL) {
		if(header != NULL)
			json_decref(header);
		if(frames != NULL)
			json_decref(frames);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("quic:packet_sent");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "header", header);
	if(frames != NULL)
		json_object_set_new(data, "frames", frames);
	if(length > 0)
		imquic_qlog_event_add_raw(data, "raw", NULL, length);
	if(id > 0)
		json_object_set_new(data, "datagram_id", json_integer(id));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_packet_received(imquic_qlog *qlog, json_t *header, json_t *frames, uint32_t id, size_t length) {
	if(qlog == NULL || header == NULL) {
		if(header != NULL)
			json_decref(header);
		if(frames != NULL)
			json_decref(frames);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("quic:packet_received");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "header", header);
	if(frames != NULL)
		json_object_set_new(data, "frames", frames);
	if(length > 0)
		imquic_qlog_event_add_raw(data, "raw", NULL, length);
	if(id > 0)
		json_object_set_new(data, "datagram_id", json_integer(id));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_packet_dropped(imquic_qlog *qlog, json_t *header, uint32_t id, size_t length, const char *trigger) {
	if(qlog == NULL) {
		if(header != NULL)
			json_decref(header);
		return;
	}
	json_t *event = imquic_qlog_event_prepare("quic:packet_dropped");
	json_t *data = imquic_qlog_event_add_data(event);
	if(header != NULL)
		json_object_set_new(data, "header", header);
	if(length > 0)
		imquic_qlog_event_add_raw(data, "raw", NULL, length);
	if(id > 0)
		json_object_set_new(data, "datagram_id", json_integer(id));
	if(trigger != NULL)
		json_object_set_new(data, "trigger", json_string(trigger));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_udp_datagrams_sent(imquic_qlog *qlog, uint32_t id, size_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:udp_datagrams_sent");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "count", json_integer(1));
	json_t *array = json_array();
	imquic_qlog_event_add_raw(array, NULL, NULL, length);
	json_object_set_new(data, "raw", array);
	if(id > 0)
		imquic_qlog_event_add_datagram_ids(data, id);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_udp_datagrams_received(imquic_qlog *qlog, uint32_t id, size_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:udp_datagrams_received");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "count", json_integer(1));
	json_t *array = json_array();
	imquic_qlog_event_add_raw(array, NULL, NULL, length);
	json_object_set_new(data, "raw", array);
	if(id > 0)
		imquic_qlog_event_add_datagram_ids(data, id);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_udp_datagrams_dropped(imquic_qlog *qlog, uint32_t id, size_t length) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:udp_datagrams_dropped");
	json_t *data = imquic_qlog_event_add_data(event);
	imquic_qlog_event_add_raw(data, "raw", NULL, length);
	if(id > 0)
		imquic_qlog_event_add_datagram_ids(data, id);
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_stream_state_updated(imquic_qlog *qlog, uint64_t id, const char *type, const char *side, const char *state) {
	if(qlog == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:stream_state_updated");
	json_t *data = imquic_qlog_event_add_data(event);
	json_object_set_new(data, "stream_id", json_integer(id));
	if(type != NULL)
		json_object_set_new(data, "stream_type", json_string(type));
	if(side != NULL)
		json_object_set_new(data, "stream_side", json_string(side));
	if(state != NULL)
		json_object_set_new(data, "new", json_string(state));
	imquic_qlog_append_event(qlog, event);
}

void imquic_qlog_key_updated(imquic_qlog *qlog, const char *type, uint8_t *key, size_t key_len, uint64_t key_phase) {
	if(qlog == NULL || type == NULL)
		return;
	json_t *event = imquic_qlog_event_prepare("quic:key_updated");
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
