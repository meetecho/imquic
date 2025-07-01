/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ subscriber
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-sub-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping sub, please wait...\n");
			break;
		case 1:
			IMQUIC_PRINT("In a hurry? I'm trying to free resources cleanly, here!\n");
			break;
		default:
			IMQUIC_PRINT("Ok, leaving immediately...\n");
			break;
	}
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
}

/* Subscriber state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static GList *request_ids = NULL;
static uint64_t max_request_id = 20;
static imquic_moq_filter_type filter_type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
static imquic_moq_location start_location = { 0 }, end_location = { 0 }, end_location_sub = { 0 };
static int64_t update_time = 0;
static uint8_t relay_auth[256];
static size_t relay_authlen = 0;

/* Object processing type */
typedef enum imquic_demo_media_type {
	DEMO_TYPE_NONE = 0,	/* Don't print the object payload */
	DEMO_TYPE_TEXT,		/* Print the object payload as text */
	DEMO_TYPE_HEX,		/* Print the object payload as a hex string */
	DEMO_TYPE_LOC,		/* Parse the object payload as LOC (moq-encoder-player's version) */
	DEMO_TYPE_MP4		/* Save the object payload to an mp4 file (moq-rs's version) */
} imquic_demo_media_type;
static const char *imquic_demo_media_type_str(imquic_demo_media_type type) {
	switch(type) {
		case DEMO_TYPE_NONE:
			return "none";
		case DEMO_TYPE_TEXT:
			return "text";
		case DEMO_TYPE_HEX:
			return "hex";
		case DEMO_TYPE_LOC:
			return "loc";
		case DEMO_TYPE_MP4:
			return "mp4";
		default:
			break;
	}
	return NULL;
}
static imquic_demo_media_type media_type = DEMO_TYPE_NONE;

/* File to save objects to, if any */
static FILE *file = NULL;

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	moq_conn = conn;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection (negotiating version)\n", imquic_get_connection_name(conn));
	imquic_moq_set_role(conn, IMQUIC_MOQ_SUBSCRIBER);
	imquic_moq_set_version(conn, moq_version);
	imquic_moq_set_max_request_id(conn, max_request_id);
	/* Check if we need to prepare an auth token to connect to the relay */
	if(options.relay_auth_info && strlen(options.relay_auth_info) > 0) {
		relay_authlen = sizeof(relay_auth);
		if(imquic_moq_auth_info_to_bytes(conn, options.relay_auth_info, relay_auth, &relay_authlen) < 0) {
			relay_authlen = 0;
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error serializing the auth token\n",
				imquic_get_connection_name(conn));
		}
		imquic_moq_set_connection_auth(conn, relay_auth, relay_authlen);
	}
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready (%s)\n",
		imquic_get_connection_name(conn), imquic_moq_version_str(imquic_moq_get_version(conn)));
	moq_version = imquic_moq_get_version(conn);
	/* Let's subscribe to the provided namespace/name(s) */
	int i = 0;
	uint64_t request_id = 0;
	uint64_t track_alias = 0;
	imquic_moq_namespace tns[32];	/* FIXME */
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		tns[i].buffer = (uint8_t *)track_namespace;
		tns[i].length = strlen(track_namespace);
		tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
		i++;
	}
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	i = 0;
	/* Check if we need to prepare an auth token */
	uint8_t auth[256];
	size_t authlen = 0;
	if(options.auth_info && strlen(options.auth_info) > 0) {
		authlen = sizeof(auth);
		if(imquic_moq_auth_info_to_bytes(conn, options.auth_info, auth, &authlen) < 0) {
			authlen = 0;
			IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error serializing the auth token\n",
				imquic_get_connection_name(conn));
		}
	}
	/* Check if we need to request forwarding right away, or if we'll ask send an update later */
	gboolean forward = TRUE;
	if(options.update_subscribe > 0 && imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_11 && (options.fetch == NULL || options.join_offset >= 0))
		forward = FALSE;
	if(options.subscribe_announces) {
		/* Only send a SUBSCRIBE_ANNOUNCES: the relay will send us a
		 * PUBLISH request when there's something we can subscribe to */
		if(moq_version < IMQUIC_MOQ_VERSION_12) {
			/* Version is too old, we can't: stop here */
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "PUBLISH only supported starting from version 12\n");
			g_atomic_int_inc(&stop);
			return;
		}
		imquic_moq_subscribe_announces(conn, imquic_moq_get_next_request_id(conn), tns, auth, authlen);
		return;
	}
	/* If we got here, we're subscribing manually to the specified tracks,
	 * either via SUBSCRIBE or FETCH, so iterate on all track names */
	while(options.track_name[i] != NULL) {
		const char *track_name = options.track_name[i];
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] %s to '%s'/'%s' (%s), using ID %"SCNu64"/%"SCNu64"\n",
			imquic_get_connection_name(conn), (options.fetch == NULL ? "Subscribing" : "Fetching"),
			ns, track_name, imquic_demo_media_type_str(media_type), request_id, track_alias);
		imquic_moq_name tn = {
			.buffer = (uint8_t *)track_name,
			.length = strlen(track_name)
		};
		request_id = imquic_moq_get_next_request_id(conn);
		if(options.fetch == NULL) {
			/* Send a SUBSCRIBE */
			imquic_moq_subscribe(conn, request_id, track_alias, &tns[0], &tn,
				0, FALSE, forward, filter_type, &start_location, &end_location_sub, auth, authlen);
			if(!forward)
				request_ids = g_list_append(request_ids, imquic_uint64_dup(request_id));
		} else {
			/* Send a FETCH */
			if(options.join_offset < 0) {
				/* Standalone Fetch */
				imquic_moq_fetch_range range = {
					.start = start_location,
					.end = end_location
				};
				imquic_moq_standalone_fetch(conn, request_id, &tns[0], &tn,
					!strcasecmp(options.fetch, "descending"), &range, auth, authlen);
			} else {
				/* Send a SUBSCRIBE first */
				imquic_moq_subscribe(conn, request_id, track_alias, &tns[0], &tn,
					0, FALSE, forward, filter_type, &start_location, &end_location_sub, auth, authlen);
				if(!forward)
					request_ids = g_list_append(request_ids, imquic_uint64_dup(request_id));
				/* Now send a Joining Fetch referencing that subscription */
				uint64_t fetch_request_id = imquic_moq_get_next_request_id(conn);
				imquic_moq_joining_fetch(conn, fetch_request_id, request_id,
					FALSE, options.join_offset, !strcasecmp(options.fetch, "descending"), auth, authlen);
			}
		}
		i++;
		track_alias++;
	}
	if(!forward) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Scheduling a SUBSCRIBE_UPDATE in %d seconds\n",
			imquic_get_connection_name(conn), options.update_subscribe);
		update_time = g_get_monotonic_time() + (options.update_subscribe * G_USEC_PER_SEC);
	}
}

static void imquic_demo_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, uint64_t expires, gboolean descending, imquic_moq_location *largest) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription %"SCNu64" accepted (expires=%"SCNu64"; %s order)\n",
		imquic_get_connection_name(conn), request_id, expires, descending ? "descending" : "ascending");
	if(largest) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Largest Location: %"SCNu64"/%"SCNu64"\n",
			imquic_get_connection_name(conn), largest->group, largest->object);
	}
}

static void imquic_demo_subscribe_error(imquic_connection *conn, uint64_t request_id, imquic_moq_sub_error_code error_code, const char *reason, uint64_t track_alias) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to ID %"SCNu64"/%"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, track_alias, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn, uint64_t track_alias,
		gboolean descending, imquic_moq_location *largest, gboolean forward, uint8_t *auth, size_t authlen) {
	/* We received a publish */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming publish for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, request_id, track_alias);
	if(auth != NULL)
		imquic_moq_print_auth_info(conn, auth, authlen);
	if(name == NULL || strlen(name) == 0)
		name = "temp";
	/* Done */
	forward = TRUE;
	if(options.update_subscribe > 0 && imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_11 && (options.fetch == NULL || options.join_offset >= 0)) {
		forward = FALSE;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Scheduling a SUBSCRIBE_UPDATE in %d seconds\n",
			imquic_get_connection_name(conn), options.update_subscribe);
		request_ids = g_list_append(request_ids, imquic_uint64_dup(request_id));
		update_time = g_get_monotonic_time() + (options.update_subscribe * G_USEC_PER_SEC);
	}
	imquic_moq_accept_publish(conn, request_id, forward, 0, FALSE,
		filter_type, &start_location, &end_location_sub);
}

static void imquic_demo_subscribe_done(imquic_connection *conn, uint64_t request_id, imquic_moq_sub_done_code status_code, uint64_t streams_count, const char *reason) {
	/* Our subscription is done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to ID %"SCNu64" is done, using %"SCNu64" streams: status %d (%s)\n",
		imquic_get_connection_name(conn), request_id, streams_count, status_code, reason);
	/* TODO */
}

static void imquic_demo_fetch_accepted(imquic_connection *conn, uint64_t request_id, gboolean descending, imquic_moq_location *largest) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Fetch %"SCNu64" accepted (%s order; largest group/object %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), request_id, descending ? "descending" : "ascending", largest->group, largest->object);
}

static void imquic_demo_fetch_error(imquic_connection *conn, uint64_t request_id, imquic_moq_fetch_error_code error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error fetching via ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here, unless it was a joining FETCH */
	if(options.join_offset < 0)
		g_atomic_int_inc(&stop);
}

static void imquic_demo_subscribe_announces_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to announcements '%"SCNu64"' accepted, waiting for PUBLISH requests\n",
		imquic_get_connection_name(conn), request_id);
}

static void imquic_demo_subscribe_announces_error(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_subannc_error_code error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to announcements in request '%"SCNu64"': error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_object(imquic_connection *conn, imquic_moq_object *object) {
	/* We received an object */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming object: sub=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64", id=%"SCNu64", payload=%zu bytes, extensions=%zu bytes, delivery=%s, status=%s, eos=%d\n",
		imquic_get_connection_name(conn), object->request_id, object->track_alias,
		object->group_id, object->subgroup_id, object->object_id,
		object->payload_len, object->extensions_len, imquic_moq_delivery_str(object->delivery),
		imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	if(object->payload == NULL || object->payload_len == 0) {
		if(object->end_of_stream) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d on empty packet)\n",
				imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
			if(object->delivery == IMQUIC_MOQ_USE_TRACK || (object->delivery == IMQUIC_MOQ_USE_FETCH && options.join_offset < 0)) {
				/* Stop here */
				g_atomic_int_inc(&stop);
			}
		}
		return;
	}
	if(object->extensions != NULL && object->extensions_len > 0) {
		GList *extensions = imquic_moq_parse_object_extensions(object->extensions, object->extensions_len);
		GList *temp = extensions;
		while(temp) {
			imquic_moq_object_extension *ext = (imquic_moq_object_extension *)temp->data;
			if(ext->id % 2 == 0) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  >> Extension '%"SCNu32"' = %"SCNu64"\n", ext->id, ext->value.number);
			} else {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  >> Extension '%"SCNu32"' = %.*s\n", ext->id, (int)ext->value.data.length, ext->value.data.buffer);
			}
			temp = temp->next;
		}
		g_list_free_full(extensions, (GDestroyNotify)imquic_moq_object_extension_free);
	}
	if(file != NULL)
		fwrite(object->payload, 1, object->payload_len, file);
	if(media_type == DEMO_TYPE_TEXT) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %.*s\n", (int)object->payload_len, object->payload);
	} else if(media_type == DEMO_TYPE_HEX) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- ");
		for(size_t i=0; i<object->payload_len; ++i)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "%02x", object->payload[i]);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
	} else if(media_type == DEMO_TYPE_LOC) {
		/* FIXME Assuming LOC from https://github.com/facebookexperimental/moq-encoder-player/ */
		uint8_t length = 0;
		size_t offset = 0;
		uint64_t chunk_type = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Chunk type:  %"SCNu64"\n", chunk_type);
		offset += length;
		uint64_t seq_id = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Sequence ID: %"SCNu64"\n", seq_id);
		offset += length;
		uint64_t timestamp = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Timestamp:  %"SCNu64"\n", timestamp);
		offset += length;
		uint64_t duration = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Duration:   %"SCNu64"\n", duration);
		offset += length;
		uint64_t wall_clock = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Wall clock: %"SCNu64"\n", wall_clock);
		offset += length;
		uint64_t metadata_size = imquic_varint_read(&object->payload[offset], object->payload_len-offset, &length);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Metadata:   %"SCNu64" bytes\n", metadata_size);
		offset += length;
		if(metadata_size > 0) {
			for(size_t i=0; i<metadata_size; ++i)
				IMQUIC_LOG(IMQUIC_LOG_INFO, "%02x", object->payload[offset+i]);
			IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
			offset += metadata_size;
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Payload:    %"SCNu64" bytes\n", object->payload_len-offset);
	} else if(object->request_id == 0 && media_type == DEMO_TYPE_MP4) {
		/* FIXME Ugly hack: if this is mp4, and our response to request ID 0, subscribe to another track */
		uint64_t request_id = 1;
		uint64_t track_alias = 1;
		const char *track_name = "1.m4s";
		imquic_moq_namespace tns[32];	/* FIXME */
		int i = 0;
		while(options.track_namespace[i] != NULL) {
			const char *track_namespace = options.track_namespace[i];
			tns[i].buffer = (uint8_t *)track_namespace;
			tns[i].length = strlen(track_namespace);
			tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
			i++;
		}
		char tns_buffer[256];
		const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to %s/%s (%s), using ID %"SCNu64"/%"SCNu64"\n",
			imquic_get_connection_name(conn), ns, track_name, imquic_demo_media_type_str(media_type), request_id, track_alias);
		imquic_moq_name tn = {
			.buffer = (uint8_t *)track_name,
			.length = strlen(track_name)
		};
		/* Check if we need to prepare an auth token */
		uint8_t auth[256];
		size_t authlen = 0;
		if(options.auth_info && strlen(options.auth_info) > 0)
			imquic_moq_auth_info_to_bytes(conn, options.auth_info, auth, &authlen);
		imquic_moq_subscribe(conn, request_id, track_alias, &tns[0], &tn,
			0, FALSE, TRUE, filter_type, &start_location, &end_location_sub, auth, authlen);
	}
	if(object->end_of_stream) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d)\n",
			imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
		if(object->delivery == IMQUIC_MOQ_USE_TRACK || (object->delivery == IMQUIC_MOQ_USE_FETCH && options.join_offset < 0)) {
			/* Last object received, stop here */
			g_atomic_int_inc(&stop);
		}
	}
}

static void imquic_demo_incoming_go_away(imquic_connection *conn, const char *uri) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got a GOAWAY: %s\n", imquic_get_connection_name(conn), uri);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
	if(conn == moq_conn)
		imquic_connection_unref(conn);
	moq_conn = NULL;
	/* Stop here */
	g_atomic_int_inc(&stop);
}

int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_demo_handle_signal);
	signal(SIGTERM, imquic_demo_handle_signal);

	IMQUIC_PRINT("imquic version %s\n", imquic_get_version_string_full());
	IMQUIC_PRINT("  -- %s (commit hash)\n", imquic_get_build_sha());
	IMQUIC_PRINT("  -- %s (build time)\n\n", imquic_get_build_time());

	/* Initialize some command line options defaults */
	options.debug_level = IMQUIC_LOG_INFO;
	options.join_offset = -1;
	options.end_group = IMQUIC_MAX_VARINT;
	options.end_object = IMQUIC_MAX_VARINT;
	/* Let's call our cmdline parser */
	if(!demo_options_parse(&options, argc, argv)) {
		demo_options_show_usage();
		demo_options_destroy();
		exit(1);
	}
	/* Logging level */
	imquic_set_log_level(options.debug_level);
	/* Debugging */
	if(options.debug_locks)
		imquic_set_lock_debugging(TRUE);
	if(options.debug_refcounts)
		imquic_set_refcount_debugging(TRUE);

	int ret = 0;
	if(options.remote_host == NULL || options.remote_port == 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid QUIC server address\n");
		ret = 1;
		goto done;
	}
	if(options.port > 65535) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid port\n");
		ret = 1;
		goto done;
	}
	if(!options.raw_quic && !options.webtransport) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "No raw QUIC or WebTransport enabled (enable at least one)\n");
		ret = 1;
		goto done;
	}
	if(options.ticket_file != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled (ticket file '%s')\n", options.ticket_file);
	if(options.moq_version != NULL) {
		if(!strcasecmp(options.moq_version, "any")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 11 and %d\n", IMQUIC_MOQ_VERSION_MAX - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY;
		} else if(!strcasecmp(options.moq_version, "legacy")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 6 and 10\n");
			moq_version = IMQUIC_MOQ_VERSION_ANY_LEGACY;
		} else {
			moq_version = IMQUIC_MOQ_VERSION_BASE + atoi(options.moq_version);
			if(moq_version < IMQUIC_MOQ_VERSION_MIN || moq_version > IMQUIC_MOQ_VERSION_MAX) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported MoQ version %s\n", options.moq_version);
				ret = 1;
				goto done;
			}
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ %d\n", moq_version - IMQUIC_MOQ_VERSION_BASE);
		}
	}
	if(options.subscribe_announces && options.fetch != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Can't enable SUBSCRIBE_ANNOUNCES and FETCH at the same time\n");
		ret = 1;
		goto done;
	}
	if(options.fetch) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using a %s FETCH for the subscription\n", (options.join_offset < 0 ? "Standalone" : "Joining"));
		if(options.join_offset >= 0)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Joining FETCH with a %d group offset\n", options.join_offset);
		if(strcasecmp(options.fetch, "ascending") && strcasecmp(options.fetch, "descending")) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid fetch ordering\n");
			ret = 1;
			goto done;
		}
	} else if(options.subscribe_announces) {
		if(moq_version == IMQUIC_MOQ_VERSION_ANY_LEGACY || (moq_version > IMQUIC_MOQ_VERSION_MIN && moq_version < IMQUIC_MOQ_VERSION_12)) {
			/* Version is too old, we can't: stop here */
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "PUBLISH only supported starting from version 12\n");
			ret = 1;
			goto done;
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using a SUBSCRIBE_ANNOUNCES and incoming PUBLISH for the subscription\n");
	} else {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using a SUBSCRIBE for the subscription\n");
	}
	if(options.track_namespace == NULL || options.track_namespace[0] == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track namespace (s)\n");
		ret = 1;
		goto done;
	}
	if(!options.subscribe_announces && (options.track_name == NULL || options.track_name[0] == NULL)) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track name(s)\n");
		ret = 1;
		goto done;
	}

	if(options.filter_type != NULL) {
		if(options.fetch != NULL && options.join_offset < 0) {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Ignoring filter type (unused for Standalone FETCH)\n");
		} else {
			if(!strcasecmp(options.filter_type, "LargestObject")) {
				filter_type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
			} else if(!strcasecmp(options.filter_type, "NextGroupStart")) {
				filter_type = IMQUIC_MOQ_FILTER_NEXT_GROUP_START;
			} else if(!strcasecmp(options.filter_type, "AbsoluteStart")) {
				filter_type = IMQUIC_MOQ_FILTER_ABSOLUTE_START;
			} else if(!strcasecmp(options.filter_type, "AbsoluteRange")) {
				filter_type = IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE;
			} else {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid filter '%s'\n", options.filter_type);
				ret = 1;
				goto done;
			}
		}
	}
	if(options.fetch != NULL && options.join_offset < 0) {
		start_location.group = options.start_group;
		start_location.object = options.start_object;
		end_location.group = options.end_group;
		end_location.object = (options.end_object == IMQUIC_MAX_VARINT) ? 0 : (options.end_object + 1);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "FETCH range: [%"SCNu64"/%"SCNu64"] --> [%"SCNu64"/%"SCNu64"]\n",
			start_location.group, start_location.object, end_location.group, end_location.object);
	} else if(!options.subscribe_announces) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Using '%s' as the SUBSCRIBE filter type\n", imquic_moq_filter_type_str(filter_type));
		if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START) {
			start_location.group = options.start_group;
			start_location.object = options.start_object;
			IMQUIC_LOG(IMQUIC_LOG_INFO, "SUBSCRIBE start location: [%"SCNu64"/%"SCNu64"]\n",
				start_location.group, start_location.object);
		} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
			start_location.group = options.start_group;
			start_location.object = options.start_object;
			end_location.group = options.end_group;
			end_location_sub.group = (options.end_group == IMQUIC_MAX_VARINT) ? 0 : (options.end_group + 1);
			IMQUIC_LOG(IMQUIC_LOG_INFO, "SUBSCRIBE start location: [%"SCNu64"/%"SCNu64"] --> End group [%"SCNu64"]\n",
				start_location.group, start_location.object, end_location.group);
		}
	}
	if(options.fetch == NULL && options.update_subscribe) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Will send a SUBSCRIBE_UPDATE to actually start streaming after %d seconds (note: ignored for versions earlier than 11)\n",
			options.update_subscribe);
	}

	if(options.media_type != NULL) {
		if(!strcasecmp(options.media_type, "none")) {
			media_type = DEMO_TYPE_NONE;
		} else if(!strcasecmp(options.media_type, "text")) {
			media_type = DEMO_TYPE_TEXT;
		} else if(!strcasecmp(options.media_type, "hex")) {
			media_type = DEMO_TYPE_HEX;
		} else if(!strcasecmp(options.media_type, "loc")) {
			media_type = DEMO_TYPE_LOC;
		} else if(!strcasecmp(options.media_type, "mp4")) {
			media_type = DEMO_TYPE_MP4;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_WARN, "Unsupported media type '%s', falling back to 'none'", options.media_type);
		}
	}
	if(options.target_file != NULL) {
		file = fopen(options.target_file, "wb");
		if(file == NULL) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Error creating file '%s': %s\n",
				options.target_file, g_strerror(errno));
			ret = 1;
			goto done;
		}
	}

	/* Check if we need to create a QLOG file, and which we should save */
	gboolean qlog_quic = FALSE, qlog_http3 = FALSE, qlog_moq = FALSE;
	if(options.qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating QLOG file '%s'\n", options.qlog_path);
		if(options.qlog_sequential)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Using sequential JSON\n");
		int i = 0;
		while(options.qlog_logging != NULL && options.qlog_logging[i] != NULL) {
			if(!strcasecmp(options.qlog_logging[i], "quic")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging QUIC events\n");
				qlog_quic = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "http3") && options.webtransport) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging HTTP/3 events\n");
				qlog_http3 = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "moq")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging MoQT events\n");
				qlog_moq = TRUE;
			}
			i++;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");

	/* Initialize the library and create a client */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *client = imquic_create_moq_client("moq-sub",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_REMOTE_HOST, options.remote_host,
		IMQUIC_CONFIG_REMOTE_PORT, options.remote_port,
		IMQUIC_CONFIG_SNI, options.sni,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, (options.ticket_file != NULL),
		IMQUIC_CONFIG_TICKET_FILE, options.ticket_file,
		IMQUIC_CONFIG_HTTP3_PATH, options.path,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_MOQ, qlog_moq,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", imquic_get_endpoint_alpn(client));
	if(options.webtransport && imquic_get_endpoint_subprotocol(client) != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Subprotocol: %s\n", imquic_get_endpoint_subprotocol(client));
	imquic_set_new_moq_connection_cb(client, imquic_demo_new_connection);
	imquic_set_moq_ready_cb(client, imquic_demo_ready);
	imquic_set_subscribe_accepted_cb(client, imquic_demo_subscribe_accepted);
	imquic_set_subscribe_error_cb(client, imquic_demo_subscribe_error);
	imquic_set_incoming_publish_cb(client, imquic_demo_incoming_publish);
	imquic_set_subscribe_done_cb(client, imquic_demo_subscribe_done);
	imquic_set_fetch_accepted_cb(client, imquic_demo_fetch_accepted);
	imquic_set_fetch_error_cb(client, imquic_demo_fetch_error);
	imquic_set_subscribe_announces_accepted_cb(client, imquic_demo_subscribe_announces_accepted);
	imquic_set_subscribe_announces_error_cb(client, imquic_demo_subscribe_announces_error);
	imquic_set_incoming_object_cb(client, imquic_demo_incoming_object);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_go_away);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	while(!stop) {
		if(update_time > 0 && g_get_monotonic_time() >= update_time) {
			/* Send a SUBSCRIBE_UPDATE with forward=true */
			update_time = 0;
			/* TODO This should be done for all subscriptions */
			GList *temp = request_ids;
			while(temp) {
				uint64_t *request_id = (uint64_t *)temp->data;
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Sending a SUBSCRIBE_UPDATE for ID %"SCNu64"\n",
					imquic_get_connection_name(moq_conn), *request_id);
				imquic_moq_location start_location = { 0 };
				imquic_moq_update_subscribe(moq_conn, *request_id, &start_location, end_location_sub.group, 0, TRUE);
				temp = temp->next;
			}
		}
		g_usleep(100000);
	}

	/* Shutdown the client */
	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();
	if(file != NULL)
		fclose(file);
	g_list_free_full(request_ids, (GDestroyNotify)g_free);

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
