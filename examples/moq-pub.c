/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ publisher
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-pub-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0, connected = 0;
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

/* Publisher state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static uint64_t moq_request_id = 0, moq_track_alias = 0;
static imquic_moq_delivery delivery = IMQUIC_MOQ_USE_SUBGROUP;
static char pub_tns_buffer[256];
static const char *pub_tns = NULL;
static uint8_t relay_auth[256];
static size_t relay_authlen = 0;

static volatile int started = 0, send_objects = 0, done_sent = 0;
static uint64_t max_request_id = 100;
static imquic_moq_location sub_start = { 0 }, sub_end = { 0 };
static uint64_t group_id = 0, object_id = 0;

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	moq_conn = conn;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection (configuring parameters)\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s (%s)\n", imquic_get_connection_name(conn),
		imquic_is_connection_webtransport(conn) ? "WebTransport" : "Raw QUIC",
		imquic_is_connection_webtransport(conn) ? imquic_get_connection_wt_protocol(conn) : imquic_get_connection_alpn(conn));
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
	const char *peer = imquic_moq_get_remote_implementation(conn);
	moq_version = imquic_moq_get_version(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		imquic_moq_version_str(moq_version));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		peer ? peer : "unknown implementation");
	g_atomic_int_set(&connected, 1);
	/* Let's publish our namespace or publish right away */
	imquic_moq_namespace tns[32];	/* FIXME */
	int i = 0;
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		tns[i].buffer = (uint8_t *)track_namespace;
		tns[i].length = strlen(track_namespace);
		tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
		i++;
	}
	pub_tns = imquic_moq_namespace_str(tns, pub_tns_buffer, sizeof(pub_tns_buffer), TRUE);
	if(!options.publish) {
		/* We use PUBLISH_NAMESPACE + incoming SUBSCRIBE */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Announcing namespace '%s'\n", imquic_get_connection_name(conn), pub_tns);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Will serve track '%s'\n", imquic_get_connection_name(conn), options.track_name);
		/* Check if we need to prepare an auth token */
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		if(options.auth_info && strlen(options.auth_info) > 0) {
			params.auth_token_set = TRUE;
			params.auth_token_len = sizeof(params.auth_token);
			if(imquic_moq_auth_info_to_bytes(conn, options.auth_info, params.auth_token, &params.auth_token_len) < 0) {
				params.auth_token_set = FALSE;
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error serializing the auth token\n",
					imquic_get_connection_name(conn));
			}
		}
		imquic_moq_publish_namespace(conn, imquic_moq_get_next_request_id(conn), &tns[0], &params);
	} else {
		/* We use PUBLISH */
		if(moq_version < IMQUIC_MOQ_VERSION_12) {
			/* Version is too old, we can't: stop here */
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "PUBLISH only supported starting from version 12\n");
			g_atomic_int_inc(&stop);
			return;
		}
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publishing namespace/track '%s'/'%s'\n", imquic_get_connection_name(conn), pub_tns, options.track_name);
		imquic_moq_name tn = {
			.buffer = (uint8_t *)options.track_name,
			.length = strlen(options.track_name)
		};
		moq_request_id = imquic_moq_get_next_request_id(conn);
		gboolean forward = FALSE;
		/* Check if we need to prepare an auth token */
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.group_order_set = TRUE;
		params.group_order_ascending = TRUE;
		params.forward_set = TRUE;
		params.forward = forward;
		if(options.auth_info && strlen(options.auth_info) > 0) {
			params.auth_token_set = TRUE;
			params.auth_token_len = sizeof(params.auth_token);
			if(imquic_moq_auth_info_to_bytes(conn, options.auth_info, params.auth_token, &params.auth_token_len) < 0) {
				params.auth_token_set = FALSE;
				IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Error serializing the auth token\n",
					imquic_get_connection_name(conn));
			}
		}
		imquic_moq_publish(conn, moq_request_id, &tns[0], &tn, moq_track_alias, &params);
	}
}

static void imquic_demo_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish Namespace '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
}

static void imquic_demo_publish_namespace_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error announcing namespace: error %d (%s)\n",
		imquic_get_connection_name(conn), error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_publish_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
	/* Start sending objects */
	sub_end.group = IMQUIC_MAX_VARINT;
	sub_end.object = IMQUIC_MAX_VARINT;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Starting delivery of objects: [%"SCNu64"/%"SCNu64"] --> [%"SCNu64"/%"SCNu64"]\n",
		imquic_get_connection_name(conn), sub_start.group, sub_start.object, sub_end.group, sub_end.object);
	g_atomic_int_set(&send_objects, 1);
}

static void imquic_demo_publish_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error publishing with ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12) {
		/* Older versions of MoQ expect the track alias in the SUBSCRIBE */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
			imquic_get_connection_name(conn), ns, name, request_id, track_alias);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64")\n",
			imquic_get_connection_name(conn), ns, name, request_id);
	}
	if(pub_tns == NULL || strcasecmp(ns, pub_tns) || strcasecmp(name, options.track_name)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Unknown namespace or track\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Unknown namespace or track", track_alias);
		return;
	}
	if(options.publish || g_atomic_int_get(&send_objects)) {
		/* FIXME In this demo, we only allow one subscriber at a time,
		 * as we expect a relay to mediate between us and subscribers */
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] We already have a subscriber\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_INTERNAL_ERROR, "We already have a subscriber", track_alias);
		return;
	}
	/* TODO Check if it matches our published namespace */
	/* Check if there's authorization needed */
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	/* TODO Check priority, filters, forwarding */
	if(!parameters->group_order_ascending) {
		/* We don't support descending mode yet */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Descending group order unsupported, will send objects in ascending group order\n",
			imquic_get_connection_name(conn));
	}
	/* Check the filter */
	uint64_t filter_type = parameters->subscription_filter_set ?
		parameters->subscription_filter.type : IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	gboolean pub_started = g_atomic_int_get(&started);
	sub_end.group = IMQUIC_MAX_VARINT;
	sub_end.object = IMQUIC_MAX_VARINT;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Requested filter type '%s'\n",
		imquic_get_connection_name(conn), imquic_moq_filter_type_str(filter_type));
	if(filter_type == IMQUIC_MOQ_FILTER_LARGEST_OBJECT) {
		sub_start.group = group_id;
		sub_start.object = object_id;
	} else if(filter_type == IMQUIC_MOQ_FILTER_NEXT_GROUP_START) {
		sub_start.group = group_id + 1;
		sub_start.object = 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START) {
		sub_start = parameters->subscription_filter.start_location;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"]\n",
			imquic_get_connection_name(conn), sub_start.group, sub_start.object);
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		sub_start = parameters->subscription_filter.start_location;
		if(parameters->subscription_filter.end_group == 0)
			sub_end.group = IMQUIC_MAX_VARINT;
		else
			sub_end.group = parameters->subscription_filter.end_group - 1;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"] --> End group [%"SCNu64"]\n",
			imquic_get_connection_name(conn), sub_start.group, sub_start.object, sub_end.group);
	}
	/* Accept the subscription */
	moq_request_id = request_id;
	if(moq_version < IMQUIC_MOQ_VERSION_12)
		moq_track_alias = track_alias;
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order_ascending = TRUE;
	if(pub_started) {
		rparams.largest_object_set = TRUE;
		rparams.largest_object = sub_start;
	}
	imquic_moq_accept_subscribe(conn, moq_request_id, moq_track_alias, &rparams);
	/* Start sending objects */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Starting delivery of objects: [%"SCNu64"/%"SCNu64"] --> [%"SCNu64"/%"SCNu64"]\n",
		imquic_get_connection_name(conn), sub_start.group, sub_start.object, sub_end.group, sub_end.object);
	g_atomic_int_set(&send_objects, 1);
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), request_id);
	/* Stop sending objects */
	g_atomic_int_set(&send_objects, 0);
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

static void imquic_demo_send_data(char *text, gboolean last) {
	uint8_t extensions[256];
	size_t extensions_len = 0;
	gboolean first = g_atomic_int_compare_and_exchange(&started, 0, 1);
	if((first && options.first_group > 0 && group_id == options.first_group) ||
			(first && options.first_object > 0 && object_id == options.first_object) ||
			options.extensions) {
		/* We have extensions to add to the object */
		GList *exts = NULL;
		imquic_moq_object_extension pgidext = { 0 };
		imquic_moq_object_extension poidext = { 0 };
		imquic_moq_object_extension numext = { 0 };
		imquic_moq_object_extension dataext = { 0 };
		if(first && options.first_group > 0 && group_id == options.first_group) {
			/* Add the Prior Group ID Gap extension */
			pgidext.id = IMQUIC_MOQ_EXT_PRIOR_GROUP_ID_GAP;
			pgidext.value.number = options.first_group;
			exts = g_list_append(exts, &pgidext);
		}
		if(first && options.first_object > 0 && object_id == options.first_object) {
			/* Add the Prior Object ID Gap extension */
			poidext.id = IMQUIC_MOQ_EXT_PRIOR_OBJECT_ID_GAP;
			poidext.value.number = options.first_object;
			exts = g_list_append(exts, &poidext);
		}
		if(options.extensions) {
			/* Just for fun, we add a couple of fake extensions to the object: a numeric
			 * extension set to the length of the text, and a data extension with a string */
			numext.id = 0x6;	/* FIXME */
			numext.value.number = strlen(text);
			exts = g_list_append(exts, &numext);
			dataext.id = 0x7;	/* FIXME */
			dataext.value.data.buffer = (uint8_t *)"lminiero";
			dataext.value.data.length = strlen("lminiero");
			exts = g_list_append(exts, &dataext);
		}
		extensions_len = imquic_moq_build_object_extensions(exts, extensions, sizeof(extensions));
		g_list_free(exts);
	}
	/* Check if it matches the filter */
	if(group_id < sub_start.group || (group_id == sub_start.group && object_id < sub_start.object)) {
		/* Not the time to send the object yet */
		return;
	}
	if(group_id > sub_end.group || (group_id == sub_end.group && object_id > sub_end.object)) {
		/* We've sent all that we were asked about */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Reached the end group, the subscription is done\n",
			imquic_get_connection_name(moq_conn));
		/* Send a PUBLISH_DONE */
		imquic_moq_publish_done(moq_conn, moq_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Reached the end group");
		g_atomic_int_set(&done_sent, 1);
		moq_request_id = 0;
		g_atomic_int_set(&send_objects, 0);
		return;
	} else if(group_id == sub_end.group && object_id == sub_end.object) {
		last = TRUE;
	}
	/* Prepare the object and send it */
	imquic_moq_object object = {
		.request_id = moq_request_id,
		.track_alias = moq_track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = 0,
		.payload = (uint8_t *)text,
		.payload_len = strlen(text),
		.extensions = extensions,
		.extensions_len = extensions_len,
		.delivery = delivery,
		.end_of_stream = FALSE
	};
	imquic_moq_send_object(moq_conn, &object);
	if(last && delivery == IMQUIC_MOQ_USE_SUBGROUP) {
		/* Send an empty object with status "end of X" */
		object.object_id++;
		object.object_status = IMQUIC_MOQ_END_OF_GROUP;
		object.payload_len = 0;
		object.payload = NULL;
		object.extensions = NULL;
		object.extensions_len = 0;
		object.end_of_stream = TRUE;
		imquic_moq_send_object(moq_conn, &object);
	}
	if(group_id == sub_end.group && object_id == sub_end.object) {
		/* We've sent the last object */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Reached the end group, the subscription is done\n",
			imquic_get_connection_name(moq_conn));
		/* Send a PUBLISH_DONE */
		imquic_moq_publish_done(moq_conn, moq_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Reached the end group");
		g_atomic_int_set(&done_sent, 1);
		moq_request_id = 0;
		g_atomic_int_set(&send_objects, 0);
	}
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
	if(options.track_namespace == NULL || options.track_namespace[0] == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track namespace(s)\n");
		ret = 1;
		goto done;
	}
	if(options.track_name == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing track name\n");
		ret = 1;
		goto done;
	}
	if(options.delivery != NULL) {
		if(!strcasecmp(options.delivery, "datagram")) {
			delivery = IMQUIC_MOQ_USE_DATAGRAM;
		} else if(!strcasecmp(options.delivery, "subgroup")) {
			delivery = IMQUIC_MOQ_USE_SUBGROUP;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported delivery mode '%s'\n", options.delivery);
			ret = 1;
			goto done;
		}
	}
	if(options.first_group > 0)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "First group: %"SCNu64" (will send the 'Prior Group ID Gap' extension)\n", options.first_group);
	if(options.first_object > 0)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "First object: %"SCNu64" (will send the 'Prior Object ID Gap' extension)\n", options.first_object);
	if(options.publish) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Will use PUBLISH instead of PUBLISH_NAMESPACE + SUBSCRIBE\n");
		if(moq_version > IMQUIC_MOQ_VERSION_MIN && moq_version < IMQUIC_MOQ_VERSION_12) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "PUBLISH only supported starting from version 12\n");
			ret = 1;
			goto done;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Will use track_alias=%"SCNu64", if a version higher or equal than 12 is negotiated\n",
		options.track_alias);
	moq_track_alias	= options.track_alias;

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
				if(options.qlog_stream)
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- -- Logging the payload of QUIC STREAM frames\n");
			} else if(!strcasecmp(options.qlog_logging[i], "http3") && options.webtransport) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging HTTP/3 events\n");
				qlog_http3 = TRUE;
			} else if(!strcasecmp(options.qlog_logging[i], "moq")) {
				IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Logging MoQT events\n");
				qlog_moq = TRUE;
				if(options.qlog_moq_messages)
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- -- Logging the payload of MoQT control messages\n");
				if(options.qlog_moq_objects)
					IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- -- Logging the payload of MoQT objects\n");
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
	imquic_server *client = imquic_create_moq_client("moq-pub",
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
		IMQUIC_CONFIG_QLOG_QUIC_STREAM, options.qlog_stream,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_MOQ, qlog_moq,
		IMQUIC_CONFIG_QLOG_MOQ_MESSAGES, options.qlog_moq_messages,
		IMQUIC_CONFIG_QLOG_MOQ_OBJECTS, options.qlog_moq_objects,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_MOQ_VERSION, moq_version,
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN(s):\n");
		int i = 0;
		const char **alpns = imquic_get_endpoint_alpns(client);
		while(alpns[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", alpns[i]);
			i++;
		}
	}
	if(options.webtransport && imquic_get_endpoint_wt_protocols(client) != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "WebTransport Protocol(s):\n");
		int i = 0;
		const char **wt_protocols = imquic_get_endpoint_wt_protocols(client);
		while(wt_protocols[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", wt_protocols[i]);
			i++;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Delivery: %s\n", imquic_moq_delivery_str(delivery));
	imquic_set_new_moq_connection_cb(client, imquic_demo_new_connection);
	imquic_set_moq_ready_cb(client, imquic_demo_ready);
	imquic_set_publish_namespace_accepted_cb(client, imquic_demo_publish_namespace_accepted);
	imquic_set_publish_namespace_error_cb(client, imquic_demo_publish_namespace_error);
	imquic_set_publish_accepted_cb(client, imquic_demo_publish_accepted);
	imquic_set_publish_error_cb(client, imquic_demo_publish_error);
	imquic_set_incoming_subscribe_cb(client, imquic_demo_incoming_subscribe);
	imquic_set_incoming_unsubscribe_cb(client, imquic_demo_incoming_unsubscribe);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_go_away);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	/* FIXME We publish like moq-rs's moq-clock */
	char buffer[50];
	struct tm imquictmresult;
	time_t imquicltime;
	int64_t now = g_get_monotonic_time(), before = now;
	GList *objects = NULL;
	group_id = options.first_group;
	object_id = options.first_object;
	char *seconds = NULL;
	gboolean last = FALSE;
	while(!stop) {
		if(!g_atomic_int_get(&connected)) {
			before = g_get_monotonic_time();
			g_usleep(100000);
			continue;
		}
		if(g_atomic_int_get(&send_objects) == 1) {
			/* Someone just subscribed */
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Starting to send MoQ objects\n");
			g_atomic_int_set(&send_objects, 2);
		}
		/* Update the time every second */
		now = g_get_monotonic_time();
		if(now-before < G_USEC_PER_SEC) {
			g_usleep(100000);
			continue;
		}
		before += G_USEC_PER_SEC;
		/* Generate the time string */
		imquicltime = time(NULL);
		localtime_r(&imquicltime, &imquictmresult);
		strftime(buffer, sizeof(buffer), "%Y-%m-%d %T", &imquictmresult);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", buffer);
		seconds = &buffer[strlen(buffer)-2];
		last = !strcasecmp(seconds, "59");
		if(!strcasecmp(seconds, "00")) {
			/* Minute wrap, reset the group */
			g_list_free_full(objects, (GDestroyNotify)g_free);
			objects = NULL;
			group_id++;
			object_id = 0;
			*seconds = '\0';
			objects = g_list_append(objects, g_strdup(buffer));
			if(g_atomic_int_get(&send_objects) == 2)
				imquic_demo_send_data(buffer, FALSE);
			*seconds = '0';
		}
		/* Add to the group */
		if(objects == NULL) {
			*seconds = '\0';
			objects = g_list_append(objects, g_strdup(buffer));
			if(g_atomic_int_get(&send_objects) == 2)
				imquic_demo_send_data(buffer, last);
			*seconds = '0';
		} else {
			object_id++;
			objects = g_list_append(objects, g_strdup(seconds));
			if(g_atomic_int_get(&send_objects) == 2)
				imquic_demo_send_data(seconds, last);
		}
	}
	g_list_free_full(objects, (GDestroyNotify)g_free);
	/* We're done, check if we need to send a PUBLISH_DONE and/or an PUBLISH_NAMESPACE_DONE */
	if(g_atomic_int_get(&started) && !g_atomic_int_get(&done_sent))
		imquic_moq_publish_done(moq_conn, moq_request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Publisher left");
	if(!options.publish) {
		imquic_moq_namespace tns[32];	/* FIXME */
		int i = 0;
		while(options.track_namespace[i] != NULL) {
			const char *track_namespace = options.track_namespace[i];
			tns[i].buffer = (uint8_t *)track_namespace;
			tns[i].length = strlen(track_namespace);
			tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
			i++;
		}
		imquic_moq_publish_namespace_done(moq_conn, &tns[0]);
	}
	/* Shutdown the client */
	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
