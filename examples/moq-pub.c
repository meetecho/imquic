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
static uint64_t moq_subscribe_id = 0, moq_track_alias = 0;
static imquic_moq_delivery delivery = IMQUIC_MOQ_USE_SUBGROUP;
static volatile int send_objects = 0;
static uint64_t max_subscribe_id = 1;

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	moq_conn = conn;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
	imquic_moq_set_role(conn, IMQUIC_MOQ_PUBLISHER);
	imquic_moq_set_version(conn, moq_version);
	imquic_moq_set_max_subscribe_id(conn, max_subscribe_id);
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready (%s)\n",
		imquic_get_connection_name(conn), imquic_moq_version_str(imquic_moq_get_version(conn)));
	moq_version = imquic_moq_get_version(conn);
	g_atomic_int_set(&connected, 1);
	/* Let's announce our namespace */
	imquic_moq_namespace tns[5];	/* FIXME */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Announcing namespace ", imquic_get_connection_name(conn));
	int i = 0;
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		if(i > 0)
			IMQUIC_LOG(IMQUIC_LOG_INFO, "/");
		IMQUIC_LOG(IMQUIC_LOG_INFO, "'%s'", track_namespace);
		tns[i].buffer = (uint8_t *)track_namespace;
		tns[i].length = strlen(track_namespace);
		tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
		i++;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");
	imquic_moq_announce(conn, &tns[0]);
}

static void imquic_demo_announce_accepted(imquic_connection *conn, imquic_moq_namespace *tns) {
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Announce '%s' accepted\n",
		imquic_get_connection_name(conn), ns);
}

static void imquic_demo_announce_error(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason) {
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error announcing namespace '%s': error %d (%s)\n",
		imquic_get_connection_name(conn), ns, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth) {
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, track_alias);
	/* TODO Check if it matches our announced namespace */
	/* Check if there's authorization needed */
	char auth_info[256];
	auth_info[0] = '\0';
	if(auth && auth->buffer && auth->length > 0) {
		g_snprintf(auth_info, sizeof(auth_info), "%.*s", (int)auth->length, auth->buffer);
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %s\n",
			imquic_get_connection_name(conn), auth_info);
	}
	if(options.auth_info && strcmp(options.auth_info, auth_info)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Incorrect authorization info provided\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, subscribe_id, 403, "Unauthorized access", track_alias);
		if(moq_version >= IMQUIC_MOQ_VERSION_06)
			imquic_moq_set_max_subscribe_id(conn, ++max_subscribe_id);
		return;
	}
	/* Accept the subscription */
	moq_subscribe_id = subscribe_id;
	moq_track_alias = track_alias;
	imquic_moq_accept_subscribe(conn, subscribe_id, 0, FALSE);
	/* Start sending objects */
	g_atomic_int_set(&send_objects, 1);
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t subscribe_id) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), subscribe_id);
	/* TODO Stop sending objects */
	g_atomic_int_set(&send_objects, 0);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
	if(conn == moq_conn)
		imquic_connection_unref(conn);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_send_data(char *text, uint64_t group_id, uint64_t object_id, gboolean last) {
	uint8_t extensions[256];
	size_t extensions_len = 0;
	size_t extensions_count = 0;
	if(options.extensions) {
		/* Just for fun, we add a couple of fake extensions to the object: a numeric
		 * extension set to the length of the text, and a data extension with a string */
		GList *exts = NULL;
		imquic_moq_object_extension numext = { 0 };
		numext.id = 6;
		numext.value.number = text ? strlen(text) : 0;
		exts = g_list_append(exts, &numext);
		imquic_moq_object_extension dataext = { 0 };
		dataext.id = 7;
		dataext.value.data.buffer = (uint8_t *)"lminiero";
		dataext.value.data.length = strlen("lminiero");
		exts = g_list_append(exts, &dataext);
		extensions_len = imquic_moq_build_object_extensions(exts, extensions, sizeof(extensions));
		extensions_count = 2;
		g_list_free(exts);
	}
	/* Prepare the object and send it */
	imquic_moq_object object = {
		.subscribe_id = moq_subscribe_id,
		.track_alias = moq_track_alias,
		.group_id = group_id,
		.subgroup_id = 0,
		.object_id = object_id,
		.object_status = 0,
		.object_send_order = 0,
		.payload = (uint8_t *)text,
		.payload_len = strlen(text),
		.extensions = extensions,
		.extensions_len = extensions_len,
		.extensions_count = extensions_count,
		.delivery = delivery,
		.end_of_stream = (last && imquic_moq_get_version(moq_conn) == IMQUIC_MOQ_VERSION_03)
	};
	imquic_moq_send_object(moq_conn, &object);
	if(last && imquic_moq_get_version(moq_conn) > IMQUIC_MOQ_VERSION_03 &&
			(delivery == IMQUIC_MOQ_USE_GROUP || delivery == IMQUIC_MOQ_USE_SUBGROUP || delivery == IMQUIC_MOQ_USE_TRACK)) {
		/* Send an empty object with status "end of X" */
		object.object_id++;
		if(delivery == IMQUIC_MOQ_USE_GROUP)
			object.object_status = IMQUIC_MOQ_END_OF_GROUP;
		else if(delivery == IMQUIC_MOQ_USE_SUBGROUP)
			object.object_status = IMQUIC_MOQ_END_OF_SUBGROUP;
		else if(delivery == IMQUIC_MOQ_USE_TRACK)
			object.object_status = IMQUIC_MOQ_END_OF_TRACK_AND_GROUP;
		object.payload_len = 0;
		object.payload = NULL;
		object.extensions = NULL;
		object.extensions_len = 0;
		object.extensions_count = 0;
		object.end_of_stream = TRUE;
		imquic_moq_send_object(moq_conn, &object);
	}
}

int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_demo_handle_signal);
	signal(SIGTERM, imquic_demo_handle_signal);

	IMQUIC_PRINT("imquic version %s\n", imquic_get_version_string_full());
	IMQUIC_PRINT("  -- %s (commit hash)\n", imquic_get_build_sha());
	IMQUIC_PRINT("  -- %s (build time)\n", imquic_get_build_time());

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
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 6 and %d\n", IMQUIC_MOQ_VERSION_MAX - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY;
		} else if(!strcasecmp(options.moq_version, "legacy")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between %d and 5\n", IMQUIC_MOQ_VERSION_MIN - IMQUIC_MOQ_VERSION_BASE);
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
		} else if(!strcasecmp(options.delivery, "stream")) {
			delivery = IMQUIC_MOQ_USE_STREAM;
		} else if(!strcasecmp(options.delivery, "group")) {
			delivery = IMQUIC_MOQ_USE_GROUP;
		} else if(!strcasecmp(options.delivery, "subgroup")) {
			delivery = IMQUIC_MOQ_USE_SUBGROUP;
		} else if(!strcasecmp(options.delivery, "track")) {
			delivery = IMQUIC_MOQ_USE_TRACK;
		} else {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported delivery mode '%s'\n", options.delivery);
			ret = 1;
			goto done;
		}
	}

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
		IMQUIC_CONFIG_DONE, NULL);
	if(client == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", imquic_get_endpoint_alpn(client));
	if(options.webtransport && imquic_get_endpoint_subprotocol(client) != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Subprotocol: %s\n", imquic_get_endpoint_subprotocol(client));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "Delivery: %s\n", imquic_moq_delivery_str(delivery));
	imquic_set_new_moq_connection_cb(client, imquic_demo_new_connection);
	imquic_set_moq_ready_cb(client, imquic_demo_ready);
	imquic_set_announce_accepted_cb(client, imquic_demo_announce_accepted);
	imquic_set_announce_error_cb(client, imquic_demo_announce_error);
	imquic_set_incoming_subscribe_cb(client, imquic_demo_incoming_subscribe);
	imquic_set_incoming_unsubscribe_cb(client, imquic_demo_incoming_unsubscribe);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);
	imquic_start_endpoint(client);

	/* FIXME We publish like moq-rs's moq-clock */
	char buffer[50];
	struct tm imquictmresult;
	time_t imquicltime;
	int64_t now = g_get_monotonic_time(), before = now;
	GList *objects = NULL;
	uint64_t group_id = 0, object_id = 0;
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
				imquic_demo_send_data(buffer, group_id, object_id, FALSE);
			*seconds = '0';
		}
		/* Add to the group */
		if(objects == NULL) {
			*seconds = '\0';
			objects = g_list_append(objects, g_strdup(buffer));
			if(g_atomic_int_get(&send_objects) == 2)
				imquic_demo_send_data(buffer, group_id, object_id, last);
			*seconds = '0';
		} else {
			object_id++;
			objects = g_list_append(objects, g_strdup(seconds));
			if(g_atomic_int_get(&send_objects) == 2)
				imquic_demo_send_data(seconds, group_id, object_id, last);
		}
	}
	g_list_free_full(objects, (GDestroyNotify)g_free);
	/* We're done, unannounce */
	imquic_moq_namespace tns[5];	/* FIXME */
	int i = 0;
	while(options.track_namespace[i] != NULL) {
		const char *track_namespace = options.track_namespace[i];
		tns[i].buffer = (uint8_t *)track_namespace;
		tns[i].length = strlen(track_namespace);
		tns[i].next = (options.track_namespace[i+1] != NULL) ? &tns[i+1] : NULL;
		i++;
	}
	imquic_moq_unannounce(moq_conn, &tns[0]);
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
