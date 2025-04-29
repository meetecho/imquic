/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ chat participant
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-chat-options.h"
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

/* Participant state */
static imquic_connection *moq_conn = NULL;
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static GHashTable *participants = NULL, *participants_byns = NULL;
static GMutex mutex;
static char *chat_timestamp = NULL;
static volatile int send_objects = 0;
static uint64_t moq_subscribe_id = 0, moq_track_alias = 0;
static uint64_t current_subscribe_id = 0, max_subscribe_id = 1;

/* Helper structs */
typedef struct imquic_demo_moq_participant {
	imquic_connection *conn;
	char *name;
	uint64_t subscribe_id;
	GMutex mutex;
} imquic_demo_moq_participant;
static imquic_demo_moq_participant *imquic_demo_moq_participant_create(imquic_connection *conn, const char *name, uint64_t subscribe_id);
static void imquic_demo_moq_participant_destroy(imquic_demo_moq_participant *p);

/* Constructors and destructors for helper structs */
static imquic_demo_moq_participant *imquic_demo_moq_participant_create(imquic_connection *conn, const char *name, uint64_t subscribe_id) {
	imquic_demo_moq_participant *p = g_malloc0(sizeof(imquic_demo_moq_participant));
	p->conn = conn;
	p->name = name ? g_strdup(name) : NULL;
	p->subscribe_id = subscribe_id;
	g_mutex_init(&p->mutex);
	return p;
}
static void imquic_demo_moq_participant_destroy(imquic_demo_moq_participant *p) {
	if(p) {
		g_free(p->name);
		g_free(p);
	}
}

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
	imquic_moq_set_role(conn, IMQUIC_MOQ_PUBSUB);
	imquic_moq_set_version(conn, moq_version);
	imquic_moq_set_max_subscribe_id(conn, max_subscribe_id);
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready (%s)\n",
		imquic_get_connection_name(conn), imquic_moq_version_str(imquic_moq_get_version(conn)));
	moq_conn = conn;
	moq_version = imquic_moq_get_version(conn);
	/* Let's subscribe to the chat prefix */
	imquic_moq_namespace tns[2];	/* FIXME */
	tns[0].buffer = (uint8_t *)"moq-chat";
	tns[0].length = strlen("moq-chat");
	tns[0].next = &tns[1];
	tns[1].buffer = (uint8_t *)options.id;
	tns[1].length = strlen(options.id);
	tns[1].next = NULL;
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	/* Send a SUBSCRIBE_ANNOUNCES */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to notifications for prefix '%s'\n",
		imquic_get_connection_name(conn), ns);
	imquic_moq_subscribe_announces(conn, &tns[0], options.auth_info);
}

static void imquic_demo_subscribe_announces_accepted(imquic_connection *conn, imquic_moq_namespace *tns) {
	/* Subscribing to participants joining/leaving succeeded */
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to notifications for prefix '%s' accepted\n",
		imquic_get_connection_name(conn), ns);
	/* Let's announce our own presence now */
	imquic_moq_namespace mytns[5];	/* FIXME */
	mytns[0].buffer = (uint8_t *)"moq-chat";
	mytns[0].length = strlen("moq-chat");
	mytns[0].next = &mytns[1];
	mytns[1].buffer = (uint8_t *)options.id;
	mytns[1].length = strlen(options.id);
	mytns[1].next = &mytns[2];
	mytns[2].buffer = (uint8_t *)options.user_id;
	mytns[2].length = strlen(options.user_id);
	mytns[2].next = &mytns[3];
	mytns[3].buffer = (uint8_t *)"imquic-moq-chat";
	mytns[3].length = strlen("imquic-moq-chat");
	mytns[3].next = &mytns[4];
	char timestamp[50];
	g_snprintf(timestamp, sizeof(timestamp), "%"SCNi64, g_get_real_time());
	chat_timestamp = g_strdup(timestamp);
	mytns[4].buffer = (uint8_t *)timestamp;
	mytns[4].length = strlen(timestamp);
	mytns[4].next = NULL;
	imquic_moq_announce(conn, &mytns[0]);
}

static void imquic_demo_subscribe_announces_error(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason) {
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to notifications for prefix '%s': error %d (%s)\n",
		imquic_get_connection_name(conn), ns, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_announce_accepted(imquic_connection *conn, imquic_moq_namespace *tns) {
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Announce '%s' accepted\n",
		imquic_get_connection_name(conn), ns);
	/* TODO Start sending chat messages */
}

static void imquic_demo_announce_error(imquic_connection *conn, imquic_moq_namespace *tns, int error_code, const char *reason) {
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error announcing namespace '%s': error %d (%s)\n",
		imquic_get_connection_name(conn), ns, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_announce(imquic_connection *conn, imquic_moq_namespace *tns) {
	/* We received an announce, which means a new participant has joined */
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New announced namespace: '%s'\n",
		imquic_get_connection_name(conn), ns);
	/* Subscribe to the new participant */
	g_mutex_lock(&mutex);
	uint64_t subscribe_id = current_subscribe_id;
	uint64_t track_alias = subscribe_id;	/* FIXME */
	current_subscribe_id++;
	const char *track_name = "chat";
	imquic_demo_moq_participant *p = imquic_demo_moq_participant_create(conn, track_name, subscribe_id);
	g_hash_table_insert(participants, imquic_uint64_dup(subscribe_id), p);
	g_hash_table_insert(participants_byns, g_strdup(ns), p);
	imquic_moq_name tn = {
		.buffer = (uint8_t *)track_name,
		.length = strlen(track_name)
	};
	g_mutex_unlock(&mutex);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscribing to '%s'/'%s', using ID %"SCNu64"/%"SCNu64"\n",
		imquic_get_connection_name(conn), ns, track_name, subscribe_id, track_alias);
	imquic_moq_subscribe(conn, subscribe_id, track_alias, tns, &tn, options.auth_info);
}

static void imquic_demo_incoming_unannounce(imquic_connection *conn, imquic_moq_namespace *tns) {
	/* We received an unannounce, which means an existing participant left */
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Namespace unannounced: '%s'\n",
		imquic_get_connection_name(conn), ns);
	/* Find the subscribe_id associated to that namespace, and unsubscribe */
	g_mutex_lock(&mutex);
	imquic_demo_moq_participant *p = g_hash_table_lookup(participants_byns, ns);
	if(p != NULL) {
		imquic_moq_unsubscribe(conn, p->subscribe_id);
		g_hash_table_remove(participants_byns, ns);
		g_hash_table_remove(participants, &p->subscribe_id);
	}
	g_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, const char *auth) {
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, track_alias);
	/* TODO Check if it matches our announced namespace */
	/* Check if there's authorization needed */
	if(auth != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %s\n",
			imquic_get_connection_name(conn), auth);
	}
	if(options.auth_info && (auth == NULL || strcmp(options.auth_info, auth))) {
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

static void imquic_demo_subscribe_accepted(imquic_connection *conn, uint64_t subscribe_id, uint64_t expires, gboolean descending) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription %"SCNu64" accepted (expires=%"SCNu64"; %s order)\n",
		imquic_get_connection_name(conn), subscribe_id, expires, descending ? "descending" : "ascending");
}

static void imquic_demo_subscribe_error(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason, uint64_t track_alias) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to ID %"SCNu64"/%"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), subscribe_id, track_alias, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_subscribe_done(imquic_connection *conn, uint64_t subscribe_id, int status_code, uint64_t streams_count, const char *reason) {
	/* Our subscription is done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription to ID %"SCNu64" is done: status %d (%s)\n",
		imquic_get_connection_name(conn), subscribe_id, status_code, reason);
	/* TODO */
}

static void imquic_demo_fetch_accepted(imquic_connection *conn, uint64_t subscribe_id, gboolean descending, imquic_moq_position *largest) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Fetch %"SCNu64" accepted (%s order; largest group/object %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), subscribe_id, descending ? "descending" : "ascending", largest->group, largest->object);
}

static void imquic_demo_fetch_error(imquic_connection *conn, uint64_t subscribe_id, int error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error fetching via ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), subscribe_id, error_code, reason);
	/* Stop here */
	g_atomic_int_inc(&stop);
}

static void imquic_demo_incoming_object(imquic_connection *conn, imquic_moq_object *object) {
	/* We received an object */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming object: sub=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64", id=%"SCNu64", order=%"SCNu64", payload=%zu bytes, extensions=%zu bytes, delivery=%s, status=%s, eos=%d\n",
		imquic_get_connection_name(conn), object->subscribe_id, object->track_alias,
		object->group_id, object->subgroup_id, object->object_id, object->object_send_order,
		object->payload_len, object->extensions_len, imquic_moq_delivery_str(object->delivery),
		imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	if(object->payload == NULL || object->payload_len == 0) {
		if(object->end_of_stream) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d on empty packet)\n",
				imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
			if(object->delivery == IMQUIC_MOQ_USE_TRACK || object->delivery == IMQUIC_MOQ_USE_FETCH) {
				/* Stop here */
				g_atomic_int_inc(&stop);
			}
		}
		return;
	}
	/* TODO Handle chat message */
	if(object->end_of_stream) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stream closed (status '%s' and eos=%d)\n",
			imquic_get_connection_name(conn), imquic_moq_object_status_str(object->object_status), object->end_of_stream);
		if(object->delivery == IMQUIC_MOQ_USE_TRACK || object->delivery == IMQUIC_MOQ_USE_FETCH) {
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
	/* Stop here */
	g_atomic_int_inc(&stop);
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
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 11 and %d\n", IMQUIC_MOQ_VERSION_MAX - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY;
		} else if(!strcasecmp(options.moq_version, "legacy")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 6 and 10\n");
			moq_version = IMQUIC_MOQ_VERSION_ANY_LEGACY;
		} else if(!strcasecmp(options.moq_version, "ancient")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between %d and 5\n", IMQUIC_MOQ_VERSION_MIN - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY_ANCIENT;
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
	//~ if(options.fetch != NULL && strcasecmp(options.fetch, "ascending") && strcasecmp(options.fetch, "descending")) {
		//~ IMQUIC_LOG(IMQUIC_LOG_FATAL, "Invalid fetch ordering\n");
		//~ ret = 1;
		//~ goto done;
	//~ }
	if(options.id == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing chat ID\n");
		ret = 1;
		goto done;
	}
	if(options.user_id == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing participant ID\n");
		ret = 1;
		goto done;
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

	/* Initialize the library and create a client */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *client = imquic_create_moq_client("moq-chat",
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
	imquic_set_subscribe_announces_accepted_cb(client, imquic_demo_subscribe_announces_accepted);
	imquic_set_subscribe_announces_error_cb(client, imquic_demo_subscribe_announces_error);
	imquic_set_announce_accepted_cb(client, imquic_demo_announce_accepted);
	imquic_set_announce_error_cb(client, imquic_demo_announce_error);
	imquic_set_incoming_announce_cb(client, imquic_demo_incoming_announce);
	imquic_set_incoming_unannounce_cb(client, imquic_demo_incoming_unannounce);
	imquic_set_incoming_subscribe_cb(client, imquic_demo_incoming_subscribe);
	imquic_set_incoming_unsubscribe_cb(client, imquic_demo_incoming_unsubscribe);
	imquic_set_subscribe_accepted_cb(client, imquic_demo_subscribe_accepted);
	imquic_set_subscribe_error_cb(client, imquic_demo_subscribe_error);
	imquic_set_subscribe_done_cb(client, imquic_demo_subscribe_done);
	imquic_set_fetch_accepted_cb(client, imquic_demo_fetch_accepted);
	imquic_set_fetch_error_cb(client, imquic_demo_fetch_error);
	imquic_set_incoming_object_cb(client, imquic_demo_incoming_object);
	imquic_set_incoming_goaway_cb(client, imquic_demo_incoming_go_away);
	imquic_set_moq_connection_gone_cb(client, imquic_demo_connection_gone);

	/* Initialize the resources we'll need */
	participants = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_demo_moq_participant_destroy);
	participants_byns = g_hash_table_new_full(NULL, NULL, NULL, NULL);

	/* Start the client */
	imquic_start_endpoint(client);

	while(!stop)
		g_usleep(100000);

	/* We're done, interrupt the notifications for the chat prefix */
	imquic_moq_namespace tns[2];	/* FIXME */
	tns[0].buffer = (uint8_t *)"moq-chat";
	tns[0].length = strlen("moq-chat");
	tns[0].next = &tns[1];
	tns[1].buffer = (uint8_t *)options.id;
	tns[1].length = strlen(options.id);
	tns[1].next = NULL;
	imquic_moq_unsubscribe_announces(moq_conn, &tns[0]);
	/* Let's also unannounce our own presence, if we announced it before */
	if(chat_timestamp != NULL) {
		imquic_moq_namespace mytns[5];	/* FIXME */
		mytns[0].buffer = (uint8_t *)"moq-chat";
		mytns[0].length = strlen("moq-chat");
		mytns[0].next = &mytns[1];
		mytns[1].buffer = (uint8_t *)options.id;
		mytns[1].length = strlen(options.id);
		mytns[1].next = &mytns[2];
		mytns[2].buffer = (uint8_t *)options.user_id;
		mytns[2].length = strlen(options.user_id);
		mytns[2].next = &mytns[3];
		mytns[3].buffer = (uint8_t *)"imquic-moq-chat";
		mytns[3].length = strlen("imquic-moq-chat");
		mytns[3].next = &mytns[4];
		mytns[4].buffer = (uint8_t *)chat_timestamp;
		mytns[4].length = strlen(chat_timestamp);
		mytns[4].next = NULL;
		imquic_moq_unannounce(moq_conn, &mytns[0]);
		g_free(chat_timestamp);
	}

	/* Shutdown the client */
	imquic_shutdown_endpoint(client);

done:
	imquic_deinit();
	if(participants != NULL)
		g_hash_table_unref(participants);
	if(participants_byns != NULL)
		g_hash_table_unref(participants_byns);
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
