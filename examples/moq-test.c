/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ test
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-test-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping test, please wait...\n");
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

/* Relay state */
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;

/* Namespace tuple fields */
typedef enum imquic_demo_tuple_field {
	TUPLE_FIELD_PROTOCOL = 0,
	TUPLE_FIELD_FORWARDING,
	TUPLE_FIELD_START_GROUP,
	TUPLE_FIELD_START_OBJECT,
	TUPLE_FIELD_LAST_GROUP,
	TUPLE_FIELD_LAST_OBJECT,
	TUPLE_FIELD_OBJxGROUP,
	TUPLE_FIELD_OBJ0_SIZE,
	TUPLE_FIELD_OBJS_SIZE,
	TUPLE_FIELD_OBJS_FREQ,
	TUPLE_FIELD_GROUP_INC,
	TUPLE_FIELD_OBJ_INC,
	TUPLE_FIELD_SEND_EOG,
	TUPLE_FIELD_EXT_INT,
	TUPLE_FIELD_EXT_VAR,
	TUPLE_FIELD_TIMEOUT
} imquic_demo_tuple_field;
#define IMQUIC_DEMO_TEST_NAME	"moq-test-00"
#define IMQUIC_DEMO_TEST_MAX		16
static const char *imquic_demo_tuple_field_str(imquic_demo_tuple_field field) {
	switch(field) {
		case TUPLE_FIELD_PROTOCOL:
			return "moq-test protocol";
		case TUPLE_FIELD_FORWARDING:
			return "Forwarding Preference";
		case TUPLE_FIELD_START_GROUP:
			return "Start Group";
		case TUPLE_FIELD_START_OBJECT:
			return "Start Object";
		case TUPLE_FIELD_LAST_GROUP:
			return "Last Group in Track";
		case TUPLE_FIELD_LAST_OBJECT:
			return "Last Object in Track";
		case TUPLE_FIELD_OBJxGROUP:
			return "Objects per Group";
		case TUPLE_FIELD_OBJ0_SIZE:
			return "Size of Object 0";
		case TUPLE_FIELD_OBJS_SIZE:
			return "Size of Objects > 0";
		case TUPLE_FIELD_OBJS_FREQ:
			return "Object Frequency";
		case TUPLE_FIELD_GROUP_INC:
			return "Group Increment";
		case TUPLE_FIELD_OBJ_INC:
			return "Object Increment";
		case TUPLE_FIELD_SEND_EOG:
			return "Send End of Group Markers";
		case TUPLE_FIELD_EXT_INT:
			return "Test Integer Extension";
		case TUPLE_FIELD_EXT_VAR:
			return "Test Variable Extension";
		case TUPLE_FIELD_TIMEOUT:
			return "Publisher Delivery Timeout";
		default:
			break;
	}
	return NULL;
};
static int64_t default_test[IMQUIC_DEMO_TEST_MAX];

/* Helper structs */

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection\n", imquic_get_connection_name(conn));
	imquic_moq_set_role(conn, IMQUIC_MOQ_PUBLISHER);
	imquic_moq_set_version(conn, moq_version);
	imquic_moq_set_max_subscribe_id(conn, 1000);	/* FIXME */
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready (%s)\n",
		imquic_get_connection_name(conn), imquic_moq_version_str(imquic_moq_get_version(conn)));
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_auth_info *auth) {
	/* We received a subscribe */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, track_alias);
	if(auth && auth->buffer && auth->length > 0) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %.*s\n",
			imquic_get_connection_name(conn), (int)auth->length, auth->buffer);
	}
	/* TODO Evaluate the namespace tuple and create a test */
	ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), FALSE);
	if(strcasecmp(ns, IMQUIC_DEMO_TEST_NAME)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid test protocol '%s' in tuple field 0 (should be '%s')\n",
			imquic_get_connection_name(conn), ns, IMQUIC_DEMO_TEST_NAME);
		imquic_moq_reject_subscribe(conn, subscribe_id, 400, "Invalid tuple field 0", track_alias);
		return;
	}
	int64_t test[IMQUIC_DEMO_TEST_MAX];
	memcpy(test, default_test, sizeof(default_test));
	uint8_t count = 0;
	gboolean invalid = FALSE;
	imquic_moq_namespace *temp = tns;
	while(temp) {
		if(count >= IMQUIC_DEMO_TEST_MAX) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid namespace tuple, too many fields (> %d)\n",
				imquic_get_connection_name(conn), IMQUIC_DEMO_TEST_MAX);
			imquic_moq_reject_subscribe(conn, subscribe_id, 400, "Too many tuple fields", track_alias);
			return;
		}
		if(count > 0) {
			ns = imquic_moq_namespace_str(temp, tns_buffer, sizeof(tns_buffer), FALSE);
			if(ns != NULL) {
				/* A value was provided, evaluate it */
				test[count] = strtoll(ns, 0, 10);
				switch(count) {
					case TUPLE_FIELD_FORWARDING:
						if(test[count] < 0 || test[count] > 3)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_START_GROUP:
					case TUPLE_FIELD_START_OBJECT:
					case TUPLE_FIELD_LAST_GROUP:
					case TUPLE_FIELD_LAST_OBJECT:
					case TUPLE_FIELD_OBJxGROUP:
					case TUPLE_FIELD_OBJ0_SIZE:
					case TUPLE_FIELD_OBJS_SIZE:
					case TUPLE_FIELD_OBJS_FREQ:
					case TUPLE_FIELD_GROUP_INC:
					case TUPLE_FIELD_OBJ_INC:
					case TUPLE_FIELD_TIMEOUT:
						if(test[count] < 0)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_SEND_EOG:
						if(test[count] < 0 || test[count] > 1)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_EXT_INT:
					case TUPLE_FIELD_EXT_VAR:
					case TUPLE_FIELD_PROTOCOL:
					default:
						break;
				}
				if(invalid) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid tuple field '%s', out of range\n",
						imquic_get_connection_name(conn), imquic_demo_tuple_field_str(count));
					imquic_moq_reject_subscribe(conn, subscribe_id, 400, "Invalud tuple field", track_alias);
					return;
				}
			}
		}
		count++;
		temp = temp->next;
	}
	if(test[TUPLE_FIELD_LAST_OBJECT] == -1)
		test[TUPLE_FIELD_LAST_OBJECT] = test[TUPLE_FIELD_OBJxGROUP];
	/* Summarize the test */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Requested test:\n", imquic_get_connection_name(conn));
	uint8_t i = 0;
	for(i=1; i<IMQUIC_DEMO_TEST_MAX; i++) {
		if(test[i] >= 0) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- #%d (%s) = %"SCNi64"\n",
				i, imquic_demo_tuple_field_str(i), test[i]);
		} else {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- #%d (%s) = (don't add)\n",
				i, imquic_demo_tuple_field_str(i));
		}
	}
	/* TODO Accept and serve the test subscription */
	imquic_moq_accept_subscribe(conn, subscribe_id, 0, FALSE);
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t subscribe_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), subscribe_id);
}

static void imquic_demo_incoming_standalone_fetch(imquic_connection *conn, uint64_t subscribe_id, imquic_moq_namespace *tns, imquic_moq_name *tn,
		gboolean descending, imquic_moq_fetch_range *range, imquic_moq_auth_info *auth) {
	/* We received a standalone fetch */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming standalone fetch for '%s'/'%s' (ID %"SCNu64"; %s order; group/object range %"SCNu64"/%"SCNu64"-->%"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, descending ? "descending" : "ascending",
		range->start.group, range->start.object, range->end.group, range->end.object);
	if(auth && auth->buffer && auth->length > 0) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %.*s\n",
			imquic_get_connection_name(conn), (int)auth->length, auth->buffer);
	}
	/* TODO Evaluate the namespace tuple and create a test */
}

static void imquic_demo_incoming_joining_fetch(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id ,
		uint64_t preceding_group_offset, gboolean descending, imquic_moq_auth_info *auth) {
	/* We received a joining fetch */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming joining fetch for subscription %"SCNu64" (ID %"SCNu64"; %"SCNu64" groups; %s order)\n",
		imquic_get_connection_name(conn), joining_subscribe_id, subscribe_id, preceding_group_offset, descending ? "descending" : "ascending");
	if(auth && auth->buffer && auth->length > 0) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %.*s\n",
			imquic_get_connection_name(conn), (int)auth->length, auth->buffer);
	}
	/* TODO Evaluate the namespace tuple and create a test */
}

static void imquic_demo_incoming_fetch_cancel(imquic_connection *conn, uint64_t subscribe_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming fetch cancel for subscription %"SCNu64"\n", imquic_get_connection_name(conn), subscribe_id);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
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
	if(options.cert_pem == NULL || strlen(options.cert_pem) == 0 || options.cert_key == NULL || strlen(options.cert_key) == 0) {
		IMQUIC_LOG(IMQUIC_LOG_FATAL, "Missing certificate/key\n");
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
	if(options.early_data)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Early data support enabled\n");

	if(options.moq_version != NULL) {
		if(!strcasecmp(options.moq_version, "any")) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ between 6 and %d\n", IMQUIC_MOQ_VERSION_MAX - IMQUIC_MOQ_VERSION_BASE);
			moq_version = IMQUIC_MOQ_VERSION_ANY;
		} else if(!strcasecmp(options.moq_version, "legacy")) {
			IMQUIC_LOG(IMQUIC_LOG_FATAL, "Versions lower than 6 don't support namespace tuples\n");
			ret = 1;
			goto done;
		} else {
			moq_version = IMQUIC_MOQ_VERSION_BASE + atoi(options.moq_version);
			if(moq_version < IMQUIC_MOQ_VERSION_MIN || moq_version > IMQUIC_MOQ_VERSION_MAX) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Unsupported MoQ version %s\n", options.moq_version);
				ret = 1;
				goto done;
			} else if(moq_version < IMQUIC_MOQ_VERSION_06) {
				IMQUIC_LOG(IMQUIC_LOG_FATAL, "Versions lower than 6 don't support namespace tuples\n");
				ret = 1;
				goto done;
			}
			IMQUIC_LOG(IMQUIC_LOG_INFO, "Negotiating version of MoQ %d\n", moq_version - IMQUIC_MOQ_VERSION_BASE);
		}
	}

	/* Initialize the library and create a server */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *server = imquic_create_moq_server("moq-test",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, options.early_data,
		IMQUIC_CONFIG_DONE, NULL);
	if(server == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN: %s\n", imquic_get_endpoint_alpn(server));
	if(options.webtransport && imquic_get_endpoint_subprotocol(server) != NULL)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Subprotocol: %s\n", imquic_get_endpoint_subprotocol(server));
	imquic_set_new_moq_connection_cb(server, imquic_demo_new_connection);
	imquic_set_moq_ready_cb(server, imquic_demo_ready);
	imquic_set_incoming_subscribe_cb(server, imquic_demo_incoming_subscribe);
	imquic_set_incoming_unsubscribe_cb(server, imquic_demo_incoming_unsubscribe);
	imquic_set_incoming_standalone_fetch_cb(server, imquic_demo_incoming_standalone_fetch);
	imquic_set_incoming_joining_fetch_cb(server, imquic_demo_incoming_joining_fetch);
	imquic_set_incoming_fetch_cancel_cb(server, imquic_demo_incoming_fetch_cancel);
	imquic_set_moq_connection_gone_cb(server, imquic_demo_connection_gone);

	/* Initialize test defaults */
	default_test[TUPLE_FIELD_PROTOCOL] = 0;	/* Ignored, this will need to be "moq-test-0" */
	default_test[TUPLE_FIELD_FORWARDING] = 0;
	default_test[TUPLE_FIELD_START_GROUP] = 0;
	default_test[TUPLE_FIELD_START_OBJECT] = 0;
	default_test[TUPLE_FIELD_LAST_GROUP] = (1L << 62) -1;
	default_test[TUPLE_FIELD_LAST_OBJECT] = -1;
	default_test[TUPLE_FIELD_OBJxGROUP] = 10;
	default_test[TUPLE_FIELD_OBJ0_SIZE] = 1024;
	default_test[TUPLE_FIELD_OBJS_SIZE] = 100;
	default_test[TUPLE_FIELD_OBJS_FREQ] = 1000;
	default_test[TUPLE_FIELD_GROUP_INC] = 1;
	default_test[TUPLE_FIELD_OBJ_INC] = 1;
	default_test[TUPLE_FIELD_SEND_EOG] = 0;
	default_test[TUPLE_FIELD_EXT_INT] = -1;	/* Don't add extension */
	default_test[TUPLE_FIELD_EXT_VAR] = -1;	/* Don't add extension */
	default_test[TUPLE_FIELD_TIMEOUT] = 0;

	/* Start the server */
	imquic_start_endpoint(server);

	while(!stop) {
		/* TODO */
		g_usleep(100000);
	}

	imquic_shutdown_endpoint(server);

done:
	imquic_deinit();
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
