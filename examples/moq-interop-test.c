/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * imquic-based MoQ test client for moq-interop-runner, see
 * https://github.com/englishm/moq-interop-runner/ for details
 *
 */

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-interop-test-options.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0, running = 0;
static void imquic_moq_interop_handle_signal(int signum) {
	g_atomic_int_inc(&stop);
	if(g_atomic_int_get(&stop) > 2)
		exit(1);
}

/* Defaults */
static const char *relay = "https://localhost:4443";
static gboolean no_verify = FALSE, verbose = FALSE;

/* Supported tests */
typedef enum imquic_moq_interop_test {
	IMQUIC_INTEROP_UNKNOWN = 0,
	IMQUIC_INTEROP_SETUP_ONLY,
	IMQUIC_INTEROP_ANNOUNCE_ONLY,
	IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE,
	IMQUIC_INTEROP_SUBSCRIBE_ERROR,
	IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE,
	IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE,
} imquic_moq_interop_test;
static imquic_moq_interop_test imquic_moq_interop_test_parse(const char *name) {
	if(name == NULL)
		return IMQUIC_INTEROP_UNKNOWN;
	if(!strcasecmp(name, "setup-only"))
		return IMQUIC_INTEROP_SETUP_ONLY;
	else if(!strcasecmp(name, "announce-only"))
		return IMQUIC_INTEROP_ANNOUNCE_ONLY;
	else if(!strcasecmp(name, "publish-namespace-done"))
		return IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE;
	else if(!strcasecmp(name, "subscribe-error"))
		return IMQUIC_INTEROP_SUBSCRIBE_ERROR;
	else if(!strcasecmp(name, "announce-subscribe"))
		return IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE;
	else if(!strcasecmp(name, "subscribe-before-announce"))
		return IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE;
	return IMQUIC_INTEROP_UNKNOWN;
}
static const char *imquic_moq_interop_test_str(imquic_moq_interop_test test) {
	switch(test) {
		case IMQUIC_INTEROP_SETUP_ONLY:
			return "setup-only";
		case IMQUIC_INTEROP_ANNOUNCE_ONLY:
			return "announce-only";
		case IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE:
			return "publish-namespace-done";
		case IMQUIC_INTEROP_SUBSCRIBE_ERROR:
			return "subscribe-error";
		case IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE:
			return "announce-subscribe";
		case IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE:
			return "subscribe-before-announce";
		default:
			break;
	}
	return NULL;
}

/* Test client structure */
typedef struct imquic_moq_interop_client {
	void *test;
	imquic_client *client;
	imquic_connection *conn;
	gboolean publisher;
} imquic_moq_interop_client;
static void imquic_moq_interop_client_destroy(imquic_moq_interop_client *mc) {
	if(mc != NULL) {
		imquic_shutdown_endpoint(mc->client);
		g_free(mc);
	}
}

/* Test context */
typedef struct imquic_moq_interop_test_context {
	imquic_moq_interop_test name;
	gboolean need_publisher, need_subscriber;
	gboolean subscriber_first;
	imquic_moq_interop_client *publisher, *subscriber;
	int64_t timeout;
	volatile int done, success;
	char *pub_connection_id, *sub_connection_id,
		*expected, *received, *message;
	GList *subtests;
} imquic_moq_interop_test_context;
static void imquic_moq_interop_test_context_cleanup(imquic_moq_interop_test_context *test) {
	if(test != NULL) {
		imquic_moq_interop_client_destroy(test->publisher);
		imquic_moq_interop_client_destroy(test->subscriber);
		g_free(test->pub_connection_id);
		g_free(test->sub_connection_id);
		g_free(test->expected);
		g_free(test->received);
		g_free(test->message);
		g_list_free_full(test->subtests, (GDestroyNotify)g_free);
	}
}

/* Tester state */
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static gboolean webtransport = FALSE;
static char *host = NULL, *path = NULL;
static uint16_t port = 0;
static uint64_t max_request_id = 100;
static GList *all_tests = NULL, *tests = NULL;
static imquic_moq_interop_test_context *current_test = NULL;

/* Runners */
static int imquic_moq_interop_perform_test(imquic_moq_interop_test_context *test, int test_num);
static imquic_moq_interop_client *imquic_moq_interop_client_create(imquic_moq_interop_test_context *test, gboolean publisher);

/* Callbacks */
static void imquic_moq_interop_new_connection(imquic_connection *conn, void *user_data);
static void imquic_moq_interop_ready(imquic_connection *conn);
static void imquic_moq_interop_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id,
	imquic_moq_request_parameters *parameters);
static void imquic_moq_interop_publish_namespace_error(imquic_connection *conn, uint64_t request_id,
	imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval);
static void imquic_moq_interop_incoming_subscribe(imquic_connection *conn, uint64_t request_id,
	uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters);
static void imquic_moq_interop_subscribe_accepted(imquic_connection *conn, uint64_t request_id,
	uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_extensions);
static void imquic_moq_interop_subscribe_error(imquic_connection *conn, uint64_t request_id,
	imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias, uint64_t retry_interval);
static void imquic_moq_interop_connection_gone(imquic_connection *conn);

/* Main */
int main(int argc, char *argv[]) {
	/* Handle SIGINT (CTRL-C), SIGTERM (from service managers) */
	signal(SIGINT, imquic_moq_interop_handle_signal);
	signal(SIGTERM, imquic_moq_interop_handle_signal);

	/* Let's call our cmdline parser */
	if(!demo_options_parse(&options, argc, argv)) {
		demo_options_show_usage();
		demo_options_destroy();
		exit(1);
	}
	/* We need to only output TAP 14, so disable all imquic logging */
	imquic_set_log_level(IMQUIC_LOG_NONE);

	/* Prepare a list of all supported tests */
	imquic_moq_interop_test_context setup_only = { 0 };
	setup_only.name = IMQUIC_INTEROP_SETUP_ONLY;
	setup_only.need_publisher = TRUE;
	setup_only.timeout = 2*G_USEC_PER_SEC;
	all_tests = g_list_append(all_tests, &setup_only);
	imquic_moq_interop_test_context announce_only = { 0 };
	announce_only.name = IMQUIC_INTEROP_ANNOUNCE_ONLY;
	announce_only.need_publisher = TRUE;
	announce_only.timeout = 2*G_USEC_PER_SEC;
	all_tests = g_list_append(all_tests, &announce_only);
	imquic_moq_interop_test_context publish_namespace_done = { 0 };
	publish_namespace_done.name = IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE;
	publish_namespace_done.need_publisher = TRUE;
	publish_namespace_done.timeout = 2*G_USEC_PER_SEC;
	all_tests = g_list_append(all_tests, &publish_namespace_done);
	imquic_moq_interop_test_context subscribe_error = { 0 };
	subscribe_error.name = IMQUIC_INTEROP_SUBSCRIBE_ERROR;
	subscribe_error.need_subscriber = TRUE;
	subscribe_error.timeout = 2*G_USEC_PER_SEC;
	all_tests = g_list_append(all_tests, &subscribe_error);
	imquic_moq_interop_test_context announce_subscribe = { 0 };
	announce_subscribe.name = IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE;
	announce_subscribe.need_publisher = TRUE;
	announce_subscribe.need_subscriber = TRUE;
	announce_subscribe.timeout = 3*G_USEC_PER_SEC;
	all_tests = g_list_append(all_tests, &announce_subscribe);
	imquic_moq_interop_test_context subscribe_before_announce = { 0 };
	subscribe_before_announce.name = IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE;
	subscribe_before_announce.need_publisher = TRUE;
	subscribe_before_announce.need_subscriber = TRUE;
	subscribe_before_announce.subscriber_first = TRUE;
	subscribe_before_announce.timeout = 3*G_USEC_PER_SEC + (G_USEC_PER_SEC/2);
	all_tests = g_list_append(all_tests, &subscribe_before_announce);

	/* Only print the list, if that's what's asked of us */
	int ret = 0;
	if(options.list) {
		GList *temp = all_tests;
		while(temp) {
			imquic_moq_interop_test_context *test_ctx = (imquic_moq_interop_test_context *)temp->data;
			g_print("%s\n", imquic_moq_interop_test_str(test_ctx->name));
			temp = temp->next;
		}
		goto done;
	}

	/* Check env variables */
	if(g_getenv("RELAY_URL") != NULL)
		relay = g_getenv("RELAY_URL");
	if(g_getenv("TESTCASE") != NULL) {
		imquic_moq_interop_test name = imquic_moq_interop_test_parse(g_getenv("TESTCASE"));
		imquic_moq_interop_test_context *test_ctx = NULL;
		GList *temp = all_tests;
		while(temp) {
			test_ctx = (imquic_moq_interop_test_context *)temp->data;
			if(test_ctx->name == name)
				break;
			test_ctx = NULL;
			temp = temp->next;
		}

		if(test_ctx == NULL) {
			/* Unsupported test */
			ret = 127;
			goto done;
		}
		tests = g_list_append(tests, test_ctx);
	}
	if(g_getenv("VERBOSE") != NULL)
		verbose = TRUE;
	if(g_getenv("TLS_DISABLE_VERIFY") != NULL)
		no_verify = TRUE;
	/* Check command line arguments */
	if(options.relay != NULL)
		relay = options.relay;
	if(options.test != NULL) {
		imquic_moq_interop_test name = imquic_moq_interop_test_parse(options.test);
		imquic_moq_interop_test_context *test_ctx = NULL;
		GList *temp = all_tests;
		while(temp) {
			test_ctx = (imquic_moq_interop_test_context *)temp->data;
			if(test_ctx->name == name)
				break;
			test_ctx = NULL;
			temp = temp->next;
		}

		if(test_ctx == NULL) {
			/* Unsupported test */
			ret = 127;
			goto done;
		}
		tests = g_list_append(tests, test_ctx);
	}
	if(options.verbose)
		verbose = TRUE;
	if(options.no_verify)
		no_verify = TRUE;

	/* TODO Parse the relay address to protocol, address and port */
	GUri *uri = g_uri_parse(relay, G_URI_FLAGS_NONE, NULL);
	if(uri != NULL) {
		if(!strcasecmp(g_uri_get_scheme(uri), "https")) {
			/* WebTransport */
			host = g_strdup(g_uri_get_host(uri));
			port = g_uri_get_port(uri);
			path = strlen(g_uri_get_path(uri)) > 0 ? g_strdup(g_uri_get_path(uri)) : NULL;
		} else if(!strcasecmp(g_uri_get_scheme(uri), "moqt")) {
			/* Raw QUIC */
			host = g_strdup(g_uri_get_host(uri));
			port = g_uri_get_port(uri);
			path = NULL;
		}
		g_uri_unref(uri);
	}

	/* If no specific test was requested, perform them all */
	if(tests == NULL)
		tests = g_list_copy(all_tests);

	/* Write the TAP 14 header */
	g_print("TAP version 14\n");
	g_print("# imquic-moq-interop-test v%s\n", imquic_get_version_string_full());
	g_print("# Relay: %s\n", relay);
	g_print("1..%d\n", g_list_length(tests));

	/* Initialize the library */
	imquic_init(NULL);

	/* Start the tests */
	GList *temp = tests;
	int test_num = 0;
	while(temp) {
		test_num++;
		imquic_moq_interop_test_context *test_ctx = (imquic_moq_interop_test_context *)temp->data;
		int res = imquic_moq_interop_perform_test(test_ctx, test_num);
		if(res != 0)
			ret = 1;
		if(res < 0) {
			/* FIXME Fatal error */
			break;
		}
		temp = temp->next;
	}

done:
	/* Done */
	demo_options_destroy();
	g_list_free(tests);
	g_list_free(all_tests);
	g_free(host);
	g_free(path);
	exit(ret);
}

/* Runners */
static int imquic_moq_interop_perform_test(imquic_moq_interop_test_context *test, int test_num) {
	current_test = test;
	if(host == NULL) {
		/* Nothing we can do, give up */
		g_print("not ok %d - %s\n", test_num, imquic_moq_interop_test_str(test->name));
		g_print("Bail out! Invalid relay address\n");
		return -1;
	}
	if(test->need_publisher) {
		test->publisher = imquic_moq_interop_client_create(test, TRUE);
		if(test->publisher == NULL) {
			g_print("not ok %d - %s\n", test_num, imquic_moq_interop_test_str(test->name));
			g_print("Bail out! Error creating client\n");
			return -1;
		}
	}
	if(test->need_subscriber) {
		test->subscriber = imquic_moq_interop_client_create(test, FALSE);
		if(test->subscriber == NULL) {
			imquic_moq_interop_client_destroy(test->publisher);
			g_print("not ok %d - %s\n", test_num, imquic_moq_interop_test_str(test->name));
			g_print("Bail out! Error creating client\n");
			return -1;
		}
	}

	/* Start the first connection we need */
	if(test->subscriber_first || test->publisher == NULL) {
		imquic_start_endpoint(test->subscriber->client);
	} else {
		imquic_start_endpoint(test->publisher->client);
	}

	/* TODO */
	int ret = 0;
	int64_t start = g_get_monotonic_time(), now = start, deadline = now + test->timeout;
	while(!g_atomic_int_get(&stop) && !g_atomic_int_get(&test->done)) {
		now = g_get_monotonic_time();
		if(now > deadline) {
			/* A timeout occurred */
			if(test->name == IMQUIC_INTEROP_SETUP_ONLY) {
				ret = -1;
			} else {
				ret = 1;
			}
			break;
		}
		g_usleep(1);
	}
	now = g_get_monotonic_time();
	if(ret >= 0)
		ret = g_atomic_int_get(&test->success) ? 0 : 1;
	/* Print the results */
	if(test->subtests != NULL) {
		/* We have subtests too */
		g_print("# Subtests: %s\n", imquic_moq_interop_test_str(test->name));
		g_print("    1..%d\n", g_list_length(test->subtests));
		GList *temp = test->subtests;
		int step = 0;
		while(temp) {
			step++;
			char *text = (char *)temp->data;
			if(*text == '!')
				g_print("    not ok %d - %s\n", step, text+1);
			else
				g_print("    ok %d - %s\n", step, text);
			temp = temp->next;
		}
	}
	g_print("%s %d - %s\n", (ret == 0 ? "ok" : "not ok"), test_num,
		imquic_moq_interop_test_str(test->name));
	if(ret != 0 || verbose) {
		/* Write the YAML summary */
		g_print("  ---\n");
		g_print("  duration_ms: %"SCNi64"\n", ((now-start)/1000));
		if(test->expected != NULL)
			g_print("  expected: %s\n", test->expected);
		if(test->received != NULL)
			g_print("  received: %s\n", test->received);
		if(test->message != NULL)
			g_print("  message: %s\n", test->message);
		if(test->pub_connection_id != NULL) {
			if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE || test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE)
				g_print("  publisher_connection_id: %s\n", test->pub_connection_id);
			else
				g_print("  connection_id: %s\n", test->pub_connection_id);
		}
		if(test->sub_connection_id != NULL) {
			if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE || test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE)
				g_print("  subscriber_connection_id: %s\n", test->sub_connection_id);
			else
				g_print("  connection_id: %s\n", test->sub_connection_id);
		}
		g_print("  ---\n");
	}
	if(ret < 0)
		g_print("Bail out! Timeout trying to connect\n");

	/* Cleanup */
	imquic_moq_interop_test_context_cleanup(test);
	return ret;
}

static imquic_moq_interop_client *imquic_moq_interop_client_create(imquic_moq_interop_test_context *test, gboolean publisher) {
	imquic_moq_interop_client *mc = g_malloc(sizeof(imquic_moq_interop_client));
	mc->test = test;
	mc->publisher = publisher;
	mc->conn = NULL;
	mc->client = imquic_create_moq_client(
		publisher ? "interop-publisher" : "interop-subscriber",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_REMOTE_HOST, host,
		IMQUIC_CONFIG_REMOTE_PORT, port,
		IMQUIC_CONFIG_RAW_QUIC, !webtransport,
		IMQUIC_CONFIG_WEBTRANSPORT, webtransport,
		IMQUIC_CONFIG_HTTP3_PATH, path ? path : "/",
		IMQUIC_CONFIG_TLS_NO_VERIFY, no_verify,
		IMQUIC_CONFIG_MOQ_VERSION, moq_version,
		IMQUIC_CONFIG_USER_DATA, mc,
		IMQUIC_CONFIG_DONE, NULL);
	if(mc->client == NULL) {
		imquic_moq_interop_client_destroy(mc);
		return NULL;
	}
	imquic_set_new_moq_connection_cb(mc->client, imquic_moq_interop_new_connection);
	imquic_set_moq_ready_cb(mc->client, imquic_moq_interop_ready);
	imquic_set_moq_connection_gone_cb(mc->client, imquic_moq_interop_connection_gone);
	if(publisher) {
		imquic_set_publish_namespace_accepted_cb(mc->client, imquic_moq_interop_publish_namespace_accepted);
		imquic_set_publish_namespace_error_cb(mc->client, imquic_moq_interop_publish_namespace_error);
		imquic_set_incoming_subscribe_cb(mc->client, imquic_moq_interop_incoming_subscribe);
	} else {
		imquic_set_subscribe_accepted_cb(mc->client, imquic_moq_interop_subscribe_accepted);
		imquic_set_subscribe_error_cb(mc->client, imquic_moq_interop_subscribe_error);
	}
	return mc;
}

/* Callbacks */
static void imquic_moq_interop_new_connection(imquic_connection *conn, void *user_data) {
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)user_data;
	if(client != NULL) {
		client->conn = conn;
		imquic_connection_ref(conn);
		imquic_set_connection_user_data(conn, user_data);
	}
	imquic_moq_set_max_request_id(conn, max_request_id);
}

static void imquic_moq_interop_ready(imquic_connection *conn) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(client->publisher && test->pub_connection_id == NULL)
		test->pub_connection_id = g_strdup(imquic_get_client_initial_connection_id(conn));
	else if(!client->publisher && test->sub_connection_id == NULL)
		test->sub_connection_id = g_strdup(imquic_get_client_initial_connection_id(conn));
	if(verbose) {
		/* Add a sub-step */
		char step[100];
		if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE || test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE) {
			g_snprintf(step, sizeof(step), "%s connected", (client->publisher ? "publisher" : "subscriber"));
		} else {
			g_snprintf(step, sizeof(step), "client connected");
		}
		test->subtests = g_list_append(test->subtests, g_strdup(step));
	}
	if(test->name == IMQUIC_INTEROP_SETUP_ONLY) {
		/* We're done */
		g_atomic_int_set(&test->success, 1);
		g_atomic_int_set(&test->done, 1);
	} else if(test->name == IMQUIC_INTEROP_ANNOUNCE_ONLY ||
			test->name == IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE ||
			(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE && client->publisher) ||
			(test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE && client->publisher)) {
		/* Publish the namespace */
		imquic_moq_namespace tns[2];
		tns[0].buffer = (uint8_t *)"moq-test";
		tns[0].length = strlen("moq-test");
		tns[0].next = &tns[1];
		tns[1].buffer = (uint8_t *)"interop";
		tns[1].length = strlen("interop");
		tns[1].next = NULL;
		imquic_moq_publish_namespace(conn, imquic_moq_get_next_request_id(conn), &tns[0], NULL);
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("publisher announced namespace"));
	} else if(test->name == IMQUIC_INTEROP_SUBSCRIBE_ERROR) {
		/* Subscribe to a non-existing track */
		imquic_moq_namespace tns[2];
		tns[0].buffer = (uint8_t *)"nonexistent";
		tns[0].length = strlen("nonexistent");
		tns[0].next = &tns[1];
		tns[1].buffer = (uint8_t *)"namespace";
		tns[1].length = strlen("namespace");
		tns[1].next = NULL;
		imquic_moq_name tn = {
			.buffer = (uint8_t *)"test-track",
			.length = strlen("test-track")
		};
		imquic_moq_subscribe(conn, imquic_moq_get_next_request_id(conn), 0, &tns[0], &tn, NULL);
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("subscriber subscribed to non-existing track"));
	} else if((test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE ||
			test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE) && !client->publisher) {
		/* Subscribe to the test track */
		imquic_moq_namespace tns[2];
		tns[0].buffer = (uint8_t *)"moq-test";
		tns[0].length = strlen("moq-test");
		tns[0].next = &tns[1];
		tns[1].buffer = (uint8_t *)"interop";
		tns[1].length = strlen("interop");
		tns[1].next = NULL;
		imquic_moq_name tn = {
			.buffer = (uint8_t *)"test-track",
			.length = strlen("test-track")
		};
		imquic_moq_subscribe(conn, imquic_moq_get_next_request_id(conn), 0, &tns[0], &tn, NULL);
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("subscriber subscribed to track"));
		if(test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE) {
			/* FIXME We should wait 500ms to start the publisher in this scenario */
			imquic_start_endpoint(test->publisher->client);
		}
	}
	/* TODO Other tests */
}

static void imquic_moq_interop_publish_namespace_accepted(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_parameters *parameters) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(verbose)
		test->subtests = g_list_append(test->subtests, g_strdup("publisher received ok to announced namespace"));
	if(test->name == IMQUIC_INTEROP_ANNOUNCE_ONLY) {
		/* We're done */
		g_atomic_int_set(&test->success, 1);
		g_atomic_int_set(&test->done, 1);
	} else if(test->name == IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE) {
		/* Send a PUBLISH_NAMESPACE_DONE */
		imquic_moq_namespace tns[2];
		tns[0].buffer = (uint8_t *)"moq-test";
		tns[0].length = strlen("moq-test");
		tns[0].next = &tns[1];
		tns[1].buffer = (uint8_t *)"interop";
		tns[1].length = strlen("interop");
		tns[1].next = NULL;
		int ret = imquic_moq_publish_namespace_done(conn, &tns[0]);
		if(ret == 0) {
			g_atomic_int_set(&test->success, 1);
			if(verbose)
				test->subtests = g_list_append(test->subtests, g_strdup("publisher sent namespace done"));
		} else {
			if(verbose)
				test->subtests = g_list_append(test->subtests, g_strdup("!publisher sent namespace done"));
		}
		/* We're done */
		g_atomic_int_set(&test->done, 1);
	} else if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE) {
		/* Start the subscriber */
		imquic_start_endpoint(test->subscriber->client);
	}
	/* TODO Other tests */
}

static void imquic_moq_interop_publish_namespace_error(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t retry_interval) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(test->name == IMQUIC_INTEROP_ANNOUNCE_ONLY || test->name == IMQUIC_INTEROP_PUBLISH_NAMESPACE_DONE) {
		/* We're done */
		test->expected = g_strdup("REQUEST_OK");
		test->received = g_strdup("REQUEST_ERROR");
		char message[200];
		g_snprintf(message, sizeof(message), "Error code %d (%s)", error_code, reason ? reason : "??");
		g_atomic_int_set(&test->done, 1);
	}
	/* TODO Other tests */
}

static void imquic_moq_interop_incoming_subscribe(imquic_connection *conn, uint64_t request_id,
		uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(verbose)
		test->subtests = g_list_append(test->subtests, g_strdup("publisher received subscribe"));
	if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE) {
		/* Accept the subscription */
		imquic_moq_accept_subscribe(conn, request_id, 0, NULL, NULL);
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("publisher accepted subscribe"));
	}
}

static void imquic_moq_interop_subscribe_accepted(imquic_connection *conn, uint64_t request_id,
		uint64_t track_alias, imquic_moq_request_parameters *parameters, GList *track_extensions) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(test->name == IMQUIC_INTEROP_SUBSCRIBE_ERROR) {
		/* We're done */
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("!subscriber received ok to subscription"));
		test->expected = g_strdup("REQUEST_ERROR");
		test->received = g_strdup("SUBSCRIBE_OK");
		g_atomic_int_set(&test->done, 1);
	} else if(test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE ||
			test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE) {
		/* We're done */
		if(verbose)
			test->subtests = g_list_append(test->subtests, g_strdup("subscriber received ok to subscription"));
		g_atomic_int_set(&test->success, 1);
		g_atomic_int_set(&test->done, 1);
	}
	/* TODO Other tests */
}

static void imquic_moq_interop_subscribe_error(imquic_connection *conn, uint64_t request_id,
		imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias, uint64_t retry_interval) {
	/* Depending on the test, we may or may not be done */
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	if(verbose)
		test->subtests = g_list_append(test->subtests, g_strdup("subscriber received error to subscription"));
	if(test->name == IMQUIC_INTEROP_SUBSCRIBE_ERROR ||
			test->name == IMQUIC_INTEROP_ANNOUNCE_SUBSCRIBE ||
			test->name == IMQUIC_INTEROP_SUBSCRIBE_BEFORE_ANNOUNCE) {
		/* We're done */
		g_atomic_int_set(&test->success, 1);
		g_atomic_int_set(&test->done, 1);
	}
	/* TODO Other tests */
}

static void imquic_moq_interop_connection_gone(imquic_connection *conn) {
	imquic_moq_interop_client *client = (imquic_moq_interop_client *)imquic_get_connection_user_data(conn);
	imquic_moq_interop_test_context *test = (imquic_moq_interop_test_context *)client->test;
	g_atomic_int_set(&test->done, 1);
}
