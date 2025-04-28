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

/* Tester state */
static imquic_moq_version moq_version = IMQUIC_MOQ_VERSION_ANY;
static GMutex mutex;
static GHashTable *connections = NULL, *subscribers = NULL;
static void *imquic_demo_tester_thread(void *data);

/* Namespace tuple fields */
typedef enum imquic_demo_tuple_field {
	TUPLE_FIELD_PROTOCOL = 0,
	TUPLE_FIELD_FORWARDING,
	TUPLE_FIELD_START_GROUP,
	TUPLE_FIELD_START_OBJECT,
	TUPLE_FIELD_LAST_GROUP,
	TUPLE_FIELD_LAST_OBJECT,
	TUPLE_FIELD_OBJS_x_GROUP,
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
		case TUPLE_FIELD_OBJS_x_GROUP:
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
typedef struct imquic_demo_moq_subscriber {
	imquic_connection *conn;
	GHashTable *subscriptions;
	GHashTable *subscriptions_by_id;
	GMutex mutex;
} imquic_demo_moq_subscriber;
static imquic_demo_moq_subscriber *imquic_demo_moq_subscriber_create(imquic_connection *conn);
static void imquic_demo_moq_subscriber_destroy(imquic_demo_moq_subscriber *sub);

typedef struct imquic_demo_moq_subscription {
	imquic_demo_moq_subscriber *sub;
	uint64_t subscribe_id;
	uint64_t track_alias;
	gboolean fetch;
	gboolean descending;
	imquic_moq_fetch_range range;
	int64_t test[IMQUIC_DEMO_TEST_MAX];
	GThread *thread;
	volatile int destroyed;
} imquic_demo_moq_subscription;
static imquic_demo_moq_subscription *imquic_demo_moq_subscription_create(imquic_demo_moq_subscriber *sub,
	uint64_t subscribe_id, uint64_t track_alias);
static void imquic_demo_moq_subscription_stop(imquic_demo_moq_subscription *s);
static void imquic_demo_moq_subscription_destroy(imquic_demo_moq_subscription *s);

/* Constructors and destructors for helper structs */
static imquic_demo_moq_subscriber *imquic_demo_moq_subscriber_create(imquic_connection *conn) {
	imquic_demo_moq_subscriber *sub = g_malloc0(sizeof(imquic_demo_moq_subscriber));
	sub->conn = conn;
	sub->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_demo_moq_subscription_stop);
	sub->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	g_mutex_init(&sub->mutex);
	return sub;
}
static void imquic_demo_moq_subscriber_destroy(imquic_demo_moq_subscriber *sub) {
	if(sub) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing subscriber %s\n", imquic_get_connection_name(sub->conn));
		if(sub->subscriptions)
			g_hash_table_unref(sub->subscriptions);
		if(sub->subscriptions_by_id)
			g_hash_table_unref(sub->subscriptions_by_id);
		g_mutex_clear(&sub->mutex);
		g_free(sub);
	}
}

static imquic_demo_moq_subscription *imquic_demo_moq_subscription_create(imquic_demo_moq_subscriber *sub,
		uint64_t subscribe_id, uint64_t track_alias) {
	imquic_demo_moq_subscription *s = g_malloc0(sizeof(imquic_demo_moq_subscription));
	s->sub = sub;
	s->subscribe_id = subscribe_id;
	s->track_alias = track_alias;
	return s;
}
static void imquic_demo_moq_subscription_stop(imquic_demo_moq_subscription *s) {
	if(s && g_atomic_int_compare_and_exchange(&s->destroyed, 0, 1)) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Stopping subscription %"SCNu64"/%"SCNu64"\n", s->subscribe_id, s->track_alias);
	}
}
static void imquic_demo_moq_subscription_destroy(imquic_demo_moq_subscription *s) {
	if(s) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing subscription %"SCNu64"/%"SCNu64"\n", s->subscribe_id, s->track_alias);
		g_free(s);
	}
}

static int imquic_demo_tuple_to_test(imquic_connection *conn, imquic_moq_namespace *tns, int64_t *test, char *error, size_t error_len) {
	/* Evaluate the namespace tuple and create a test profile */
	char tns_buffer[20];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), FALSE);
	if(strcasecmp(ns, IMQUIC_DEMO_TEST_NAME)) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid test protocol '%s' in tuple field 0 (should be '%s')\n",
			imquic_get_connection_name(conn), ns, IMQUIC_DEMO_TEST_NAME);
		g_snprintf(error, error_len, "Invalid tuple field 0");
		return 400;
	}
	memcpy(test, default_test, sizeof(default_test));
	uint8_t count = 0;
	gboolean invalid = FALSE;
	imquic_moq_namespace *temp = tns;
	while(temp) {
		if(count >= IMQUIC_DEMO_TEST_MAX) {
			IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid namespace tuple, too many fields (> %d)\n",
				imquic_get_connection_name(conn), IMQUIC_DEMO_TEST_MAX);
			g_snprintf(error, error_len, "Too many tuple fields");
			return 400;
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
					case TUPLE_FIELD_OBJ0_SIZE:
					case TUPLE_FIELD_OBJS_SIZE:
						if(test[count] < 0)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_OBJS_x_GROUP:
					case TUPLE_FIELD_OBJS_FREQ:
					case TUPLE_FIELD_GROUP_INC:
					case TUPLE_FIELD_OBJ_INC:
						if(test[count] <= 0)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_SEND_EOG:
						if(test[count] < 0 || test[count] > 1)
							invalid = TRUE;
						break;
					case TUPLE_FIELD_EXT_INT:
					case TUPLE_FIELD_EXT_VAR:
					case TUPLE_FIELD_TIMEOUT:
					case TUPLE_FIELD_PROTOCOL:
					default:
						break;
				}
				if(invalid) {
					IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid tuple field '%s', out of range\n",
						imquic_get_connection_name(conn), imquic_demo_tuple_field_str(count));
					g_snprintf(error, error_len, "Invalid tuple field %"SCNu8, count);
					return 400;
				}
			}
		}
		count++;
		temp = temp->next;
	}
	if(test[TUPLE_FIELD_START_GROUP] > test[TUPLE_FIELD_LAST_GROUP]) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid tuple fields, '%s' is larger than '%s'\n",
			imquic_get_connection_name(conn), imquic_demo_tuple_field_str(TUPLE_FIELD_START_GROUP),
			imquic_demo_tuple_field_str(TUPLE_FIELD_LAST_GROUP));
		g_snprintf(error, error_len, "Conflicting tuple fields %"SCNu8" and %"SCNu8,
			TUPLE_FIELD_START_GROUP, TUPLE_FIELD_LAST_GROUP);
		return 400;
	}
	if(test[TUPLE_FIELD_LAST_OBJECT] == -1)
		test[TUPLE_FIELD_LAST_OBJECT] = test[TUPLE_FIELD_OBJS_x_GROUP];
	if(test[TUPLE_FIELD_START_OBJECT] > test[TUPLE_FIELD_LAST_OBJECT]) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Invalid tuple fields, '%s' is larger than '%s'\n",
			imquic_get_connection_name(conn), imquic_demo_tuple_field_str(TUPLE_FIELD_START_OBJECT),
			imquic_demo_tuple_field_str(TUPLE_FIELD_LAST_OBJECT));
		g_snprintf(error, error_len, "Conflicting tuple fields %"SCNu8" and %"SCNu8,
			TUPLE_FIELD_START_OBJECT, TUPLE_FIELD_LAST_OBJECT);
		return 400;
	}
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
	return 0;
}

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	g_mutex_lock(&mutex);
	g_hash_table_insert(connections, conn, conn);
	g_mutex_unlock(&mutex);
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

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t subscribe_id, uint64_t track_alias, imquic_moq_namespace *tns, imquic_moq_name *tn, const char *auth) {
	/* We received a subscribe */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, track_alias);
	if(auth != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %s\n",
			imquic_get_connection_name(conn), auth);
	}
	/* Parse the namespace tuple to a test profile */
	int64_t test[IMQUIC_DEMO_TEST_MAX];
	char err[256];
	int res = imquic_demo_tuple_to_test(conn, tns, test, err, sizeof(err));
	if(res != 0) {
		imquic_moq_reject_subscribe(conn, subscribe_id, res, err, track_alias);
		return;
	}
	g_mutex_lock(&mutex);
	/* Create a subscriber, if needed */
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		/* Create a new one */
		sub = imquic_demo_moq_subscriber_create(conn);
		g_hash_table_insert(subscribers, conn, sub);
	}
	/* Make sure we don't know this subscription already */
	if(g_hash_table_lookup(sub->subscriptions_by_id, &subscribe_id) != NULL) {
		g_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Already subscribed with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), subscribe_id);
		return;
	}
	/* Create a subscription to this track */
	imquic_demo_moq_subscription *s = imquic_demo_moq_subscription_create(sub, subscribe_id, track_alias);
	memcpy(s->test, test, sizeof(test));
	g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(subscribe_id), s);
	g_hash_table_insert(sub->subscriptions, imquic_uint64_dup(track_alias), s);
	g_mutex_unlock(&mutex);
	/* Accept and serve the test subscription */
	imquic_moq_accept_subscribe(conn, subscribe_id, 0, FALSE);
	/* Spawn thread to send objects */
	GError *error = NULL;
	s->thread = g_thread_try_new("moq-test", &imquic_demo_tester_thread, s, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Got error %d (%s) trying to launch a new test thread\n",
			imquic_get_connection_name(conn), error->code, error->message ? error->message : "??");
		g_error_free(error);
	}
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t subscribe_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), subscribe_id);
	/* Find the subscriber */
	g_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		g_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &subscribe_id);
	if(s && !s->fetch) {
		g_hash_table_remove(sub->subscriptions_by_id, &subscribe_id);
		g_hash_table_remove(sub->subscriptions, &s->track_alias);
	}
	g_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_standalone_fetch(imquic_connection *conn, uint64_t subscribe_id, imquic_moq_namespace *tns, imquic_moq_name *tn,
		gboolean descending, imquic_moq_fetch_range *range, const char *auth) {
	/* We received a standalone fetch */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming standalone fetch for '%s'/'%s' (ID %"SCNu64"; %s order; group/object range %"SCNu64"/%"SCNu64"-->%"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, subscribe_id, descending ? "descending" : "ascending",
		range->start.group, range->start.object, range->end.group, range->end.object);
	if(auth != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %s\n",
			imquic_get_connection_name(conn), auth);
	}
	/* Parse the namespace tuple to a test profile */
	int64_t test[IMQUIC_DEMO_TEST_MAX];
	char err[256];
	int res = imquic_demo_tuple_to_test(conn, tns, test, err, sizeof(err));
	if(res != 0) {
		imquic_moq_reject_fetch(conn, subscribe_id, res, err);
		return;
	}
	/* Intersect the test settings with the provided range */
	imquic_moq_position largest = {
		.group = test[TUPLE_FIELD_START_GROUP],
		.object = test[TUPLE_FIELD_START_OBJECT]
	};
	while((largest.group + test[TUPLE_FIELD_GROUP_INC]) <= (uint64_t)test[TUPLE_FIELD_LAST_GROUP])
		largest.group += test[TUPLE_FIELD_GROUP_INC];
	int64_t i = 0;
	for(i=0; i<test[TUPLE_FIELD_OBJS_x_GROUP]; i++) {
		largest.object += test[TUPLE_FIELD_OBJ_INC];
		if(largest.object >= (uint64_t)test[TUPLE_FIELD_LAST_OBJECT]) {
			if(largest.object > (uint64_t)test[TUPLE_FIELD_LAST_OBJECT])
				largest.object -= test[TUPLE_FIELD_LAST_OBJECT];
			break;
		}
	}
	if(range->start.group > largest.group || range->end.group < (uint64_t)test[TUPLE_FIELD_START_GROUP] ||
			(range->start.group == largest.group && range->start.object > largest.object) ||
			(range->end.group == (uint64_t)test[TUPLE_FIELD_START_GROUP] && range->end.object < (uint64_t)test[TUPLE_FIELD_START_OBJECT])) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] FETCH range outside of test range\n", imquic_get_connection_name(conn));
		imquic_moq_reject_fetch(conn, subscribe_id, 400, "FETCH range outside of test range");
		return;
	}
	g_mutex_lock(&mutex);
	/* Create a subscriber, if needed */
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		/* Create a new one */
		sub = imquic_demo_moq_subscriber_create(conn);
		g_hash_table_insert(subscribers, conn, sub);
	}
	/* Make sure we don't know this subscription already */
	if(g_hash_table_lookup(sub->subscriptions_by_id, &subscribe_id) != NULL) {
		g_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Already subscribed with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), subscribe_id);
		return;
	}
	/* Create a subscription to this track */
	imquic_demo_moq_subscription *s = imquic_demo_moq_subscription_create(sub, subscribe_id, 0);
	s->fetch = TRUE;
	s->descending = descending;
	s->range = *range;
	memcpy(s->test, test, sizeof(test));
	g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(subscribe_id), s);
	g_mutex_unlock(&mutex);
	/* Accept and serve the test subscription */
	imquic_moq_accept_fetch(conn, subscribe_id, descending, &largest);
	/* Spawn thread to send objects */
	GError *error = NULL;
	s->thread = g_thread_try_new("moq-test", &imquic_demo_tester_thread, s, &error);
	if(error != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Got error %d (%s) trying to launch a new test thread\n",
			imquic_get_connection_name(conn), error->code, error->message ? error->message : "??");
		g_error_free(error);
	}
}

static void imquic_demo_incoming_joining_fetch(imquic_connection *conn, uint64_t subscribe_id, uint64_t joining_subscribe_id ,
		uint64_t preceding_group_offset, gboolean descending, const char *auth) {
	/* We received a joining fetch */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming joining fetch for subscription %"SCNu64" (ID %"SCNu64"; %"SCNu64" groups; %s order)\n",
		imquic_get_connection_name(conn), joining_subscribe_id, subscribe_id, preceding_group_offset, descending ? "descending" : "ascending");
	if(auth != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Authorization info: %s\n",
			imquic_get_connection_name(conn), auth);
	}
	/* TODO Add support for joining FETCH */
	imquic_moq_reject_fetch(conn, subscribe_id, 500, "Not implemented yet");
}

static void imquic_demo_incoming_fetch_cancel(imquic_connection *conn, uint64_t subscribe_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming fetch cancel for subscription %"SCNu64"\n", imquic_get_connection_name(conn), subscribe_id);
	/* Find the subscriber */
	g_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		g_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &subscribe_id);
	if(s && s->fetch)
		g_hash_table_remove(sub->subscriptions_by_id, &subscribe_id);
	g_mutex_unlock(&mutex);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
	/* Remove subscribers associated to this connection */
	g_mutex_lock(&mutex);
	g_hash_table_remove(subscribers, conn);
	if(g_hash_table_remove(connections, conn))
		imquic_connection_unref(conn);
	g_mutex_unlock(&mutex);
}

/* Tester thread, to send objects as requested in a SUBSCRIBE or FETCH */
static void *imquic_demo_tester_thread(void *data) {
	imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)data;
	if(data == NULL) {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid subscription\n");
		g_thread_unref(g_thread_self());
		return NULL;
	}
	imquic_connection *conn = s->sub->conn;
	imquic_connection_ref(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Starting delivery thread\n", imquic_get_connection_name(conn));
	/* Resources */
	imquic_moq_delivery delivery = s->test[TUPLE_FIELD_FORWARDING] == 3 ?
		IMQUIC_MOQ_USE_DATAGRAM : IMQUIC_MOQ_USE_SUBGROUP;
	if(s->fetch)
		delivery = IMQUIC_MOQ_USE_FETCH;
	uint64_t group_id = s->test[TUPLE_FIELD_START_GROUP];
	uint64_t subgroup_id = 0;
	uint64_t object_id = s->test[TUPLE_FIELD_START_OBJECT];
	if(s->descending) {
		object_id += ((s->test[TUPLE_FIELD_OBJS_x_GROUP] - 1) * s->test[TUPLE_FIELD_OBJ_INC]);
		if(group_id == (uint64_t)s->test[TUPLE_FIELD_LAST_GROUP])
			object_id = s->test[TUPLE_FIELD_LAST_OBJECT];
	}
	if(s->test[TUPLE_FIELD_FORWARDING] == 2)
		subgroup_id = object_id % 2;
	int64_t num_objects = 0;
	gboolean send_object = TRUE, next_group = FALSE, last_object = FALSE;
	uint64_t last_group_id = 0, last_subgroup_id = 0, last_object_id = 0;
	/* Buffers */
	uint8_t *obj0_p = s->test[TUPLE_FIELD_OBJ0_SIZE] ? g_malloc(s->test[TUPLE_FIELD_OBJ0_SIZE]) : NULL;
	if(obj0_p)
		memset(obj0_p, 't', s->test[TUPLE_FIELD_OBJ0_SIZE]);
	uint8_t *obj_p = s->test[TUPLE_FIELD_OBJS_SIZE] ? g_malloc(s->test[TUPLE_FIELD_OBJS_SIZE]) : NULL;
	if(obj_p)
		memset(obj_p, 't', s->test[TUPLE_FIELD_OBJS_SIZE]);
	uint8_t extensions[256];
	size_t extensions_len = 0;
	size_t extensions_count = 0;
	if(s->test[TUPLE_FIELD_EXT_INT] >= 0)
		extensions_count++;
	if(s->test[TUPLE_FIELD_EXT_VAR] >= 0)
		extensions_count++;
	/* Timers */
	int64_t frequency = s->test[TUPLE_FIELD_OBJS_FREQ] * 1000;
	int64_t sleep_time = frequency/2;
	int64_t now = g_get_monotonic_time(), before = now - frequency;
	/* Loop */
	while(!g_atomic_int_get(&s->destroyed)) {
		if(!s->fetch) {
			/* For SUBSCRIBE, we send objects at the right time */
			now = g_get_monotonic_time();
			if((now-before) < frequency) {
				g_usleep(sleep_time);
				continue;
			}
			before += frequency;
		}
		/* Time to send an object */
		send_object = TRUE;
		if(s->fetch && ((group_id < s->range.start.group || group_id > s->range.end.group) ||
				(group_id == s->range.start.group && object_id < s->range.start.object) ||
				(group_id == s->range.end.group && s->range.end.object > 0 && object_id > s->range.end.object))) {
			/* Outside of the FETCH range: progress but don't send the object */
			send_object = FALSE;
		}
		if(group_id >= (uint64_t)s->test[TUPLE_FIELD_LAST_GROUP] ||
				(group_id + (uint64_t)s->test[TUPLE_FIELD_GROUP_INC]) > (uint64_t)s->test[TUPLE_FIELD_LAST_GROUP]) {
			/* Check if this is going to be the last object in the track */
			if((!s->descending && object_id >= (uint64_t)s->test[TUPLE_FIELD_LAST_OBJECT]) ||
					(s->descending && (object_id == 0 || (group_id == (uint64_t)s->test[TUPLE_FIELD_START_GROUP] && object_id <= (uint64_t)s->test[TUPLE_FIELD_START_OBJECT]))))
				last_object = TRUE;
		}
		if(extensions_count > 0) {
			GList *exts = NULL;
			imquic_moq_object_extension numext = { 0 }, dataext = { 0 };
			if(s->test[TUPLE_FIELD_EXT_INT] >= 0) {
				/* Add a numeric extension */
				numext.id = 2 * s->test[TUPLE_FIELD_EXT_INT];
				numext.value.number = g_random_int();
				exts = g_list_append(exts, &numext);
			}
			if(s->test[TUPLE_FIELD_EXT_VAR] >= 0) {
				/* Add a data extension */
				dataext.id = 2 * s->test[TUPLE_FIELD_EXT_VAR] + 1;
				dataext.value.data.buffer = (uint8_t *)"moq-test";
				dataext.value.data.length = strlen("moq-test");
				exts = g_list_append(exts, &dataext);
			}
			extensions_len = imquic_moq_build_object_extensions(exts, extensions, sizeof(extensions));
			g_list_free(exts);
		}
		imquic_moq_object object = {
			.subscribe_id = s->subscribe_id,
			.track_alias = s->track_alias,
			.group_id = group_id,
			.subgroup_id = subgroup_id,
			.object_id = object_id,
			.object_status = 0,
			.object_send_order = 0,
			.payload = (num_objects == 0) ? obj0_p : obj_p,
			.payload_len = (num_objects == 0) ? s->test[TUPLE_FIELD_OBJ0_SIZE] : s->test[TUPLE_FIELD_OBJS_SIZE],
			.extensions = (extensions_len > 0) ? extensions : NULL,
			.extensions_len = extensions_len,
			.extensions_count = extensions_count,
			.delivery = delivery,
			.end_of_stream = (last_object || (!s->fetch && num_objects == (s->test[TUPLE_FIELD_OBJS_x_GROUP] - 1) && !s->test[TUPLE_FIELD_SEND_EOG]))
		};
		if(send_object) {
			imquic_moq_send_object(conn, &object);
			last_group_id = object.group_id;
			last_subgroup_id = object.subgroup_id;
			last_object_id = object.object_id;
		}
		/* Update IDs for the next object */
		num_objects++;
		next_group = (num_objects == s->test[TUPLE_FIELD_OBJS_x_GROUP]);
		if(last_object || (!s->fetch && next_group)) {
			/* We've sent all objects in this group, do we need to send an end of group? */
			if(s->test[TUPLE_FIELD_SEND_EOG]) {
				object.group_id = last_group_id;
				object.object_id = last_object_id + s->test[TUPLE_FIELD_OBJ_INC];
				object.subgroup_id = last_subgroup_id;
				if(s->test[TUPLE_FIELD_FORWARDING] == 1)
					object.subgroup_id++;
				else if(s->test[TUPLE_FIELD_FORWARDING] == 2)
					object.subgroup_id = object.object_id % 2;
				object.object_status = last_object ? IMQUIC_MOQ_END_OF_TRACK_AND_GROUP : IMQUIC_MOQ_END_OF_GROUP;
				object.payload_len = 0;
				object.payload = NULL;
				object.extensions = NULL;
				object.extensions_len = 0;
				object.extensions_count = 0;
				object.end_of_stream = TRUE;
				if(send_object || last_object)
					imquic_moq_send_object(conn, &object);
			}
			next_group = TRUE;
		} else {
			if(!s->descending) {
				object_id += s->test[TUPLE_FIELD_OBJ_INC];
			} else {
				if(object_id >= (uint64_t)s->test[TUPLE_FIELD_OBJ_INC])
					object_id -= s->test[TUPLE_FIELD_OBJ_INC];
				else
					next_group = TRUE;
			}
			if(s->test[TUPLE_FIELD_FORWARDING] == 1)
				subgroup_id++;
			else if(s->test[TUPLE_FIELD_FORWARDING] == 2)
				subgroup_id = object_id % 2;
		}
		if(next_group) {
			/* Let's reset/update the IDs */
			group_id += s->test[TUPLE_FIELD_GROUP_INC];
			subgroup_id = 0;
			object_id = 0;
			if(s->descending) {
				object_id += ((s->test[TUPLE_FIELD_OBJS_x_GROUP] - 1) * s->test[TUPLE_FIELD_OBJ_INC]);
				if(group_id >= (uint64_t)s->test[TUPLE_FIELD_LAST_GROUP])
					object_id = s->test[TUPLE_FIELD_LAST_OBJECT];
			}
			if(s->test[TUPLE_FIELD_FORWARDING] == 2)
				subgroup_id = object_id % 2;
			num_objects = 0;
			if(group_id > (uint64_t)s->test[TUPLE_FIELD_LAST_GROUP]) {
				/* We reached the last group, stop here */
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] All groups sent\n", imquic_get_connection_name(conn));
				g_mutex_lock(&mutex);
				g_hash_table_remove(s->sub->subscriptions_by_id, &s->subscribe_id);
				if(!s->fetch)
					g_hash_table_remove(s->sub->subscriptions, &s->track_alias);
				g_mutex_unlock(&mutex);
				break;
			}
			next_group = FALSE;
		}
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Stopping delivery thread\n", imquic_get_connection_name(conn));
	/* Destroy the subscription and the resources */
	imquic_demo_moq_subscription_destroy(s);
	g_free(obj0_p);
	g_free(obj_p);
	/* Done */
	imquic_connection_unref(conn);
	g_thread_unref(g_thread_self());
	return NULL;
}


/* Main */
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

	/* Check if we need to create a QLOG file, and which we should save */
	gboolean qlog_quic = FALSE, qlog_http3 = FALSE, qlog_moq = FALSE;
	if(options.qlog_path != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Creating QLOG file(s) in '%s'\n", options.qlog_path);
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
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_MOQ, qlog_moq,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
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
	default_test[TUPLE_FIELD_PROTOCOL] = 0;					/* Ignored, this will always be "moq-test-0" */
	default_test[TUPLE_FIELD_FORWARDING] = 0;
	default_test[TUPLE_FIELD_START_GROUP] = 0;
	default_test[TUPLE_FIELD_START_OBJECT] = 0;
	default_test[TUPLE_FIELD_LAST_GROUP] = (1L << 62) -1;
	default_test[TUPLE_FIELD_LAST_OBJECT] = -1;				/* Default is objects per group, plus 1 if sending end of group markers */
	default_test[TUPLE_FIELD_OBJS_x_GROUP] = 10;
	default_test[TUPLE_FIELD_OBJ0_SIZE] = 1024;
	default_test[TUPLE_FIELD_OBJS_SIZE] = 100;
	default_test[TUPLE_FIELD_OBJS_FREQ] = 1000;
	default_test[TUPLE_FIELD_GROUP_INC] = 1;
	default_test[TUPLE_FIELD_OBJ_INC] = 1;
	default_test[TUPLE_FIELD_SEND_EOG] = 0;
	default_test[TUPLE_FIELD_EXT_INT] = -1;					/* Don't add any numeric extension by default */
	default_test[TUPLE_FIELD_EXT_VAR] = -1;					/* Don't add any variable extension by default */
	default_test[TUPLE_FIELD_TIMEOUT] = -1;					/* No delivery timeout by default */

	/* Initialize the resources we'll need */
	connections = g_hash_table_new(NULL, NULL);
	subscribers = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_demo_moq_subscriber_destroy);

	/* Start the server */
	imquic_start_endpoint(server);

	while(!stop) {
		/* TODO */
		g_usleep(100000);
	}

	imquic_shutdown_endpoint(server);

done:
	imquic_deinit();
	if(connections != NULL)
		g_hash_table_unref(connections);
	if(subscribers != NULL)
		g_hash_table_unref(subscribers);
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
