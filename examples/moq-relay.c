/*
 * imquic
 *
 * Author:  Lorenzo Miniero <lorenzo@meetecho.com>
 * License: MIT
 *
 * Basic MoQ relay
 *
 */

#include <arpa/inet.h>

#include <imquic/imquic.h>
#include <imquic/moq.h>

#include "moq-relay-options.h"
#include "moq-utils.h"

/* Command line options */
static demo_options options = { 0 };

/* Signal */
static volatile int stop = 0;
static void imquic_demo_handle_signal(int signum) {
	switch(g_atomic_int_get(&stop)) {
		case 0:
			IMQUIC_PRINT("Stopping relay, please wait...\n");
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
static imquic_mutex mutex = IMQUIC_MUTEX_INITIALIZER;
static GHashTable *connections = NULL, *publishers = NULL, *subscribers = NULL, *namespaces = NULL;
static GList *monitors = NULL;
static GList *fetches = NULL;

/* Helper structs */
typedef struct imquic_demo_moq_publisher {
	imquic_connection *conn;
	GHashTable *namespaces;
	GHashTable *subscriptions;
	GHashTable *subscriptions_by_id;
	uint64_t relay_track_alias;
	imquic_mutex mutex;
} imquic_demo_moq_publisher;
static imquic_demo_moq_publisher *imquic_demo_moq_publisher_create(imquic_connection *conn);
static void imquic_demo_moq_publisher_destroy(imquic_demo_moq_publisher *pub);

typedef struct imquic_demo_moq_published_namespace {
	imquic_demo_moq_publisher *pub;
	char *track_namespace;
	imquic_moq_namespace *tns;
	GHashTable *tracks;
	imquic_mutex mutex;
} imquic_demo_moq_published_namespace;
static imquic_demo_moq_published_namespace *imquic_demo_moq_published_namespace_create(imquic_demo_moq_publisher *pub,
	const char *track_namespace, imquic_moq_namespace *tns);
static void imquic_demo_moq_published_namespace_destroy(imquic_demo_moq_published_namespace *annc);

typedef struct imquic_demo_moq_track {
	imquic_demo_moq_published_namespace *annc;
	char *track_name;
	uint64_t request_id;
	uint64_t track_alias;
	gboolean track_alias_valid;
	gboolean published;
	gboolean pending;
	GList *subscriptions;
	GList *objects;
	imquic_mutex mutex;
} imquic_demo_moq_track;
static imquic_demo_moq_track *imquic_demo_moq_track_create(imquic_demo_moq_published_namespace *annc, const char *track_name);
static void imquic_demo_moq_track_destroy(imquic_demo_moq_track *annc);

typedef struct imquic_demo_moq_subscriber {
	imquic_connection *conn;
	GHashTable *subscriptions;
	GHashTable *subscriptions_by_id;
	uint64_t relay_track_alias;
	imquic_mutex mutex;
} imquic_demo_moq_subscriber;
static imquic_demo_moq_subscriber *imquic_demo_moq_subscriber_create(imquic_connection *conn);
static void imquic_demo_moq_subscriber_destroy(imquic_demo_moq_subscriber *sub);

typedef struct imquic_demo_moq_subscription {
	imquic_demo_moq_subscriber *sub;
	imquic_demo_moq_track *track;
	uint64_t request_id;
	uint64_t track_alias;
	gboolean active;
	imquic_moq_location sub_start, sub_end;
	uint64_t last_group_id, last_subgroup_id;
	gboolean fetch;
	gboolean forward;
	GList *objects;
	imquic_mutex mutex;
} imquic_demo_moq_subscription;
static imquic_demo_moq_subscription *imquic_demo_moq_subscription_create(imquic_demo_moq_subscriber *sub,
	imquic_demo_moq_track *track, uint64_t request_id, uint64_t track_alias);
static void imquic_demo_moq_subscription_destroy(imquic_demo_moq_subscription *s);

typedef struct imquic_demo_moq_monitor {
	uint64_t request_id;
	imquic_connection *conn;
	imquic_moq_namespace *tns;
	gboolean published;
	GHashTable *known_tracks;
	gboolean forward;
	char *ns;
} imquic_demo_moq_monitor;
static imquic_demo_moq_monitor *imquic_demo_moq_monitor_create(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, const char *ns);
static void imquic_demo_moq_monitor_destroy(imquic_demo_moq_monitor *mon);
/* Helper functions to return monitors that match a namespace */
static GList *imquic_demo_match_monitors(imquic_connection *conn, imquic_moq_namespace *tns);
static void imquic_demo_alert_monitors(imquic_demo_moq_published_namespace *annc, imquic_demo_moq_track *track, gboolean done);

/* Constructors and destructors for helper structs */
static imquic_demo_moq_publisher *imquic_demo_moq_publisher_create(imquic_connection *conn) {
	imquic_demo_moq_publisher *pub = g_malloc0(sizeof(imquic_demo_moq_publisher));
	pub->conn = conn;
	pub->namespaces = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_demo_moq_published_namespace_destroy);
	pub->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);
	pub->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, NULL);

	imquic_mutex_init(&pub->mutex);
	return pub;
}
static void imquic_demo_moq_publisher_destroy(imquic_demo_moq_publisher *pub) {
	if(pub) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing publisher %s\n", imquic_get_connection_name(pub->conn));
		if(pub->namespaces) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, pub->namespaces);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				imquic_demo_moq_published_namespace *annc = value;
				annc->pub = NULL;
				g_hash_table_iter_remove(&iter);
			}
			g_hash_table_unref(pub->namespaces);
		}
		if(pub->subscriptions != NULL)
			g_hash_table_unref(pub->subscriptions);
		if(pub->subscriptions_by_id != NULL)
			g_hash_table_unref(pub->subscriptions_by_id);
		imquic_mutex_destroy(&pub->mutex);
		g_free(pub);
	}
}
static imquic_demo_moq_published_namespace *imquic_demo_moq_published_namespace_create(imquic_demo_moq_publisher *pub,
		const char *track_namespace, imquic_moq_namespace *tns) {
	imquic_demo_moq_published_namespace *annc = g_malloc0(sizeof(imquic_demo_moq_published_namespace));
	annc->pub = pub;
	annc->track_namespace = g_strdup(track_namespace);
	annc->tns = imquic_moq_namespace_duplicate(tns);
	annc->tracks = g_hash_table_new_full(g_str_hash, g_str_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_demo_moq_track_destroy);
	imquic_mutex_init(&annc->mutex);
	return annc;
}
static void imquic_demo_moq_published_namespace_destroy(imquic_demo_moq_published_namespace *annc) {
	if(annc) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing namespace %s\n", annc->track_namespace);
		imquic_demo_alert_monitors(annc, NULL, TRUE);
		if(annc->track_namespace) {
			g_hash_table_remove(namespaces, annc->track_namespace);
			g_free(annc->track_namespace);
		}
		imquic_moq_namespace_free(annc->tns);
		if(annc->tracks) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, annc->tracks);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				imquic_demo_moq_track *t = value;
				t->annc = NULL;
			}
			g_hash_table_unref(annc->tracks);
		}
		imquic_mutex_destroy(&annc->mutex);
		g_free(annc);
	}
}
static imquic_demo_moq_track *imquic_demo_moq_track_create(imquic_demo_moq_published_namespace *annc, const char *track_name) {
	imquic_demo_moq_track *t = g_malloc0(sizeof(imquic_demo_moq_track));
	t->annc = annc;
	t->track_name = g_strdup(track_name);
	t->pending = TRUE;
	t->track_alias_valid = FALSE;
	imquic_mutex_init(&t->mutex);
	return t;
}
static void imquic_demo_moq_track_destroy(imquic_demo_moq_track *t) {
	if(t) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing track %s\n", t->track_name);
		g_free(t->track_name);
		if(t->annc && t->annc->pub) {
			if(t->track_alias_valid)
				g_hash_table_remove(t->annc->pub->subscriptions, &t->track_alias);
			g_hash_table_remove(t->annc->pub->subscriptions_by_id, &t->request_id);
		}
		imquic_mutex_lock(&t->mutex);
		GList *temp = t->subscriptions;
		while(temp) {
			imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
			if(s) {
				if(t->published && s->sub)
					imquic_moq_publish_done(s->sub->conn, s->request_id, IMQUIC_MOQ_PUBDONE_TRACK_ENDED, "Publisher disconnected");
				s->track = NULL;
				if(s->fetch) {
					g_list_free(s->objects);
					s->objects = NULL;
					fetches = g_list_remove(fetches, s);
				}
			}
			temp = temp->next;
		}
		g_list_free(t->subscriptions);
		t->subscriptions = NULL;
		g_list_free_full(t->objects, (GDestroyNotify)imquic_moq_object_cleanup);
		t->objects = NULL;
		imquic_mutex_unlock(&t->mutex);
		imquic_mutex_destroy(&t->mutex);
		g_free(t);
	}
}
static imquic_demo_moq_subscriber *imquic_demo_moq_subscriber_create(imquic_connection *conn) {
	imquic_demo_moq_subscriber *sub = g_malloc0(sizeof(imquic_demo_moq_subscriber));
	sub->conn = conn;
	sub->subscriptions = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, NULL);
	sub->subscriptions_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal,
		(GDestroyNotify)g_free, (GDestroyNotify)imquic_demo_moq_subscription_destroy);
	imquic_mutex_init(&sub->mutex);
	return sub;
}
static void imquic_demo_moq_subscriber_destroy(imquic_demo_moq_subscriber *sub) {
	if(sub) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Removing subscriber %s\n", imquic_get_connection_name(sub->conn));
		if(sub->subscriptions) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, sub->subscriptions);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				imquic_demo_moq_subscription *s = value;
				s->sub = NULL;
			}
			g_hash_table_unref(sub->subscriptions);
		}
		if(sub->subscriptions_by_id)
			g_hash_table_unref(sub->subscriptions_by_id);
		imquic_mutex_destroy(&sub->mutex);
		g_free(sub);
	}
}
static imquic_demo_moq_subscription *imquic_demo_moq_subscription_create(imquic_demo_moq_subscriber *sub,
		imquic_demo_moq_track *track, uint64_t request_id, uint64_t track_alias) {
	imquic_demo_moq_subscription *s = g_malloc0(sizeof(imquic_demo_moq_subscription));
	s->sub = sub;
	s->track = track;
	s->request_id = request_id;
	s->track_alias = track_alias;
	s->forward = TRUE;
	imquic_mutex_init(&s->mutex);
	return s;
}
static void imquic_demo_moq_subscription_destroy(imquic_demo_moq_subscription *s) {
	if(s) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- Removing subscription %"SCNu64"/%"SCNu64"\n", s->request_id, s->track_alias);
		if(s->track) {
			imquic_mutex_lock(&s->track->mutex);
			s->track->subscriptions = g_list_remove(s->track->subscriptions, s);
			imquic_mutex_unlock(&s->track->mutex);
		}
		if(s->fetch) {
			g_list_free(s->objects);
			fetches = g_list_remove(fetches, s);
		}
		imquic_mutex_destroy(&s->mutex);
		g_free(s);
	}
}

static imquic_demo_moq_monitor *imquic_demo_moq_monitor_create(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, const char *ns) {
	imquic_demo_moq_monitor *mon = g_malloc0(sizeof(imquic_demo_moq_monitor));
	mon->conn = conn;
	mon->request_id = request_id;
	mon->ns = ns ? g_strdup(ns) : NULL;
	mon->forward = TRUE;
	mon->tns = imquic_moq_namespace_duplicate(tns);
	mon->known_tracks = g_hash_table_new(NULL, NULL);
	return mon;
}

static void imquic_demo_moq_monitor_destroy(imquic_demo_moq_monitor *mon) {
	if(mon) {
		g_free(mon->ns);
		imquic_moq_namespace_free(mon->tns);
		g_hash_table_destroy(mon->known_tracks);
		g_free(mon);
	}
}

/* Helper functions to return monitors that match a namespace */
static GList *imquic_demo_match_monitors(imquic_connection *conn, imquic_moq_namespace *tns) {
	if(monitors == NULL || tns == NULL)
		return NULL;
	imquic_demo_moq_monitor *mon = NULL;
	GList *list = NULL, *temp = monitors;
	while(temp) {
		mon = (imquic_demo_moq_monitor *)temp->data;
		if(mon->conn != conn && imquic_moq_namespace_contains(mon->tns, tns))
			list = g_list_prepend(list, mon);
		temp = temp->next;
	}
	return list;
}

static void imquic_demo_alert_monitors(imquic_demo_moq_published_namespace *annc, imquic_demo_moq_track *track, gboolean done) {
	if(annc == NULL && track == NULL)
		return;
	if(annc == NULL)
		annc = track->annc;
	imquic_moq_namespace *tns = annc ? annc->tns : NULL;
	imquic_connection *conn = (annc && annc->pub) ? annc->pub->conn : NULL;
	GList *list = imquic_demo_match_monitors(conn, tns);
	if(list == NULL)
		return;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Namespace matches %d monitors\n",
		imquic_get_connection_name(conn), g_list_length(list));
	GList *temp = list;
	imquic_demo_moq_monitor *mon = NULL;
	while(temp) {
		mon = (imquic_demo_moq_monitor *)temp->data;
		if(mon->conn) {
			if(!done && !mon->published) {
				/* Send a PUBLISH_NAMESPACE */
				mon->published = TRUE;
				imquic_moq_publish_namespace(mon->conn, imquic_moq_get_next_request_id(conn), tns, NULL);
			} else if(done && mon->published) {
				/* Send a PUBLISH_NAMESPACE_DONE */
				mon->published = FALSE;
				imquic_moq_publish_namespace_done(mon->conn, tns);
			}
			if(track == NULL || g_hash_table_lookup(mon->known_tracks, track)) {
				temp = temp->next;
				continue;
			}
			/* Also send a PUBLISH to this interested subscriber: we create
			 * a subscription to track it and relay the media when ready */
			g_hash_table_insert(mon->known_tracks, track, track);
			imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
			if(sub == NULL) {
				/* Create a new subscriber instance */
				sub = imquic_demo_moq_subscriber_create(mon->conn);
				g_hash_table_insert(subscribers, mon->conn, sub);
			}
			uint64_t relay_request_id = imquic_moq_get_next_request_id(mon->conn);
			uint64_t relay_track_alias = sub->relay_track_alias;
			sub->relay_track_alias++;
			imquic_demo_moq_subscription *s = imquic_demo_moq_subscription_create(sub, track,
				relay_request_id, relay_track_alias);
			g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(relay_request_id), s);
			g_hash_table_insert(sub->subscriptions, imquic_uint64_dup(relay_track_alias), s);
			track->subscriptions = g_list_append(track->subscriptions, s);
			s->forward = mon->forward;
			s->sub_end.group = IMQUIC_MAX_VARINT;
			s->sub_end.object = IMQUIC_MAX_VARINT;
			/* Send the request */
			imquic_moq_name tn = {
				.buffer = (uint8_t *)track->track_name,
				.length = strlen(track->track_name),
			};
			imquic_moq_request_parameters params;
			imquic_moq_request_parameters_init_defaults(&params);
			imquic_moq_publish(mon->conn, relay_request_id, tns, &tn, relay_track_alias, &params);
		}
		temp = temp->next;
	}
	g_list_free(list);
}

/* Helper function to reorder objects in descending group order */
static int imquic_demo_reorder_descending(gconstpointer a, gconstpointer b) {
	imquic_moq_object *oa = (imquic_moq_object *)a;
	imquic_moq_object *ob = (imquic_moq_object *)b;
	if(oa->group_id > ob->group_id) {
		return -1;
	} else if(oa->group_id < ob->group_id) {
		return 1;
	} else {
		/* Same group, order on object */
		if(oa->object_id < ob->object_id)
			return -1;
		else if(oa->object_id > ob->object_id)
			return 1;
	}
	return 0;
}

/* Callbacks */
static void imquic_demo_new_connection(imquic_connection *conn, void *user_data) {
	/* Got new connection */
	imquic_connection_ref(conn);
	g_hash_table_insert(connections, conn, conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New MoQ connection (configuring parameters)\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s (%s)\n", imquic_get_connection_name(conn),
		imquic_is_connection_webtransport(conn) ? "WebTransport" : "Raw QUIC",
		imquic_is_connection_webtransport(conn) ? imquic_get_connection_wt_protocol(conn) : imquic_get_connection_alpn(conn));
	imquic_moq_set_max_request_id(conn, 100);
}

static uint64_t imquic_demo_incoming_moq_connection(imquic_connection *conn, uint8_t *auth, size_t authlen) {
	/* We got a CLIENT_SETUP */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got a new MoQ connection attempt\n",
		imquic_get_connection_name(conn));
	if(auth != NULL)
		imquic_moq_print_auth_info(conn, auth, authlen);
	if(!imquic_moq_check_auth_info(conn, options.auth_info, auth, authlen)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Incorrect authorization info provided\n", imquic_get_connection_name(conn));
		return IMQUIC_MOQ_UNAUTHORIZED;
	}
	/* Accept the connection */
	return 0;
}

static void imquic_demo_ready(imquic_connection *conn) {
	/* Negotiation was done */
	const char *peer = imquic_moq_get_remote_implementation(conn);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection ready\n", imquic_get_connection_name(conn));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		imquic_moq_version_str(imquic_moq_get_version(conn)));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- %s\n", imquic_get_connection_name(conn),
		peer ? peer : "unknown implementation");
}

static void imquic_demo_incoming_publish_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters) {
	/* We received an publish_namespace */
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] New published namespace: '%s'\n",
		imquic_get_connection_name(conn), ns);
	/* Check if this was published already */
	imquic_mutex_lock(&mutex);
	if(g_hash_table_lookup(namespaces, ns) != NULL) {
		/* Already published, reject */
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_ERR, "[%s] Namespace already published\n", imquic_get_connection_name(conn));
		imquic_moq_reject_publish_namespace(conn, request_id, IMQUIC_MOQ_REQERR_INTERNAL_ERROR, "Namespace already published");
		return;
	}
	/* Find the publisher from this connection */
	imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
	if(pub == NULL) {
		/* Create a new one */
		pub = imquic_demo_moq_publisher_create(conn);
		g_hash_table_insert(publishers, conn, pub);
	}
	/* Let's keep track of it */
	imquic_demo_moq_published_namespace *annc = imquic_demo_moq_published_namespace_create(pub, ns, tns);
	g_hash_table_insert(pub->namespaces, g_strdup(ns), annc);
	g_hash_table_insert(namespaces, g_strdup(ns), annc);
	/* Check if there's monitors interested in this */
	imquic_demo_alert_monitors(annc, NULL, FALSE);
	imquic_mutex_unlock(&mutex);
	/* Accept the publish */
	imquic_moq_accept_publish_namespace(conn, request_id, NULL);
}

static void imquic_demo_incoming_publish_namespace_cancel(imquic_connection *conn, imquic_moq_namespace *tns, imquic_moq_request_error_code error_code, const char *reason) {
	/* We received an publish_namespace cancel */
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Cancelled publishing of namespace: '%s' (%d, %s)\n",
		imquic_get_connection_name(conn), ns, error_code, reason);
	/* Find the namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	if(annc->pub == NULL || annc->pub->conn != conn) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got PUBLISH_NAMESPACE_CANCEL from a different connection, ignoring\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of it */
	g_hash_table_remove(namespaces, ns);
	if(annc->pub->namespaces)
		g_hash_table_remove(annc->pub->namespaces, annc->track_namespace);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_publish_namespace_done(imquic_connection *conn, imquic_moq_namespace *tns) {
	/* We received an publish_namespace_done */
	char buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, buffer, sizeof(buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish Namespace done: '%s'\n",
		imquic_get_connection_name(conn), ns);
	/* Find the namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	if(annc->pub == NULL || annc->pub->conn != conn) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Got PUBLISH_NAMESPACE_DONE from a different connection, ignoring\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Check if there's monitors interested in this */
	imquic_demo_alert_monitors(annc, NULL, TRUE);
	/* Get rid of it */
	g_hash_table_remove(namespaces, ns);
	if(annc->pub->namespaces)
		g_hash_table_remove(annc->pub->namespaces, annc->track_namespace);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_publish(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns, imquic_moq_name *tn,
		uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	/* We received a publish */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming publish for '%s'/'%s' (ID %"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, request_id, track_alias);
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	if(name == NULL || strlen(name) == 0)
		name = "temp";
	/* We also treat an incoming PUBLISH as an PUBLISH_NAMESPACE for that namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL) {
		/* Find the publisher from this connection */
		imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
		if(pub == NULL) {
			/* Create a new one */
			pub = imquic_demo_moq_publisher_create(conn);
			g_hash_table_insert(publishers, conn, pub);
		}
		/* Let's keep track of it */
		annc = imquic_demo_moq_published_namespace_create(pub, ns, tns);
		g_hash_table_insert(pub->namespaces, g_strdup(ns), annc);
		g_hash_table_insert(namespaces, g_strdup(ns), annc);
	}
	/* We also treat it as if we sent a SUBSCRIBE that got accepted */
	if(g_hash_table_lookup(annc->tracks, name) != NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Track '%s' already published\n", name);
		imquic_moq_reject_publish(conn, request_id, IMQUIC_MOQ_REQERR_UNAUTHORIZED, "Track already published");
		return;
	}
	imquic_demo_moq_track *track = imquic_demo_moq_track_create(annc, name);
	track->request_id = request_id;
	track->track_alias = track_alias;
	track->published = TRUE;
	track->pending = FALSE;
	track->track_alias_valid = TRUE;
	g_hash_table_insert(annc->tracks, g_strdup(name), track);
	g_hash_table_insert(annc->pub->subscriptions_by_id, imquic_uint64_dup(track->request_id), track);
	g_hash_table_insert(annc->pub->subscriptions, imquic_uint64_dup(track->track_alias), track);
	/* Check if there's monitors interested in this */
	imquic_demo_alert_monitors(annc, track, FALSE);
	imquic_mutex_unlock(&mutex);
	/* Done */
	imquic_moq_request_parameters rparams = *parameters;
	rparams.subscriber_priority_set = TRUE;
	rparams.subscriber_priority = 128;
	rparams.subscription_filter_set = TRUE;
	rparams.subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	imquic_moq_accept_publish(conn, request_id, &rparams);
}

static void imquic_demo_publish_accepted(imquic_connection *conn, uint64_t request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Publish '%"SCNu64"' accepted\n",
		imquic_get_connection_name(conn), request_id);
	/* Find the subscriber */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Update the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &request_id);
	if(s == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] No subscription with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), request_id);
		return;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Object forwarding %s\n",
		imquic_get_connection_name(conn), (parameters->forward ? "enabled" : "disabled"));
	s->active = TRUE;
	s->forward = parameters->forward;
	/* Check the filter */
	uint64_t filter_type = parameters->subscription_filter_set ?
		parameters->subscription_filter.type : IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	imquic_moq_object *largest = NULL;
	if(s->track != NULL && s->track->objects != NULL)
		largest = (imquic_moq_object *)s->track->objects->data;
	s->sub_end.group = IMQUIC_MAX_VARINT;
	s->sub_end.object = IMQUIC_MAX_VARINT;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Requested filter type '%s'\n",
		imquic_get_connection_name(conn), imquic_moq_filter_type_str(filter_type));
	if(filter_type == IMQUIC_MOQ_FILTER_LARGEST_OBJECT) {
		s->sub_start.group = largest ? largest->group_id : 0;
		s->sub_start.object = largest ? largest->object_id : 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_NEXT_GROUP_START) {
		s->sub_start.group = largest ? (largest->group_id + 1) : 0;
		s->sub_start.object = 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START) {
		s->sub_start = parameters->subscription_filter.start_location;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"]\n",
			imquic_get_connection_name(conn), s->sub_start.group, s->sub_start.object);
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		s->sub_start = parameters->subscription_filter.start_location;
		if(parameters->subscription_filter.end_group == 0)
			s->sub_end.group = IMQUIC_MAX_VARINT;
		else
			s->sub_end.group = parameters->subscription_filter.end_group - 1;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"] --> End group [%"SCNu64"]\n",
			imquic_get_connection_name(conn), s->sub_start.group, s->sub_start.object, s->sub_end.group);
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_publish_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error publishing with ID %"SCNu64": error %d (%s)\n",
		imquic_get_connection_name(conn), request_id, error_code, reason);
	/* Find the subscriber */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &request_id);
	if(s) {
		g_hash_table_remove(sub->subscriptions, &s->track_alias);
		g_hash_table_remove(sub->subscriptions_by_id, &request_id);
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_track_status(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	/* We received a request to return the track status */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming request to return the track status for '%s'/'%s' (ID %"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, request_id);
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	if(!imquic_moq_check_auth_info(conn, options.sub_auth_info,
			parameters->auth_token_set ? parameters->auth_token : NULL,
			parameters->auth_token_set ? parameters->auth_token_len : 0)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Incorrect authorization info provided\n", imquic_get_connection_name(conn));
		imquic_moq_reject_track_status(conn, request_id, IMQUIC_MOQ_REQERR_UNAUTHORIZED, "Unauthorized access");
		return;
	}
	if(name == NULL || strlen(name) == 0)
		name = "temp";
	/* Find the namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL || annc->pub == NULL || annc->pub->conn == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_track_status(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Namespace not found");
		return;
	}
	/* Do we know this track already? */
	imquic_demo_moq_track *track = g_hash_table_lookup(annc->tracks, name);
	if(track == NULL) {
		/* TODO We don't: we should forward this upstream, but we
		 * currently don't as this is just a proof-of-concept handling
		 * of a TRACK_STATUS request to reply with something */
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_track_status(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Namespace not found");
		return;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Object forwarding %s\n",
		imquic_get_connection_name(conn), (parameters->forward ? "enabled" : "disabled"));
	/* Check the filter */
	uint64_t filter_type = parameters->subscription_filter_set ?
		parameters->subscription_filter.type : IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	imquic_moq_object *largest = NULL;
	imquic_mutex_lock(&track->mutex);
	if(!track->pending && track->objects != NULL)
		largest = (imquic_moq_object *)track->objects->data;
	imquic_moq_location start = { 0 };
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Requested filter type '%s'\n",
		imquic_get_connection_name(conn), imquic_moq_filter_type_str(filter_type));
	if(filter_type == IMQUIC_MOQ_FILTER_LARGEST_OBJECT) {
		start.group = largest ? largest->group_id : 0;
		start.object = largest ? largest->object_id : 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_NEXT_GROUP_START) {
		start.group = largest ? (largest->group_id + 1) : 0;
		start.object = 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START ||
			filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		start = parameters->subscription_filter.start_location;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"]\n",
			imquic_get_connection_name(conn), start.group, start.object);
	}
	imquic_mutex_unlock(&track->mutex);
	imquic_mutex_unlock(&mutex);
	/* TODO We should make the track_alias mapping persistent for this subscriber */
	uint64_t track_alias = track->track_alias;
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.expires_set = TRUE;
	rparams.expires = 0;
	rparams.group_order_set = TRUE;
	rparams.group_order_ascending = TRUE;
	if(largest != NULL) {
		rparams.largest_object_set = TRUE;
		rparams.largest_object = start;
	}
	imquic_moq_accept_track_status(conn, request_id, track_alias, &rparams);
}

static void imquic_demo_incoming_subscribe(imquic_connection *conn, uint64_t request_id, uint64_t track_alias,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_request_parameters *parameters) {
	/* We received a subscribe */
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
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	if(!imquic_moq_check_auth_info(conn, options.sub_auth_info,
			parameters->auth_token_set ? parameters->auth_token : NULL,
			parameters->auth_token_set ? parameters->auth_token_len : 0)) {
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Incorrect authorization info provided\n", imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_UNAUTHORIZED, "Unauthorized access", track_alias);
		return;
	}
	if(name == NULL || strlen(name) == 0)
		name = "temp";
	/* Find the namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL || annc->pub == NULL || annc->pub->conn == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Namespace not found", track_alias);
		return;
	}
	/* Do we know this track already? */
	gboolean new_track = FALSE;
	imquic_demo_moq_track *track = g_hash_table_lookup(annc->tracks, name);
	if(track == NULL) {
		/* Not yet: create a placeholder pending track */
		new_track = TRUE;
		track = imquic_demo_moq_track_create(annc, name);
		g_hash_table_insert(annc->tracks, g_strdup(name), track);
	}
	/* Create a subscriber, if needed */
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		/* Create a new one */
		sub = imquic_demo_moq_subscriber_create(conn);
		g_hash_table_insert(subscribers, conn, sub);
	}
	/* Make sure we don't know this subscription already */
	if(g_hash_table_lookup(sub->subscriptions_by_id, &request_id) != NULL) {
		/* FIXME Should we return an error? */
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "Already subscribed with ID %"SCNu64"\n", request_id);
		return;
	}
	if(imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_12) {
		/* Starting from v12, the publisher (in this case the relay, since
		 * track_alias is handled hop-by-hop) always chooses the track_alias */
		track_alias = sub->relay_track_alias;
		sub->relay_track_alias++;
	}
	/* Create a subscription to this track */
	imquic_demo_moq_subscription *s = imquic_demo_moq_subscription_create(sub, track, request_id, track_alias);
	g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(request_id), s);
	g_hash_table_insert(sub->subscriptions, imquic_uint64_dup(track_alias), s);
	imquic_mutex_lock(&track->mutex);
	track->subscriptions = g_list_append(track->subscriptions, s);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Object forwarding %s\n",
		imquic_get_connection_name(conn), (parameters->forward ? "enabled" : "disabled"));
	s->forward = parameters->forward;
	/* Check the filter */
	uint64_t filter_type = parameters->subscription_filter_set ?
		parameters->subscription_filter.type : IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
	imquic_moq_object *largest = NULL;
	if(!track->pending && track->objects != NULL)
		largest = (imquic_moq_object *)track->objects->data;
	s->sub_end.group = IMQUIC_MAX_VARINT;
	s->sub_end.object = IMQUIC_MAX_VARINT;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Requested filter type '%s'\n",
		imquic_get_connection_name(conn), imquic_moq_filter_type_str(filter_type));
	if(filter_type == IMQUIC_MOQ_FILTER_LARGEST_OBJECT) {
		s->sub_start.group = largest ? largest->group_id : 0;
		s->sub_start.object = largest ? largest->object_id : 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_NEXT_GROUP_START) {
		s->sub_start.group = largest ? (largest->group_id + 1) : 0;
		s->sub_start.object = 0;
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_START) {
		s->sub_start = parameters->subscription_filter.start_location;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"]\n",
			imquic_get_connection_name(conn), s->sub_start.group, s->sub_start.object);
	} else if(filter_type == IMQUIC_MOQ_FILTER_ABSOLUTE_RANGE) {
		s->sub_start = parameters->subscription_filter.start_location;
		if(parameters->subscription_filter.end_group == 0)
			s->sub_end.group = IMQUIC_MAX_VARINT;
		else
			s->sub_end.group = parameters->subscription_filter.end_group - 1;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- -- Start location: [%"SCNu64"/%"SCNu64"] --> End group [%"SCNu64"]\n",
			imquic_get_connection_name(conn), s->sub_start.group, s->sub_start.object, s->sub_end.group);
	}
	imquic_mutex_unlock(&track->mutex);
	/* Only accept the subscribe right now if the track is already active */
	if(!track->pending) {
		s->active = TRUE;
		/* Fill in the largest location before answering */
		imquic_moq_request_parameters rparams;
		imquic_moq_request_parameters_init_defaults(&rparams);
		rparams.expires_set = TRUE;
		rparams.expires = 0;
		rparams.group_order_set = TRUE;
		rparams.group_order_ascending = TRUE;
		if(largest != NULL) {
			rparams.largest_object_set = TRUE;
			rparams.largest_object = s->sub_start;
		}
		imquic_moq_accept_subscribe(conn, request_id, track_alias, &rparams);
	}
	/* If we just created a placeholder track, forward the subscribe to the publisher */
	if(new_track) {
		track->request_id = imquic_moq_get_next_request_id(annc->pub->conn);
		g_hash_table_insert(annc->pub->subscriptions_by_id, imquic_uint64_dup(track->request_id), track);
		if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12) {
			track->track_alias = annc->pub->relay_track_alias;
			track->track_alias_valid = TRUE;
			annc->pub->relay_track_alias++;
			g_hash_table_insert(annc->pub->subscriptions, imquic_uint64_dup(track->track_alias), track);
		}
		/* We send a 'Largest Object' filter to the subscriber, we'll filter ourselves in case */
		imquic_moq_request_parameters params;
		imquic_moq_request_parameters_init_defaults(&params);
		params.subscriber_priority_set = parameters->subscriber_priority_set;
		params.subscriber_priority = parameters->subscriber_priority;
		params.group_order_set = parameters->group_order_set;
		params.group_order_ascending = parameters->group_order_ascending;
		params.forward_set = TRUE;
		params.forward = TRUE;
		params.subscription_filter_set = TRUE;
		params.subscription_filter.type = IMQUIC_MOQ_FILTER_LARGEST_OBJECT;
		imquic_moq_subscribe(annc->pub->conn, track->request_id, track->track_alias, tns, tn, &params);
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_subscribe_accepted(imquic_connection *conn, uint64_t request_id, uint64_t track_alias, imquic_moq_request_parameters *parameters) {
	/* Our subscription to a publisher was accepted */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription %"SCNu64" accepted (expires=%"SCNu64"; %s order)\n",
		imquic_get_connection_name(conn), request_id, parameters->expires,
		parameters->group_order_ascending ? "ascending" : "descending");
	if(parameters->largest_object_set) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]   -- Largest Location: %"SCNu64"/%"SCNu64"\n",
			imquic_get_connection_name(conn),
			parameters->largest_object.group, parameters->largest_object.object);
	}
	/* Find the track associated to this subscription */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
	if(pub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No publisher found for that subscription\n");
		return;
	}
	imquic_demo_moq_track *track = g_hash_table_lookup(pub->subscriptions_by_id, &request_id);
	if(track == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No track found for that subscription\n");
		return;
	}
	if(imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_12) {
		/* Starting from v12, the publisher always chooses the track_alias */
		track->track_alias = track_alias;
		track->track_alias_valid = TRUE;
		g_hash_table_insert(pub->subscriptions, imquic_uint64_dup(track->track_alias), track);
	}
	/* Send a SUBSCRIBE_OK to all subscribers */
	imquic_mutex_lock(&track->mutex);
	GList *temp = track->subscriptions;
	while(temp) {
		imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
		if(s && s->sub && s->sub->conn) {
			s->active = TRUE;
			imquic_moq_accept_subscribe(s->sub->conn, s->request_id, s->track_alias, parameters);
		}
		temp = temp->next;
	}
	/* Check if there's monitors interested in this */
	imquic_demo_alert_monitors(NULL, track, FALSE);
	imquic_mutex_unlock(&track->mutex);
	/* Remove the pending flag */
	track->pending = FALSE;
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_subscribe_error(imquic_connection *conn, uint64_t request_id, imquic_moq_request_error_code error_code, const char *reason, uint64_t track_alias) {
	/* Our subscription to a publisher was rejected */
	if(imquic_moq_get_version(conn) < IMQUIC_MOQ_VERSION_12) {
		/* Older versions of MoQ passed the track alias in the SUBSCRIBE */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing to ID %"SCNu64"/%"SCNu64": error %d (%s)\n",
			imquic_get_connection_name(conn), request_id, track_alias, error_code, reason);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Got an error subscribing via ID %"SCNu64": error %d (%s)\n",
			imquic_get_connection_name(conn), request_id, error_code, reason);
	}
	/* Find the track associated to this subscription */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
	if(pub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No publisher found for that subscription\n");
		return;
	}
	imquic_demo_moq_track *track = g_hash_table_lookup(pub->subscriptions_by_id, &request_id);
	if(track == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No track found for that subscription\n");
		return;
	}
	/* Send a SUBSCRIBE_ERROR to all subscribers */
	imquic_mutex_lock(&track->mutex);
	GList *temp = track->subscriptions;
	while(temp) {
		imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
		if(s && s->sub && s->sub->conn)
			imquic_moq_reject_subscribe(s->sub->conn, s->request_id, error_code, reason, s->track_alias);
		temp = temp->next;
	}
	imquic_mutex_unlock(&track->mutex);
	/* Destroy the track */
	if(track->annc && track->annc->tracks)
		g_hash_table_remove(track->annc->tracks, track->track_name);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_subscribe_updated(imquic_connection *conn, uint64_t request_id,
		uint64_t sub_request_id, imquic_moq_request_parameters *parameters) {
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming update for subscription %"SCNu64"\n",
		imquic_get_connection_name(conn), request_id);
	/* Find the subscriber */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe_update(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "No such subscription");
		/* TODO We should terminate with a PUBLISH_DONE with code UPDATE_FAILED */
		return;
	}
	/* Update the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id,
		imquic_moq_get_version(conn) >= IMQUIC_MOQ_VERSION_14 ? &sub_request_id : &request_id);
	if(s == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_subscribe_update(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "No such subscription");
		/* TODO We should terminate with a PUBLISH_DONE with code UPDATE_FAILED */
		return;
	}
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	if(parameters->forward_set) {
		/* TODO Update start location and end group too */
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s]  -- Object forwarding %s\n",
			imquic_get_connection_name(conn), (parameters->forward ? "enabled" : "disabled"));
		s->forward = parameters->forward;
		rparams.forward_set = TRUE;
		rparams.forward = parameters->forward;
	}
	/* Send an acknowledgement back (only supported if we're on v15 or beyond) */
	imquic_moq_accept_subscribe_update(conn, request_id, &rparams);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_publish_done(imquic_connection *conn, uint64_t request_id, imquic_moq_pub_done_code status_code, uint64_t streams_count, const char *reason) {
	/* Our subscription is done */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Subscription via ID %"SCNu64" is done, using %"SCNu64" streams: status %d (%s)\n",
		imquic_get_connection_name(conn), request_id, streams_count, status_code, reason);
	/* Find the track associated to this subscription */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
	if(pub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No publisher found for that subscription\n");
		return;
	}
	imquic_demo_moq_track *track = g_hash_table_lookup(pub->subscriptions_by_id, &request_id);
	if(track == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "No track found for that subscription\n");
		return;
	}
	/* Send a PUBLISH_DONE to all subscribers */
	imquic_mutex_lock(&track->mutex);
	GList *temp = track->subscriptions;
	while(temp) {
		imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
		if(s && s->sub && s->sub->conn)
			imquic_moq_publish_done(s->sub->conn, s->request_id, status_code, reason);
		temp = temp->next;
	}
	imquic_mutex_unlock(&track->mutex);
	/* Destroy the track */
	if(track->annc && track->annc->tracks)
		g_hash_table_remove(track->annc->tracks, track->track_name);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_unsubscribe(imquic_connection *conn, uint64_t request_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for subscription %"SCNu64"\n", imquic_get_connection_name(conn), request_id);
	/* Find the subscriber */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of the subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &request_id);
	if(s) {
		g_hash_table_remove(sub->subscriptions, &s->track_alias);
		g_hash_table_remove(sub->subscriptions_by_id, &request_id);
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_subscribe_namespace(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_request_parameters *parameters) {
	/* We received a subscribe for a namespace tuple */
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming subscribe for namespace prefix '%s'\n",
		imquic_get_connection_name(conn), ns);
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	/* Keep track of this as a monitor */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_monitor *mon = imquic_demo_moq_monitor_create(conn, request_id, tns, ns);
	if(parameters->forward_set)
		mon->forward = parameters->forward;
	monitors = g_list_prepend(monitors, mon);
	imquic_moq_accept_subscribe_namespace(conn, request_id, NULL);
	/* Check if there's events we can push and already tracks we can publish */
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc != NULL) {
		imquic_demo_alert_monitors(annc, NULL, FALSE);
		if(annc->tracks) {
			GHashTableIter iter;
			gpointer value;
			g_hash_table_iter_init(&iter, annc->tracks);
			while(g_hash_table_iter_next(&iter, NULL, &value)) {
				imquic_demo_moq_track *track = value;
				imquic_demo_alert_monitors(NULL, track, FALSE);
			}
		}
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_unsubscribe_namespace(imquic_connection *conn, uint64_t request_id, imquic_moq_namespace *tns) {
	/* We received an unsubscribe */
	char tns_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	uint32_t conn_moq_version = imquic_moq_get_version(conn);
	if(conn_moq_version <= IMQUIC_MOQ_VERSION_14) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for namespace prefix '%s'\n",
			imquic_get_connection_name(conn), ns);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming unsubscribe for namespace via ID %"SCNu64"\n",
			imquic_get_connection_name(conn), request_id);
	}
	/* FIXME Get rid of the associated monitor */
	imquic_demo_moq_monitor *mon = NULL;
	imquic_mutex_lock(&mutex);
	GList *temp = monitors;
	while(temp) {
		mon = (imquic_demo_moq_monitor *)temp->data;
		if(conn == mon->conn && ((conn_moq_version <= IMQUIC_MOQ_VERSION_14 && !strcasecmp(ns, mon->ns)) ||
				(conn_moq_version >= IMQUIC_MOQ_VERSION_15 && request_id == mon->request_id))) {
			monitors = g_list_delete_link(monitors, temp);
			imquic_demo_moq_monitor_destroy(mon);
			break;
		}
		temp = temp->next;
	}
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_standalone_fetch(imquic_connection *conn, uint64_t request_id,
		imquic_moq_namespace *tns, imquic_moq_name *tn, imquic_moq_location_range *range, imquic_moq_request_parameters *parameters) {
		//~ gboolean descending, imquic_moq_location_range *range, uint8_t *auth, size_t authlen) {
	/* We received a standalone fetch */
	char tns_buffer[256], tn_buffer[256];
	const char *ns = imquic_moq_namespace_str(tns, tns_buffer, sizeof(tns_buffer), TRUE);
	const char *name = imquic_moq_track_str(tn, tn_buffer, sizeof(tn_buffer));
	if(range->end.object == 0)
		range->end.object = IMQUIC_MAX_VARINT;
	else
		range->end.object--;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming standalone fetch for '%s'/'%s' (ID %"SCNu64"; %s order; group/object range %"SCNu64"/%"SCNu64"-->%"SCNu64"/%"SCNu64")\n",
		imquic_get_connection_name(conn), ns, name, request_id,
		parameters->group_order_ascending ? "ascending" : "descending",
		range->start.group, range->start.object, range->end.group, range->end.object);
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	/* Find the namespace */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_published_namespace *annc = g_hash_table_lookup(namespaces, ns);
	if(annc == NULL || annc->pub == NULL || annc->pub->conn == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Namespace not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_fetch(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Namespace not found");
		return;
	}
	/* Do we know this track? */
	imquic_demo_moq_track *track = g_hash_table_lookup(annc->tracks, name);
	if(track == NULL || track->pending || track->objects == NULL) {
		/* TODO We should relay the FETCH to the publisher */
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Track not found\n",
			imquic_get_connection_name(conn));
		imquic_moq_reject_fetch(conn, request_id, IMQUIC_MOQ_REQERR_DOES_NOT_EXIST, "Track not found");
		return;
	}
	/* Create a subscriber, if needed */
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		/* Create a new one */
		sub = imquic_demo_moq_subscriber_create(conn);
		g_hash_table_insert(subscribers, conn, sub);
	}
	/* Make sure we don't know this subscription already */
	if(g_hash_table_lookup(sub->subscriptions_by_id, &request_id) != NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Already subscribed with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), request_id);
		return;
	}
	/* Create a subscription to this track, and add to the list of fetches to serve */
	imquic_demo_moq_subscription *s = imquic_demo_moq_subscription_create(sub, track, request_id, 0);
	g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(request_id), s);
	imquic_mutex_lock(&track->mutex);
	track->subscriptions = g_list_append(track->subscriptions, s);
	/* Prepare the list of objects to send, out of the provided range */
	GList *temp = track->objects;
	imquic_moq_object *object = (imquic_moq_object *)(temp ? temp->data : NULL);
	imquic_moq_location largest = {
		.group = (object ? object->group_id : 0),
		.object = (object ? object->object_id : 0)
	};
	while(temp) {
		object = (imquic_moq_object *)temp->data;
		if((object->group_id < range->start.group || object->group_id > range->end.group) ||
				(object->group_id == range->start.group && object->object_id < range->start.object) ||
				(object->group_id == range->end.group && range->end.object > 0 && object->object_id > range->end.object)) {
			/* Outside of the range */
			temp = temp->next;
			continue;
		}
		s->objects = g_list_prepend(s->objects, object);
		temp = temp->next;
	}
	s->fetch = TRUE;
	if(!parameters->group_order_ascending)
		s->objects = g_list_sort(s->objects, imquic_demo_reorder_descending);
	imquic_mutex_unlock(&track->mutex);
	fetches = g_list_prepend(fetches, s);
	/* Accept the fetch */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.group_order_set = parameters->group_order_set;
	rparams.group_order_ascending = parameters->group_order_ascending;
	imquic_moq_accept_fetch(conn, request_id, &largest, &rparams);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_joining_fetch(imquic_connection *conn, uint64_t request_id, uint64_t joining_request_id ,
		gboolean absolute, uint64_t joining_start, imquic_moq_request_parameters *parameters) {
	/* We received a joining fetch */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming %s joining fetch for subscription %"SCNu64" (ID %"SCNu64"; start=%"SCNu64"; %s order)\n",
		imquic_get_connection_name(conn), (absolute ? "absolute" : "relative"),
		joining_request_id, request_id, joining_start,
		parameters->group_order_ascending ? "ascending" : "descending");
	if(parameters->auth_token_set)
		imquic_moq_print_auth_info(conn, parameters->auth_token, parameters->auth_token_len);
	imquic_mutex_lock(&mutex);
	/* Create a subscriber, if needed */
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		/* Create a new one */
		sub = imquic_demo_moq_subscriber_create(conn);
		g_hash_table_insert(subscribers, conn, sub);
	}
	/* Find the reference subscription */
	imquic_demo_moq_subscription *s = g_hash_table_lookup(sub->subscriptions_by_id, &joining_request_id);
	if(s == NULL || !s->active) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] No subscription with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), joining_request_id);
		imquic_moq_reject_fetch(conn, request_id, IMQUIC_MOQ_REQERR_INVALID_JOINING_REQUEST_ID, "Subscription not found");
		return;
	}
	/* Make sure we don't know this subscription already */
	if(g_hash_table_lookup(sub->subscriptions_by_id, &request_id) != NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Already subscribed with ID %"SCNu64"\n",
			imquic_get_connection_name(conn), request_id);
		return;
	}
	/* Create a subscription to this track, and add to the list of fetches to serve */
	imquic_demo_moq_track *track = s->track;
	imquic_demo_moq_subscription *jf = imquic_demo_moq_subscription_create(sub, track, request_id, 0);
	g_hash_table_insert(sub->subscriptions_by_id, imquic_uint64_dup(request_id), jf);
	imquic_mutex_lock(&track->mutex);
	track->subscriptions = g_list_append(track->subscriptions, jf);
	/* Prepare the list of objects to send, using the provided group offset */
	GList *temp = track->objects;
	imquic_moq_object *object = (imquic_moq_object *)(temp ? temp->data : NULL);
	imquic_moq_location start = {
		.group = (object ? (absolute ? joining_start : (object->group_id - joining_start)) : 0),
		.object = 0
	};
	imquic_moq_location largest = {
		.group = (object ? object->group_id : 0),
		.object = (object ? object->object_id : 0)
	};
	while(temp) {
		object = (imquic_moq_object *)temp->data;
		if(object->group_id < start.group) {
			/* Outside of the range */
			temp = temp->next;
			continue;
		}
		jf->objects = g_list_prepend(jf->objects, object);
		temp = temp->next;
	}
	jf->fetch = TRUE;
	if(parameters->group_order_ascending)
		jf->objects = g_list_sort(jf->objects, imquic_demo_reorder_descending);
	imquic_mutex_unlock(&track->mutex);
	fetches = g_list_prepend(fetches, jf);
	/* Accept the fetch */
	imquic_moq_request_parameters rparams;
	imquic_moq_request_parameters_init_defaults(&rparams);
	rparams.group_order_set = parameters->group_order_set;
	rparams.group_order_ascending = parameters->group_order_ascending;
	imquic_moq_accept_fetch(conn, request_id, &largest, &rparams);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_fetch_cancel(imquic_connection *conn, uint64_t request_id) {
	/* We received an unsubscribe */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming fetch cancel for subscription %"SCNu64"\n", imquic_get_connection_name(conn), request_id);
	/* Find the subscriber */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_subscriber *sub = g_hash_table_lookup(subscribers, conn);
	if(sub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] Subscriber not found\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Get rid of the subscription */
	g_hash_table_remove(sub->subscriptions_by_id, &request_id);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_incoming_object(imquic_connection *conn, imquic_moq_object *object) {
	/* We received an object */
	if(!options.quiet) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Incoming object: reqid=%"SCNu64", alias=%"SCNu64", group=%"SCNu64", subgroup=%"SCNu64", id=%"SCNu64", payload=%zu bytes, extensions=%zu bytes, delivery=%s, status=%s, eos=%d\n",
			imquic_get_connection_name(conn), object->request_id, object->track_alias,
			object->group_id, object->subgroup_id, object->object_id,
			object->payload_len, object->extensions_len, imquic_moq_delivery_str(object->delivery),
			imquic_moq_object_status_str(object->object_status), object->end_of_stream);
	}
	/* Find the track associated to this subscription */
	imquic_mutex_lock(&mutex);
	imquic_demo_moq_publisher *pub = g_hash_table_lookup(publishers, conn);
	if(pub == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] No publisher found for that subscription\n",
			imquic_get_connection_name(conn));
		return;
	}
	imquic_demo_moq_track *track = g_hash_table_lookup(pub->subscriptions, &object->track_alias);
	if(track == NULL) {
		imquic_mutex_unlock(&mutex);
		IMQUIC_LOG(IMQUIC_LOG_WARN, "[%s] No track found for that subscription\n",
			imquic_get_connection_name(conn));
		return;
	}
	/* Duplicate the object, in case we need it later for a FETCH */
	imquic_mutex_lock(&track->mutex);
	track->objects = g_list_prepend(track->objects, imquic_moq_object_duplicate(object));
	/* Relay the object to all subscribers */
	if(!options.quiet) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Relaying to %d subscribers\n",
			imquic_get_connection_name(conn), g_list_length(track->subscriptions));
	}
	GList *temp = track->subscriptions;
	GList *done = NULL;
	while(temp) {
		imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
		if(s && !s->fetch && s->sub && s->sub->conn) {
			/* Check if it matches the filter */
			if(object->group_id < s->sub_start.group || (object->group_id == s->sub_start.group && object->object_id < s->sub_start.object)) {
				/* Not the time to send the object yet */
				temp = temp->next;
				continue;
			}
			if(object->group_id > s->sub_end.group || (object->group_id == s->sub_end.group && object->object_id > s->sub_end.object)) {
				/* We've sent all that we were asked about for this subscription */
				IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] Reached the end group, the subscription is done\n",
					imquic_get_connection_name(s->sub->conn));
				/* Send a PUBLISH_DONE */
				imquic_moq_publish_done(s->sub->conn, s->request_id, IMQUIC_MOQ_PUBDONE_SUBSCRIPTION_ENDED, "Reached the end group");
				/* Get rid of this subscription */
				done = g_list_prepend(done, s);
				temp = temp->next;
				continue;
			}
			if(!s->active || !s->forward) {
				/* Subscription not establish yet, or subscriber doesn't
				 * want to receive any object, for now, so skip this */
				temp = temp->next;
				continue;
			}
			object->request_id = s->request_id;
			object->track_alias = s->track_alias;
			imquic_moq_send_object(s->sub->conn, object);
		}
		temp = temp->next;
	}
	/* Done */
	imquic_mutex_unlock(&track->mutex);
	/* Any subscription we should get rid of? */
	temp = done;
	while(temp) {
		imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
		if(s && s->sub) {
			g_hash_table_remove(s->sub->subscriptions, &s->track_alias);
			g_hash_table_remove(s->sub->subscriptions_by_id, &s->request_id);
		}
		temp = temp->next;
	}
	g_list_free(done);
	imquic_mutex_unlock(&mutex);
}

static void imquic_demo_connection_gone(imquic_connection *conn) {
	/* Connection was closed */
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] MoQ connection gone\n", imquic_get_connection_name(conn));
	/* Remove publishers/subscribers associated to this connection */
	imquic_mutex_lock(&mutex);
	g_hash_table_remove(publishers, conn);
	g_hash_table_remove(subscribers, conn);
	GList *temp = monitors, *next = NULL;
	while(temp) {
		next = temp->next;
		imquic_demo_moq_monitor *mon = (imquic_demo_moq_monitor *)temp->data;
		if(mon->conn == conn) {
			imquic_demo_moq_monitor_destroy(mon);
			monitors = g_list_delete_link(monitors, temp);
		}
		temp = next;
	}
	imquic_mutex_unlock(&mutex);
	if(g_hash_table_remove(connections, conn))
		imquic_connection_unref(conn);
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
	if(options.quiet)
		IMQUIC_LOG(IMQUIC_LOG_INFO, "Quiet mode (won't print incoming objects)\n");
	IMQUIC_LOG(IMQUIC_LOG_INFO, "\n");

	/* Initialize the library and create a server */
	if(imquic_init(options.secrets_log) < 0) {
		ret = 1;
		goto done;
	}
	imquic_server *server = imquic_create_moq_server("moq-relay",
		IMQUIC_CONFIG_INIT,
		IMQUIC_CONFIG_TLS_CERT, options.cert_pem,
		IMQUIC_CONFIG_TLS_KEY, options.cert_key,
		IMQUIC_CONFIG_TLS_PASSWORD, options.cert_pwd,
		IMQUIC_CONFIG_LOCAL_BIND, options.ip,
		IMQUIC_CONFIG_LOCAL_PORT, options.port,
		IMQUIC_CONFIG_RAW_QUIC, options.raw_quic,
		IMQUIC_CONFIG_WEBTRANSPORT, options.webtransport,
		IMQUIC_CONFIG_EARLY_DATA, options.early_data,
		IMQUIC_CONFIG_QLOG_PATH, options.qlog_path,
		IMQUIC_CONFIG_QLOG_QUIC, qlog_quic,
		IMQUIC_CONFIG_QLOG_HTTP3, qlog_http3,
		IMQUIC_CONFIG_QLOG_MOQ, qlog_moq,
		IMQUIC_CONFIG_QLOG_SEQUENTIAL, options.qlog_sequential,
		IMQUIC_CONFIG_MOQ_VERSION, moq_version,
		IMQUIC_CONFIG_DONE, NULL);
	if(server == NULL) {
		ret = 1;
		goto done;
	}
	if(options.raw_quic) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "ALPN(s):\n");
		int i = 0;
		const char **alpns = imquic_get_endpoint_alpns(server);
		while(alpns[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", alpns[i]);
			i++;
		}
	}
	if(options.webtransport && imquic_get_endpoint_wt_protocols(server) != NULL) {
		IMQUIC_LOG(IMQUIC_LOG_INFO, "WebTransport Protocol(s):\n");
		int i = 0;
		const char **wt_protocols = imquic_get_endpoint_wt_protocols(server);
		while(wt_protocols[i] != NULL) {
			IMQUIC_LOG(IMQUIC_LOG_INFO, "  -- %s\n", wt_protocols[i]);
			i++;
		}
	}
	imquic_set_new_moq_connection_cb(server, imquic_demo_new_connection);
	imquic_set_incoming_moq_connection_cb(server, imquic_demo_incoming_moq_connection);
	imquic_set_moq_ready_cb(server, imquic_demo_ready);
	imquic_set_incoming_publish_namespace_cb(server, imquic_demo_incoming_publish_namespace);
	imquic_set_incoming_publish_namespace_cancel_cb(server, imquic_demo_incoming_publish_namespace_cancel);
	imquic_set_publish_namespace_done_cb(server, imquic_demo_publish_namespace_done);
	imquic_set_incoming_publish_cb(server, imquic_demo_incoming_publish);
	imquic_set_publish_accepted_cb(server, imquic_demo_publish_accepted);
	imquic_set_publish_error_cb(server, imquic_demo_publish_error);
	imquic_set_incoming_track_status_cb(server, imquic_demo_incoming_track_status);
	imquic_set_incoming_subscribe_cb(server, imquic_demo_incoming_subscribe);
	imquic_set_subscribe_accepted_cb(server, imquic_demo_subscribe_accepted);
	imquic_set_subscribe_error_cb(server, imquic_demo_subscribe_error);
	imquic_set_subscribe_updated_cb(server, imquic_demo_subscribe_updated);
	imquic_set_publish_done_cb(server, imquic_demo_publish_done);
	imquic_set_incoming_unsubscribe_cb(server, imquic_demo_incoming_unsubscribe);
	imquic_set_incoming_subscribe_namespace_cb(server, imquic_demo_incoming_subscribe_namespace);
	imquic_set_incoming_unsubscribe_namespace_cb(server, imquic_demo_incoming_unsubscribe_namespace);
	imquic_set_incoming_standalone_fetch_cb(server, imquic_demo_incoming_standalone_fetch);
	imquic_set_incoming_joining_fetch_cb(server, imquic_demo_incoming_joining_fetch);
	imquic_set_incoming_fetch_cancel_cb(server, imquic_demo_incoming_fetch_cancel);
	imquic_set_incoming_object_cb(server, imquic_demo_incoming_object);
	imquic_set_moq_connection_gone_cb(server, imquic_demo_connection_gone);

	/* Initialize the resources we'll need */
	connections = g_hash_table_new(NULL, NULL);
	publishers = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_demo_moq_publisher_destroy);
	subscribers = g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)imquic_demo_moq_subscriber_destroy);
	namespaces = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, NULL);

	/* Start the server */
	imquic_start_endpoint(server);

	while(!stop) {
		imquic_mutex_lock(&mutex);
		if(fetches == NULL) {
			/* Nothing to do, just wait */
			imquic_mutex_unlock(&mutex);
			g_usleep(100000);
		} else {
			/* FIXME BADLY Iterate on the fetches and serve the requested objects */
			GList *temp = fetches, *next = NULL;
			while(temp) {
				imquic_demo_moq_subscription *s = (imquic_demo_moq_subscription *)temp->data;
				if(s && s->objects) {
					GList *first = s->objects;
					imquic_moq_object *object = (imquic_moq_object *)first->data;
					object->request_id = s->request_id;
					object->track_alias = s->track_alias;
					object->delivery = IMQUIC_MOQ_USE_FETCH;
					object->end_of_stream = (first->next == NULL);
					imquic_moq_send_object(s->sub->conn, object);
					s->objects = g_list_delete_link(s->objects, first);
				}
				next = temp->next;
				if(s->objects == NULL) {
					IMQUIC_LOG(IMQUIC_LOG_INFO, "[%s] FETCH delivery %"SCNu64" completed\n",
						imquic_get_connection_name(s->sub->conn), s->request_id);
					fetches = g_list_delete_link(fetches, temp);
					if(s->sub)
						g_hash_table_remove(s->sub->subscriptions_by_id, &s->request_id);
				}
				temp = next;
			}
			imquic_mutex_unlock(&mutex);
		}
	}


	imquic_shutdown_endpoint(server);

done:
	imquic_deinit();
	if(connections != NULL)
		g_hash_table_unref(connections);
	if(publishers != NULL)
		g_hash_table_unref(publishers);
	if(subscribers != NULL)
		g_hash_table_unref(subscribers);
	if(namespaces != NULL)
		g_hash_table_unref(namespaces);
	g_list_free_full(monitors, (GDestroyNotify)imquic_demo_moq_monitor_destroy);
	if(ret == 1)
		demo_options_show_usage();
	demo_options_destroy();

	/* Done */
	IMQUIC_PRINT("Bye!\n");
	exit(ret);
}
