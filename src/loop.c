/*! \file   loop.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Event loop
 * \details Implementation of an event loop to be used in the imquic
 * library internals, mostly for networking and the dispatching of some
 * events.
 *
 * \todo At the moment, a single event loop is created a startup that
 * all connections share. Besides, the events that can be dispatched
 * are defined in a suboptimal way that will need to be fixed.
 *
 * \ingroup Core
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "internal/loop.h"
#include "internal/network.h"
#include "internal/quic.h"
#include "imquic/debug.h"

/* Resources */
static GMainContext *ctx = NULL;
static GMainLoop *loop = NULL;
static GThread *thread = NULL;
static volatile int loop_started = 0;
static void *imquic_loop_thread(void *data) {
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Joining event loop thread...\n");
	g_atomic_int_set(&loop_started, 1);
	/* Run the main loop */
	g_main_loop_run(loop);
	/* When the loop ends, we're done */
	IMQUIC_LOG(IMQUIC_LOG_VERB, "Leaving event loop thread...\n");
	return NULL;
}

/* Network source */
typedef struct imquic_network_source {
	imquic_source parent;
	imquic_network_endpoint *ne;
	GDestroyNotify destroy;
} imquic_network_source;
static void imquic_network_endpoint_receive(imquic_network_endpoint *ne) {
	if(ne == NULL || ne->fd == -1)
		return;
	char buffer[4906];
	imquic_network_address sender = { 0 };
	sender.addrlen = sizeof(sender.addr);
	int len = recvfrom(ne->fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender.addr, &sender.addrlen);
	if(len > 0) {
		/* Invoke the callback function for parsing the QUIC message */
		imquic_process_message(ne, &sender, (uint8_t *)buffer, (size_t)len);
	}
}
static gboolean imquic_network_source_prepare(GSource *source, gint *timeout) {
	*timeout = -1;
	return FALSE;
}
static gboolean imquic_network_source_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	imquic_network_source *ns = (imquic_network_source *)source;
	/* Receive the packet */
	imquic_network_endpoint_receive(ns->ne);
	return G_SOURCE_CONTINUE;
}
static void imquic_network_source_finalize(GSource *source) {
	imquic_network_source *ns = (imquic_network_source *)source;
	if(ns && ns->ne) {
		if(ns->ne->source)
			ns->ne->source = NULL;
		imquic_network_endpoint_destroy(ns->ne);
		ns->ne = NULL;
	}
}
static GSourceFuncs imquic_network_source_funcs = {
	imquic_network_source_prepare,
	NULL,
	imquic_network_source_dispatch,
	imquic_network_source_finalize,
	NULL, NULL
};

/* Connection events */
typedef struct imquic_connection_source {
	imquic_source parent;
	imquic_connection *conn;
	GDestroyNotify destroy;
} imquic_connection_source;
static gboolean imquic_connection_source_prepare(GSource *source, gint *timeout) {
	imquic_connection_source *cs = (imquic_connection_source *)source;
	return g_atomic_int_get(&cs->conn->wakeup);
}
static gboolean imquic_connection_source_dispatch(GSource *source, GSourceFunc callback, gpointer user_data) {
	imquic_connection_source *cs = (imquic_connection_source *)source;
	return imquic_handle_event(cs->conn);
}
static void imquic_connection_source_finalize(GSource *source) {
	imquic_connection_source *cs = (imquic_connection_source *)source;
	imquic_refcount_decrease(&cs->conn->ref);
}
static GSourceFuncs imquic_connection_source_funcs = {
	imquic_connection_source_prepare,
	NULL,	/* We don't need check */
	imquic_connection_source_dispatch,
	imquic_connection_source_finalize,
	NULL, NULL
};

/* Initialize the event loop */
int imquic_loop_init(void) {
	/* Initialize main context and loop */
	ctx = g_main_context_new();
	loop = g_main_loop_new(ctx, FALSE);
	/* Start the thread that will handle the loop */
	GError *error = NULL;
	thread = g_thread_try_new("imquic-loop", imquic_loop_thread, NULL, &error);
	if(error != NULL) {
		/* We show the error but it's not fatal */
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Got error %d (%s) trying to launch the event loop...\n",
			error->code, error->message ? error->message : "??");
		g_error_free(error);
		return -1;
	}
	while(!g_atomic_int_get(&loop_started))
		g_usleep(5000);
	/* Done */
	return 0;
}

void imquic_loop_wakeup(void) {
	g_main_context_wakeup(ctx);
}

void imquic_loop_deinit(void) {
	if(loop != NULL)
		g_main_loop_quit(loop);
	if(thread != NULL)
		g_thread_join(thread);
}

/* Helpers to add events to the loop */
imquic_source *imquic_loop_poll_endpoint(void *e) {
	imquic_network_source *ns = (imquic_network_source *)g_source_new(&imquic_network_source_funcs, sizeof(imquic_network_source));
	imquic_network_endpoint *ne = (imquic_network_endpoint *)e;
	ns->ne = ne;
	ne->source = ns;
	g_source_set_priority((GSource *)ns, G_PRIORITY_DEFAULT);
	g_source_add_unix_fd((GSource *)ns, ne->fd, G_IO_IN | G_IO_ERR);
	g_source_attach((GSource *)ns, ctx);
	return (imquic_source *)ns;
}

imquic_source *imquic_loop_poll_connection(void *c) {
	imquic_connection_source *cs = (imquic_connection_source *)g_source_new(&imquic_connection_source_funcs, sizeof(imquic_connection_source));
	imquic_connection *conn = (imquic_connection *)c;
	char name[255], temp[41];
	const char *alpn = conn->socket ? conn->socket->alpn : "??";
	g_snprintf(name, sizeof(name), "%s-%s", alpn, imquic_connection_id_str(&conn->local_cid, temp, sizeof(temp)));
	g_source_set_name((GSource *)cs, name);
	cs->conn = conn;
	imquic_refcount_increase(&cs->conn->ref);
	g_source_set_priority((GSource *)cs, G_PRIORITY_DEFAULT);
	g_source_attach((GSource *)cs, ctx);
	return (imquic_source *)cs;
}

imquic_source *imquic_loop_add_timer(guint ms, GSourceFunc func, gpointer data) {
	imquic_source *timer = (imquic_source *)g_timeout_source_new(ms);
	g_source_set_callback((GSource *)timer, func, data, NULL);
	g_source_attach((GSource *)timer, ctx);
	g_source_unref((GSource *)timer);
	return timer;
}
