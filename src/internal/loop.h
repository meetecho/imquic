/*! \file   loop.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Event loop (headers)
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

#ifndef IMQUIC_LOOP_H
#define IMQUIC_LOOP_H

#include <stdint.h>

#include <glib.h>

#include "network.h"

/*! \brief Initialize the event loop */
int imquic_loop_init(void);
/*! \brief Helper method to wake the event loop, in case it's waiting
 * for something and we need to refresh the list of events to monitor */
void imquic_loop_wakeup(void);
/*! \brief Uninitialize the event loop */
void imquic_loop_deinit(void);

/*! \brief Event source base */
typedef struct imquic_source {
	/*! \brief All event sources are actually extensions of the GLib \c GSource */
	GSource parent;
} imquic_source;

/*! \brief Events meant for connections */
typedef struct imquic_connection_event {
	/* \todo Refactor the event loop */
} imquic_connection_event;

/** @name Adding sources to the loop
 */
///@{
/*! \brief Monitor an endpoint socket as part of the loop
 * @param e Opaque pointer to a imquic_network_endpoint instance
 * @returns A pointer to the imquic_source, if successful, or NULL otherwise */
imquic_source *imquic_loop_poll_endpoint(void *e);
/*! \brief Monitor events associated to a connection in the core as part of the loop
 * @param c Opaque pointer to a imquic_connection instance
 * @returns A pointer to the imquic_source, if successful, or NULL otherwise */
imquic_source *imquic_loop_poll_connection(void *c);
/*! \brief Helper method to add a timed source to the loop, to fire
 * the provided callback every tot milliseconds and passing the provided data.
 * @param ms Call the callback every tot milliseconds
 * @param func Callback to invoke when the regular timer fires
 * @param data Optional user data to pass to the callback function, for correlation purposes
 * @returns A pointer to the imquic_source, if successful, or NULL otherwise */
imquic_source *imquic_loop_add_timer(guint ms, GSourceFunc func, gpointer data);
///@}

#endif
