/*! \file   ccnone.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Fake Congestion Control
 * \details Implementation of a fake congestion control algorithm, which
 * simply disables congestion control entirely. Only meant to be used
 * for testing purposes.
 *
 * \ingroup Core
 */

#include "internal/ccnone.h"
#include "imquic/debug.h"

/* Callbacks */
static gboolean imquic_congestion_control_ccnone_can_send(imquic_congestion_control *cc, size_t pkt_size) {
	/* Fake congestion controller, always return TRUE */
	return TRUE;
}

static void imquic_congestion_control_ccnone_destroy(imquic_congestion_control *cc) {
	g_free(cc);
}

/* Constructor */
imquic_congestion_control *imquic_congestion_control_ccnone_create(size_t max_datagram_size) {
	imquic_congestion_control *nocc = g_malloc0(sizeof(imquic_congestion_control));
	/* Initialize the few callbacks we need (not all) */
	nocc->can_send = imquic_congestion_control_ccnone_can_send;
	nocc->destroy = imquic_congestion_control_ccnone_destroy;
	return nocc;
}
