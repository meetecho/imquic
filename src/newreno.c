/*! \file   newreno.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  NewReno Congestion Control
 * \details Implementation of NewReno as a congestion control algorithm,
 * extending \ref imquic_congestion_control and based on the reference
 * implementation available in RFC 9002
 * (https://datatracker.ietf.org/doc/html/rfc9002#section-appendix.b).
 *
 * \ingroup Core
 */

#include "internal/newreno.h"
#include "imquic/debug.h"

/* Callbacks and congestion management */
static gboolean imquic_congestion_control_newreno_can_send(imquic_congestion_control *cc, size_t pkt_size) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL)
		return FALSE;
	/* Check if this would exceed the congestion window */
	return ((nr->bytes_in_flight + pkt_size) <= nr->congestion_window);
}

static void imquic_congestion_control_newreno_packet_sent(imquic_congestion_control *cc, imquic_congestion_control_packet *pkt) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL || pkt == NULL)
		return;
	/* https://datatracker.ietf.org/doc/html/rfc9002#section-b.4 */
	nr->bytes_in_flight += pkt->pkt_size;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][packet_sent] bytes_in_flight=%"SCNu64" (cw=%"SCNu64")\n",
		nr->bytes_in_flight, nr->congestion_window);
}

static void imquic_congestion_control_newreno_packet_acked(imquic_congestion_control *cc, imquic_congestion_control_packet *pkt) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL || pkt == NULL)
		return;
	/* https://datatracker.ietf.org/doc/html/rfc9002#section-b.5 */
	if(nr->bytes_in_flight >= pkt->pkt_size)
		nr->bytes_in_flight -= pkt->pkt_size;
	else
		nr->bytes_in_flight -= 0;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][packet_acked] bytes_in_flight=%"SCNu64"\n", nr->bytes_in_flight);
	/* TODO IsAppOrFlowControlLimited() */
	if(pkt->sent_time <= nr->congestion_recovery_start_time) {
		/* Don't increase congestion window in recovery period */
		return;
	}
	if(nr->congestion_window < nr->slow_start_threshold) {
		/* Slow start */
		nr->congestion_window += pkt->pkt_size;
	} else {
		/* Congestion avoidance */
		float increment = (float)(nr->max_datagram_size) * (float)(pkt->pkt_size);
		increment = increment / (float)(nr->congestion_window);
		nr->congestion_window += (uint64_t)increment;
	}
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][packet_acked] congestion_window=%"SCNu64"\n", nr->congestion_window);
}

static void imquic_congestion_control_newreno_congestion_event(imquic_congestion_control_newreno *nr) {
	if(nr == NULL || nr->sent_time_of_last_loss == 0)
		return;
	/* https://datatracker.ietf.org/doc/html/rfc9002#section-b.6 */
	if(nr->sent_time_of_last_loss <= nr->congestion_recovery_start_time) {
		/* Already in a recovery period, ignore */
		nr->sent_time_of_last_loss = 0;
		return;
	}
	/* Enter recovery period */
	nr->congestion_recovery_start_time = g_get_monotonic_time();
	float sst = nr->loss_reduction_factor * (float)(nr->congestion_window);
	nr->slow_start_threshold = sst;
	if(nr->slow_start_threshold > nr->congestion_window)
		nr->congestion_window = nr->slow_start_threshold;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][congestion_event] congestion_window=%"SCNu64"\n", nr->congestion_window);
	/* TODO */
	nr->sent_time_of_last_loss = 0;
}

static void imquic_congestion_control_newreno_packet_lost(imquic_congestion_control *cc, imquic_congestion_control_packet *pkt) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL || pkt == NULL)
		return;
	/* https://datatracker.ietf.org/doc/html/rfc9002#section-b.8 */
	if(pkt->first) {
		nr->sent_time_of_last_loss = 0;
		nr->persistent_congestion = FALSE;
	}
	if(nr->bytes_in_flight >= pkt->pkt_size)
		nr->bytes_in_flight -= pkt->pkt_size;
	else
		nr->bytes_in_flight -= 0;
	IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][packet_lost] bytes_in_flight=%"SCNu64"\n", nr->bytes_in_flight);
	if(pkt->sent_time > nr->sent_time_of_last_loss) {
		nr->sent_time_of_last_loss = pkt->sent_time;
		if(pkt->first_rtt_sample > 0 && pkt->sent_time > pkt->first_rtt_sample)
			nr->persistent_congestion = TRUE;
	}
	if(!pkt->last)
		return;
	/* Check if we should trigger a congestion event */
	if(nr->sent_time_of_last_loss > 0)
		imquic_congestion_control_newreno_congestion_event(nr);
	/* Check if we should update the congestion window */
	if(nr->persistent_congestion) {
		nr->congestion_window = nr->minimum_window;
		nr->congestion_recovery_start_time = 0;
		IMQUIC_LOG(IMQUIC_LOG_INFO, "[NewReno][packet_lost] congestion_window=%"SCNu64"\n", nr->congestion_window);
	}
}

static void imquic_congestion_control_newreno_packet_discarded(imquic_congestion_control *cc, imquic_congestion_control_packet *pkt) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL || pkt == NULL)
		return;
	/* https://datatracker.ietf.org/doc/html/rfc9002#section-b.9 */
	if(nr->bytes_in_flight >= pkt->pkt_size)
		nr->bytes_in_flight -= pkt->pkt_size;
	else
		nr->bytes_in_flight -= 0;
}

static void imquic_congestion_control_newreno_destroy(imquic_congestion_control *cc) {
	imquic_congestion_control_newreno *nr = (imquic_congestion_control_newreno *)cc;
	if(nr == NULL)
		return;
	g_free(nr);
}

/* Constructor */
imquic_congestion_control *imquic_congestion_control_newreno_create(size_t max_datagram_size) {
	imquic_congestion_control_newreno *nr = g_malloc0(sizeof(imquic_congestion_control_newreno));
	/* Initialize the callbacks */
	nr->base.can_send = imquic_congestion_control_newreno_can_send;
	nr->base.packet_sent = imquic_congestion_control_newreno_packet_sent;
	nr->base.packet_acked = imquic_congestion_control_newreno_packet_acked;
	nr->base.packet_lost = imquic_congestion_control_newreno_packet_lost;
	nr->base.packet_discarded = imquic_congestion_control_newreno_packet_discarded;
	nr->base.destroy = imquic_congestion_control_newreno_destroy;
	/* Initialize NewReno as per RFC 9002
	 * https://datatracker.ietf.org/doc/html/rfc9002#section-b.3 */
	nr->max_datagram_size = max_datagram_size;
	nr->loss_reduction_factor = 0.5;
	nr->persistent_congestion_threshold = 3;
	nr->congestion_window = nr->initial_window = 10 * (uint64_t)nr->max_datagram_size;
	nr->minimum_window = 2 * (uint64_t)nr->max_datagram_size;
	nr->slow_start_threshold = UINT64_MAX;
	nr->congestion_recovery_start_time = 0;
	nr->bytes_in_flight = 0;
	return (imquic_congestion_control *)nr;
}
