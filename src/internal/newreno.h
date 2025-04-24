/*! \file   newreno.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  NewReno Congestion Control (headers)
 * \details Implementation of NewReno as a congestion control algorithm,
 * extending \ref imquic_congestion_control and based on the reference
 * implementation available in RFC 9002
 * (https://datatracker.ietf.org/doc/html/rfc9002#section-appendix.b).
 *
 * \ingroup Core
 */

#ifndef IMQUIC_NEWRENO_H
#define IMQUIC_NEWRENO_H

#include "../imquic/cctrl.h"

#include <stdint.h>

/*! \brief NewReno Congestion Control */
typedef struct imquic_congestion_control_newreno {
	/*! \brief Congestion Control base */
	imquic_congestion_control base;
	/*! \brief Maximum payload size */
	size_t max_datagram_size;
	/*! \brief Loss reduction factor */
	float loss_reduction_factor;
	/*! \brief Persistent congestion threshold */
	uint8_t persistent_congestion_threshold;
	/*! \brief Congestion windows */
	uint64_t initial_window, minimum_window, congestion_window;
	/*! \brief Slow start threshold */
	uint64_t slow_start_threshold;
	/*! \brief Congestion recovery start time */
	int64_t congestion_recovery_start_time;
	/*! \brief Bytes in flight */
	uint64_t bytes_in_flight;
	/*! \brief Sent time of last loss */
	int64_t sent_time_of_last_loss;
	/*! \brief Whether lost packets triggered persistent congestion */
	gboolean persistent_congestion;
} imquic_congestion_control_newreno;

/*! brief Constructor for a new NewReno instance */
imquic_congestion_control *imquic_congestion_control_newreno_create(size_t max_datagram_size);

#endif
