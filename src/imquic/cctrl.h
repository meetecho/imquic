/*! \file   cctrl.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  QUIC congestion control abstraction (headers)
 * \details Abstraction of QUIC congestion control, providing the
 * necessary resources and functions/callbacks to implement a specific
 * congestion control algorithm (e.g., NewReno or BBRv2).
 *
 * \ingroup Core
 *
 * \page Congestion Control
 *
 * The library comes with pluggable congestion control algorithms, that
 * can be configured when creating a new server or client. Specifically,
 * passing the name of an algorithm via the \c IMQUIC_CONFIG_CONGESTION_CONTROL
 * configuration property will instruct the QUIC stack to use one algorithm
 * over the other. At the time of writing, the library itself only provides
 * two algorithms: one is "NewReno" (as specified in Appendix B of RFC 9002)
 * and one is a fake algorithm that simply disables congestion control for
 * a connection (and so only meant for local testing).
 *
 * The \c IMQUIC_CONFIG_CONGESTION_CONTROL configuration property expects
 * a string. The stack defines a couple of macros to quickly identify the
 * supported algorithms, namely \c IMQUIC_CONGESTION_CONTROL_NEWRENO for
 * NewReno ("NewReno") and \c IMQUIC_CONGESTION_CONTROL_NONE for the fake
 * algorithm ("no-congestion-control").
 *
 * The library also provides a way for you to provide your own congestion
 * control algorithm, by exposing a way for you to register a new one
 * that the library can identify by name.
 *
 */

#ifndef IMQUIC_CONGESTION_CONTROL_H
#define IMQUIC_CONGESTION_CONTROL_H

#include <stddef.h>

#include <glib.h>

/*! \brief Non-action congestion controller (for testing only) */
#define IMQUIC_CONGESTION_CONTROL_NONE		"no-congestion-control"
/*! \brief NewReno (based on Appendix B in RFC 9002) */
#define IMQUIC_CONGESTION_CONTROL_NEWRENO	"NewReno"

/** @name Registering new congestion controller algorhitms
 */
///@{
/*! \brief Packet info for congestion control */
typedef struct imquic_congestion_control_packet {
	/*! \brief When the packet was originally sent */
	int64_t sent_time;
	/*! \brief Size of the packet */
	size_t pkt_size;
	/*! \brief Whether this is the first packet in a list (e.g., for acket/lost) */
	gboolean first;
	/*! \brief Whether this is the last packet in a list (e.g., for acket/lost) */
	gboolean last;
	/*! \brief First RTT sample, if any */
	int64_t first_rtt_sample;
} imquic_congestion_control_packet;

/*! \brief QUIC Congestion Control instance abstraction */
typedef struct imquic_congestion_control {
	/*! \brief Check if a packet of a specific size can be sent */
	gboolean (* can_send)(struct imquic_congestion_control *cc, size_t pkt_size);
	/*! \brief A packet has been sent */
	void (* packet_sent)(struct imquic_congestion_control *cc, imquic_congestion_control_packet *pkt);
	/*! \brief A packet has been acked */
	void (* packet_acked)(struct imquic_congestion_control *cc, imquic_congestion_control_packet *pkt);
	/*! \brief A packet has been lost */
	void (* packet_lost)(struct imquic_congestion_control *cc, imquic_congestion_control_packet *pkt);
	/*! \brief A packet has been discarded */
	void (* packet_discarded)(struct imquic_congestion_control *cc, imquic_congestion_control_packet *pkt);
	/*! \brief The connection is over, resources must be freed */
	void (* destroy)(struct imquic_congestion_control *cc);
} imquic_congestion_control;

/*! \brief Register a new QUIC Congestion Control algorithm
 * @param name Unique name to identify the algorithm in the library
 * @param create_instance Pointer to function to use to create a new instance of the algorithm
 * @returns TRUE if the algorithm was registered, FALSE otherwise */
gboolean imquic_congestion_control_register(const char *name,
	imquic_congestion_control *(* create_instance)(size_t max_datagram_size));
///@}

#endif
