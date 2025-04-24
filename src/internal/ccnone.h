/*! \file   ccnone.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Fake Congestion Control (headers)
 * \details Implementation of a fake congestion control algorithm, which
 * simply disables congestion control entirely. Only meant to be used
 * for testing purposes.
 *
 * \ingroup Core
 */

#ifndef IMQUIC_CCONE_H
#define IMQUIC_CCNONE_H

#include "../imquic/cctrl.h"

#include <stdint.h>

/*! brief Constructor for a new no-congestion-control instance */
imquic_congestion_control *imquic_congestion_control_ccnone_create(size_t max_datagram_size);

#endif
