// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

/**
 * Structure detailing the open session operation member arguments
 */
typedef struct {
	uint32_t session_hdl;
	//!< Session handle.
	uint8_t session_priority;
	//!< Priority of the operations performed in this session.
	uint8_t operating_mode;
	//!< Options for the session to be opened (bitfield).
	uint8_t interrupt_idx;
	//!< Interrupt number of the MU used to indicate data availability.
#ifndef PSA_COMPLIANT
	uint8_t mu_id;
	//!< index of the MU as per PLAT point of view.
	uint8_t tz;
	//!< indicate if current partition has TZ enabled.
	uint8_t did;
	//!< DID of the calling partition.
#endif
} open_session_args_t;

#endif
