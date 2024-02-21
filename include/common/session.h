// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

/**
 *  @defgroup group1 Session
 *  @{
 */

/**
 * Structure detailing the open session operation member arguments
 */
typedef struct {
	uint32_t session_hdl;
	//!< Session handle.
	uint8_t mu_type;
	//!< MU with associated functionality on which session will be opened
	uint8_t interrupt_idx;
	//!< Interrupt number of the MU used to indicate data availability.
#ifndef PSA_COMPLIANT
	uint8_t mu_id;
	//!< index of the MU as per PLAT point of view.
	uint8_t tz;
	//!< Trust Zone (secure) flag - Reflects the XRDC configuration on the MU
	uint8_t did;
	//!< DID associated with the MU in the XRDC configuration.
#endif
} open_session_args_t;

/** @} end of session group */

#define HSM1	(0x1u)
//!< HSM1 channel on SE, best effort high priority.
#define HSM2	(0x2u)
//!< HSM2 channel on SE, best effort high priority.
#define HSM_NVM	(0x12u)
//!< HSM NVM channel on SE.
#define V2X_SG0 (0x3u)
//!< SG0 channel on V2X, low latency high priority.
#define V2X_SG1 (0x4u)
//!< SG1 channel on V2X, low latency low priority.
#define V2X_SHE (0x5u)
//!< SHE channel on V2X, low latency  high priority.
#define SHE1	(0x6u)
//!< SHE channel on SE,  best effort high priority.
#define SHE_NVM	(0x13u)
//!< SHE NVM channel on SE.
#define V2X_SHE_NVM (0x14u)
//!< SHE NVM channel on V2X.
#define V2X_SV0 (0x7u)
//!< SV0 channel on V2X, low latency high priority.
#define V2X_SV1 (0x8u)
//!< SV1 channel on V2X, low latency low priority.
#define V2X_HSM_NVM (0x15u)
//!< V2X NVM channel on V2X.

#endif
