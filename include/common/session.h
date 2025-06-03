// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
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

#define HSM1	(0x0u)
//!< HSM1 channel on SE, best effort high priority.
#define HSM2	(0x1u)
//!< HSM2 channel on SE, best effort high priority.
#define V2X_SG0 (0x50u)
//!< SG0 channel on V2X, low latency high priority.
#define V2X_SG1 (0x51u)
//!< SG1 channel on V2X, low latency low priority.
#define V2X_SHE (0x48u)
//!< SHE channel on V2X, low latency  high priority.
#define V2X_SHE1 (0x49u)
//!< SHE1 channel on V2X, low latency  high priority.
#define SHE1	(0x08u)
//!< SHE channel on SE,  best effort high priority.
#define V2X_SV0 (0x58u)
//!< SV0 channel on V2X, low latency high priority.
#define V2X_SV1 (0x59u)
//!< SV1 channel on V2X, low latency low priority.
#define HSM_NVM	(0x80u)
//!< HSM NVM channel on SE.
#define SHE_NVM	(0x88u)
//!< SHE NVM channel on SE.
#define V2X_SHE_NVM (0xC8u)
//!< SHE NVM channel on V2X.
#define V2X_SHE1_NVM (0xC9u)
//!< SHE1 NVM channel on V2X.
#define V2X_HSM_NVM (0xD0u)
//!< V2X HSM NVM channel run on SG0.
#define V2X_SHE_DEBUG_MU_NVM (0xE0u)
//!< V2X SHE NVM channel on DEBUG MU.

/** @} end of session group */

/*
 * bit < 0 - 2 > gives the INSTANCE ID
 */
#define INSTANCE_ID_MASK	0x07
#define INSTANCE_0	0x0
#define INSTANCE_1	0x1
#define INSTANCE_2	0x2
#define INSTANCE_3	0x3
#define INSTANCE_4	0x4
#define INSTANCE_5	0x5
#define INSTANCE_6	0x6
#define INSTANCE_7	0x7

/*
 * bit < 3 - 5 > gives the MU TYPE
 */
#define MU_TYPE_MASK	0x38
#define MU_HSM		0x00
#define MU_SHE		0x01
#define MU_SG		0x02
#define MU_SV		0x03
#define MU_DEBUG	0x04

#define MU_STR_HSM	"hsm"
#define MU_STR_SHE	"she"
#define MU_STR_SG	"sg"
#define MU_STR_SV	"sv"
#define MU_STR_DEBUG	"dbg"

/*
 * bit < 6 > gives the V2X information
 */
#define V2X_MASK	0x40

/*
 * bit < 7 > gives the NVM Mask
 */
#define NVM_MASK	0x80

#endif
