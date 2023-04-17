// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_SESSION_H
#define HSM_SESSION_H

#include <stdint.h>

/**
 *  @defgroup group1 Session
 *  @{
 */
typedef struct {
	uint32_t session_hdl;
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

/* Priority Flags */
#define HSM_OPEN_SESSION_PRIORITY_LOW       (0x00U)
 //!< Low priority. default setting on platforms that doesn't support sessions priorities.
#define HSM_OPEN_SESSION_PRIORITY_HIGH      (0x01U)
 //!< High Priority session.

/* Operating Mode */
#define HSM_OPEN_SESSION_FIPS_MODE_MASK     (1u << 0)
 //!< Only FIPS certified operations authorized in this session.
#define HSM_OPEN_SESSION_EXCLUSIVE_MASK     (1u << 1)
 //!< No other HSM session will be authorized on the same security enclave.
#define HSM_OPEN_SESSION_LOW_LATENCY_MASK   (1u << 3)
 //!< Use a low latency HSM implementation.
#define HSM_OPEN_SESSION_NO_KEY_STORE_MASK  (1u << 4)
 //!< No key store will be attached to this session. May provide better performances on some operation depending on the implementation. Usage of the session will be restricted to operations that doesn't involve secret keys (e.g. hash, signature verification, random generation).
#define HSM_OPEN_SESSION_RESERVED_MASK      ((1u << 2) | (1u << 5) | (1u << 6) | (1u << 7))
 //!< Bits reserved for future use. Should be set to 0.

/** @} end of session group */
#endif
