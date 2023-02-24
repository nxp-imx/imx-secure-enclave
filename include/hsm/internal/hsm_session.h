/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef HSM_SESSION_H
#define HSM_SESSION_H

#include "plat_os_abs.h"

#define MU_CONFIG(prio, op_mode) (((op_mode & HSM_OPEN_SESSION_LOW_LATENCY_MASK) != 0U  ? 4U : 0U)\
				| (prio == HSM_OPEN_SESSION_PRIORITY_HIGH               ? 2U : 0U)\
				| ((op_mode & HSM_OPEN_SESSION_NO_KEY_STORE_MASK) != 0U ? 1U : 0U))
#define MU_CONFIG_NB		(8)

static const uint32_t mu_table[MU_CONFIG_NB] = {
	MU_CHANNEL_PLAT_HSM,      // best_effort, low prio, with key store
	MU_CHANNEL_PLAT_HSM_2ND,  // best_effort, low prio, no key store
	MU_CHANNEL_UNDEF,         // best_effort, high prio, with key store
	MU_CHANNEL_UNDEF,         // best_effort, high prio, no key store
	MU_CHANNEL_V2X_SG1,       // low latency, low prio,  with key store
	MU_CHANNEL_V2X_SV1,       // low latency, low prio,  no key store
	MU_CHANNEL_V2X_SG0,       // low latency, high prio, with key store
	MU_CHANNEL_V2X_SV0,       // low latency, high prio, no key store
};

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
	uint8_t mu_id;
		//!< index of the MU as per PLAT point of view.
	uint8_t interrupt_idx;
		//!< Interrupt number of the MU used to indicate data availability.
	uint8_t tz;
		//!< indicate if current partition has TZ enabled.
	uint8_t did;
		//!< DID of the calling partition.
} open_session_args_t;
#define HSM_OPEN_SESSION_PRIORITY_LOW       (0x00U)
 //!< Low priority. default setting on platforms that doesn't support sessions priorities.
#define HSM_OPEN_SESSION_PRIORITY_HIGH      (0x01U)
 //!< High Priority session.
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
