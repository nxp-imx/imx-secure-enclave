// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_SESSION_H
#define SHE_SESSION_H

#include <stdint.h>
#include "common/session.h"

/**
 *  @defgroup group1 Session
 *  @{
 */

#define SHE_OPEN_SESSION_PRIORITY_LOW       (0x00U)
//!< Low priority session, default setting on platforms that doesn't suppor\n sessions priorities.

#define SHE_OPEN_SESSION_PRIORITY_HIGH      (0x01U)
//!< High Priority session.

#define SHE_OPEN_SESSION_FIPS_MODE_MASK     BIT(0)
//!< Only FIPS certified operations authorized in this session.
#define SHE_OPEN_SESSION_EXCLUSIVE_MASK     BIT(1)
//!< No other SHE session will be authorized on the same security enclave.
#define SHE_OPEN_SESSION_LOW_LATENCY_MASK   BIT(3)
//!< Use a low latency SHE implementation.

#define SHE_OPEN_SESSION_NO_KEY_STORE_MASK  BIT(4)
//!< No key store will be attached to this session. May provide better\n performances on some operation depending on the implementation. Usage of\n the session will be restricted to operations that doesn't involve secret keys\n (e.g. random generation)

/** @} end of session group */
#endif
