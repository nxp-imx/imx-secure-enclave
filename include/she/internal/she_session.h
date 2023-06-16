// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_SESSION_H
#define SHE_SESSION_H

#include <stdint.h>

#define SAB_OPEN_SESSION_PRIORITY_LOW       (0x00U)
#define SAB_OPEN_SESSION_PRIORITY_HIGH      (0x01U)

#define SAB_OPEN_SESSION_FIPS_MODE_MASK     BIT(0)
#define SAB_OPEN_SESSION_EXCLUSIVE_MASK     BIT(1)
#define SAB_OPEN_SESSION_LOW_LATENCY_MASK   BIT(3)
#define SAB_OPEN_SESSION_NO_KEY_STORE_MASK  BIT(4)

#endif
