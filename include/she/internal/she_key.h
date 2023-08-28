// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_KEY_H
#define SHE_KEY_H

/**
 * SHE keys are 128 bits (16 bytes) long.
 */
#define SHE_KEY_SIZE_IN_BYTES	16u

#define M1_M3_M5_KEY_SIZE_IN_WORDS	(SHE_KEY_SIZE_IN_BYTES >> 2)
#define M2_M4_KEY_SIZE_IN_WORDS		(SHE_KEY_SIZE_IN_BYTES >> 1)

/**
 * Identifiers for SHE keys.
 * Refer SHE specification for more information.
 */
#define SHE_KEY_1	(0x04)
#define SHE_KEY_2	(0x05)
#define SHE_KEY_3	(0x06)
#define SHE_KEY_4	(0x07)
#define SHE_KEY_5	(0x08)
#define SHE_KEY_6	(0x09)
#define SHE_KEY_7	(0x0a)
#define SHE_KEY_8	(0x0b)
#define SHE_KEY_9	(0x0c)
#define SHE_KEY_10	(0x0d)
#define SHE_RAM_KEY	(0x0e)

#endif
