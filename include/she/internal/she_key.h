// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_KEY_H
#define SHE_KEY_H

/**
 * @defgroup group200 SHE keys
 * Identifiers for SHE keys.
 *
 * Refer SHE specification for more information.
 * @{
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

#define SHE_KEY_SIZE_IN_BYTES	16u
//!< SHE keys are 128 bits (16 bytes) long.

#define M1_M3_M5_KEY_SIZE_IN_WORDS	(SHE_KEY_SIZE_IN_BYTES >> 2)
//!< size of M1, M3 ad M5 in words.
#define M2_M4_KEY_SIZE_IN_WORDS		(SHE_KEY_SIZE_IN_BYTES >> 1)
//!< size of M2 ad M4 in words.

/** @} end of keys group */

/**
 * @defgroup group300 SHE+ key extension
 * Identifiers for the SHE key extension.
 *
 * There are 5 SHE key stores in i.MX95 and 1 SHE keystore in i.MX8DXL\n
 * Each key store contains:\n
 *	1 SECRET KEY      (id = 0x0)\n
 *	1 MASTER ECU KEY  (id = 0x1)\n
 *	1 BOOT MAC KEY    (id = 0x2)\n
 *	1 BOOT MAC        (id = 0x3)\n
 *	10 KEY SLOTS      (id = 0x04 to 0xD)\n
 *	40 extra KEY SLOTS(id = keyID | key_ext,\n - keyID from 0x04 to 0xD,\n - key_ext like below picture)\n
 *	1 RAM KEY (id = 0xE)
 *  @{
 */
#define SHE_KEY_DEFAULT (0x00)
//!< no key extension: keys from 0 to 10 as defined in SHE specification.
#define SHE_KEY_N_EXT_1 (0x10)
//!< keys 11 to 20.
#define SHE_KEY_N_EXT_2 (0x20)
//!< keys 21 to 30.
#define SHE_KEY_N_EXT_3 (0x30)
//!< keys 31 to 40.
#define SHE_KEY_N_EXT_4 (0x40)
//!< keys 41 to 50.
/** @} end of keys ext group */

#endif
