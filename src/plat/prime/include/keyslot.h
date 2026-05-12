// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef KEYSLOT_H
#define KEYSLOT_H

#include <linux/ioctl.h>
#include <stdint.h>

#define KEYSLOT_NOT_AVAILABLE		0xFF

#define HMAC_KEYSLOT			0x1
#define AES_KEYSLOT			0x2

uint8_t get_keyslot(uint8_t keyslot_type);
void release_keyslot(uint64_t mask, uint8_t keyslot_type);

#endif /* KEYSLOT_H */
