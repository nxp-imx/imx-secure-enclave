// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef PRIME_IOCTL_H
#define PRIME_IOCTL_H

#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define DEVICE_PATH_V2X_DEBUG	"/dev/v2x_dbg0_ch0"

/* IOCTL definitions. */
struct prime_ioctl_get_v2x_version {
	uint8_t major;
	uint8_t minor;
	uint8_t patch;
	uint32_t commit_id;
};

#define PRIME_IOCTL			0x0A /* like MISC_MAJOR. */
#define PRIME_IOCTL_GET_V2X_VERSION	_IOR(PRIME_IOCTL, 0x09, \
					struct prime_ioctl_get_v2x_version)

int prime_ioctl_get_v2x_version(struct prime_ioctl_get_v2x_version *v2x_version);

#endif
