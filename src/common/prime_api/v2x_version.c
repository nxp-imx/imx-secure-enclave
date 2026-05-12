/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <string.h>

#include "internal/v2x_version.h"

#include "prime_ioctl.h"

prime_err_t get_v2x_version(v2x_version_t *args)
{
	struct prime_ioctl_get_v2x_version v2x_version;
	int error;

	error = prime_ioctl_get_v2x_version(&v2x_version);

	if (!error)
		memcpy(args, &v2x_version, sizeof(struct prime_ioctl_get_v2x_version));

	return error;
}
