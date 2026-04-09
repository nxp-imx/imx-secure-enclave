/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <fcntl.h>
#include <unistd.h>
#include "prime_ioctl.h"

int prime_ioctl_get_v2x_version(struct prime_ioctl_get_v2x_version *v2x_version)
{
	int fd;
	int error;

	fd = open(DEVICE_PATH_V2X_DEBUG, O_RDONLY);
	if (fd < 0) {
		printf("Failed to open v2x debug mu\n");
		return -1;
	}

	error = ioctl(fd, PRIME_IOCTL_GET_V2X_VERSION, v2x_version);

	if (error)
		printf("Failed to get V2X Version\n");

	close(fd);

	return error;
}
