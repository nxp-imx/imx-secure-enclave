/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#include "internal/prime_service.h"
#include "mu_regs.h"
#include "uio.h"

static struct uio_prime_mu g_prime_mu;

static int match_prime_dev_name(const char *uio_path, const char *uio_name)
{
	char tmp[ARR_LEN] = {0};
	ssize_t bytes;
	int fd;

	fd = open(uio_path, O_RDONLY);
	if (fd < 0)
		return errno;

	bytes = read(fd, tmp, sizeof(tmp) - 1);
	if (bytes <= 0) {
		close(fd);
		return errno;
	}
	tmp[bytes] = '\0';

	if (!strstr(tmp, uio_name)) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int read_prime_uio_minor(void)
{
	DIR *dp = NULL;
	const char *substring = "uio";
	struct dirent *entry;
	int uio_minor_num = -1;
	int ret;

	dp = opendir(UIO_DIR_PATH);
	if (!dp) {
		perror("Could not open uio directory");
		return -1;
	}

	while ((entry = readdir(dp))) {
		if (!strncmp(entry->d_name, ".", 1) ||
		    !strncmp(entry->d_name, "..", 2) ||
		    !strstr(entry->d_name, substring))
			continue;

		char uio_path[MAX_ARR_LEN] = {0};

		/* create path /sys/class/uio/uio<n>/name */
		snprintf(uio_path, sizeof(uio_path), "%s/%s/%s",
			 UIO_DIR_PATH, entry->d_name, "name");

		/* check if uio path has driver name as 'PRIME UIO' */
		ret = match_prime_dev_name(uio_path, PRIME_UIO_NAME);
		if (ret) {
			uio_minor_num = -1;
			continue;
		}

		/* match found, read number following substring 'uio' */
		ret = sscanf(entry->d_name + strlen(substring),
			     "%d", &uio_minor_num);
		if (ret <= 0) {
			printf("Error: EOF or No field assigned\n");
			uio_minor_num = -1;
		}

		break;
	}

	if (uio_minor_num == -1)
		printf("Error: PRIME UIO Device not found\n");

	closedir(dp);
	return uio_minor_num;
}

static int read_val(const char *path, long *val)
{
	char tmp[ARR_LEN] = {0};
	ssize_t bytes;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return errno;

	bytes = read(fd, tmp, sizeof(tmp) - 1);
	if (bytes <= 0) {
		close(fd);
		return errno;
	}
	tmp[bytes] = '\0';

	*val = strtol(tmp, NULL, 16);

	close(fd);
	return 0;
}

static int read_prime_uio_map(int uio_minor,
			      int map_index,
			      const char *str,
			      long *out)
{
	char path[ARR_LEN] = {0};

	snprintf(path, sizeof(path), "%s/uio%d/maps/map%d/%s",
		 UIO_DIR_PATH, uio_minor, map_index, str);

	return read_val(path, out);
}

int map_uio_memory(uint8_t uio_id, long *size, uint64_t *addr)
{
	int uio_minor;

	/* read uio number, generally 0 */
	uio_minor  = read_prime_uio_minor();
	if (uio_minor < 0)
		return -1;

	/* read /sys/class/uio/uio0/maps/map(uio_id)/size */
	if (read_prime_uio_map(uio_minor,
			       uio_id,
			       "size", size)) {
		perror("uio prime read: mu map size");
		return -1;
	}

	/* read /sys/class/uio/uio0/maps/map(uio_id)/addr */
	if (read_prime_uio_map(uio_minor,
			       uio_id,
			       "addr", addr)) {
		perror("uio prime read: mu map addr");
		return -1;
	}

	return uio_minor;
}

struct uio_prime_mu *prime_mu_open(void)
{
	struct uio_prime_mu *prime_mu = &g_prime_mu;
	char path[ARR_LEN] = {0};
	void *map;
	uint64_t addr;
	int uio_minor;

	uio_minor = map_uio_memory(MU_MAP_OFFSET, &prime_mu->size, &addr);
	if (uio_minor < 0)
		return NULL;

	/* create path /dev/uio<n> */
	snprintf(path, sizeof(path), "%s%d",
		 UIO_DEV_PATH, uio_minor);

	/* open uio device */
	prime_mu->fd = open(path, O_RDWR | O_SYNC);
	if (prime_mu->fd < 0) {
		perror("uio prime open");
		return NULL;
	}

	/* map the uio memory */
	map = mmap(NULL, prime_mu->size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, prime_mu->fd, 0);
	if (map == MAP_FAILED) {
		perror("uio prime mu mmap");
		close(prime_mu->fd);
		return NULL;
	}

	/* store MU base address and MU buffer */
	prime_mu->base = map;
	prime_mu->mu_buf = (uint8_t *)prime_mu->base + MU_BUF_OFFSET;

	/* Initialize MU */
	imx_mu_init(prime_mu->base);

	return prime_mu;
}

int prime_mu_close(int fd)
{
	struct uio_prime_mu *prime_mu = NULL;
	int ret;

	if (fd == g_prime_mu.fd)
		prime_mu = &g_prime_mu;

	if (!prime_mu) {
		printf("MU not available for fd = %d\n", fd);
		return -1;
	}

	ret = munmap(prime_mu->base, prime_mu->size);
	if (ret) {
		perror("uio prime unmap");
		return errno;
	}

	close(fd);

	return 0;
}

int v2x_prime_mmap(void)
{
	struct uio_prime_mu *prime_mu = &g_prime_mu;
	struct atu_resv_mem_info mem_info = {0};
	int fd;
	int ret;

	// Open the V2X Prime device
	fd = open(V2X_PRIME_DEVICE, O_RDWR);
	if (fd < 0) {
		printf("Prime Library: Failed to open %s\n", V2X_PRIME_DEVICE);
		return -1;
	}

	// Make v2x_prime_get_mem_info ioctl call
	ret = ioctl(fd, ATU_GET_RESV_MEM_INFO, &mem_info);
	if (ret < 0) {
		printf("Prime Library: ATU_GET_RESV_MEM_INFO ioctl failed\n");
		close(fd);
		return -1;
	}

	// Store memory information
	prime_mu->phys_addr = mem_info.phys_addr;

	return 0;
}

void v2x_prime_munmap(void)
{
	struct uio_prime_mu *prime_mu = &g_prime_mu;
	uint8_t index;
	prime_service_t handle;

	for (index = 0; index < PRIME_MAX_SESSIONS_PER_PROCESS; index++) {
		handle = g_session[index];
		if (!handle.hdl)
			continue;

		prime_close_service(handle.hdl);
	}
}
