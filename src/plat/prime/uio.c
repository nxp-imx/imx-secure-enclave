/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "mu_regs.h"
#include "uio.h"

#define UIO_DIR_PATH        "/sys/class/uio"
#define UIO_DEV_PATH	    "/dev/uio"
#define PRIME_UIO_NAME	    "FCE UIO"
#define UIO_MAP_PATH	    "maps/map"
#define MU_BUF_OFFSET	    0x8000
#define DMA_MEM_SZ_MAX      0x10000000
#define DMA_MEM_START_ADDR  0xa4220000
#define MU_MAP_OFFSET		0
#define RESERVED_MAP_OFFSET	1

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

		/* check if uio path has driver name as 'FCE UIO' */
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

struct uio_prime_mu* prime_mu_open(void)
{
	struct uio_prime_mu *prime_mu = &g_prime_mu;
	char path[ARR_LEN] = {0};
	int uio_minor;
	void *map;

	/* read uio number, generally 0 */
	uio_minor  = read_prime_uio_minor();
	if (uio_minor < 0)
		return NULL;

	/* read /sys/class/uio/uio0/maps/map0/size */
	if (read_prime_uio_map(uio_minor,
			       MU_MAP_OFFSET,
			       "size", &prime_mu->size)) {
		perror("uio prime read: mu map size");
		return NULL;
	}

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
	off_t phys_addr;
	size_t size;
	int ret;

	/* read /sys/class/uio/uio0/maps/map1/addr */
	if (read_prime_uio_map(prime_mu->uio_minor,
			       RESERVED_MAP_OFFSET,
			       "addr", &phys_addr)) {
		perror("uio prime read: reserved map addr");
		return -1;
	}

	/* read /sys/class/uio/uio0/maps/map1/size */
	if (read_prime_uio_map(prime_mu->uio_minor,
			       RESERVED_MAP_OFFSET,
			       "size", &size)) {
		perror("uio prime read: reserved map size");
		return -1;
	}

	prime_mu->iomem.phys_addr = phys_addr;
	prime_mu->iomem.size = size;
	prime_mu->iomem.pos  = 0;

	prime_mu->iomem.virt_addr = mmap(NULL, prime_mu->iomem.size,
					 PROT_READ | PROT_WRITE, MAP_SHARED,
					 prime_mu->fd,
					 1 * sysconf(_SC_PAGESIZE));
	if (prime_mu->iomem.virt_addr == MAP_FAILED) {
		perror("uio prime reserved mmap");
		return -1;
	}

	return 0;
}

void v2x_prime_munmap(void)
{
	struct uio_prime_mu *prime_mu = &g_prime_mu;

	munmap((void *)prime_mu->iomem.virt_addr, prime_mu->iomem.size);
}
