/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
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
#include "fce_mu_regs.h"
#include "fce_uio.h"

#define UIO_DIR_PATH        "/sys/class/uio"
#define UIO_DEV_PATH	    "/dev/uio"
#define FCE_UIO_NAME	    "FCE UIO"
#define UIO_MAP_PATH	    "maps/map"
#define MU_BUF_OFFSET	    0x8000
#define DMA_MEM_SZ_MAX      0x10000000
#define DMA_MEM_START_ADDR  0xa4220000

static struct uio_fce_mu g_fce_mu;

static int
match_fce_dev_name(const char *uio_path, const char *uio_name)
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

static int
read_fce_uio_num(void)
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
		ret = match_fce_dev_name(uio_path, FCE_UIO_NAME);
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
		printf("Error: FCE UIO Device not found\n");

	closedir(dp);
	return uio_minor_num;
}

static int
read_val(const char *path, long *val)
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

struct uio_fce_mu *
fce_mu_open(void)
{
	struct uio_fce_mu *fce_mu = &g_fce_mu;
	char path[ARR_LEN] = {0};
	int uio_minor_num;
	void *map;
	int ret;

	/* read uio number, generally 0 */
	uio_minor_num  = read_fce_uio_num();
	if (uio_minor_num < 0)
		return NULL;

	/* create path /sys/class/uio/uio0/maps/map0/size */
	snprintf(path, sizeof(path), "%s/%s%d/%s%d/%s",
		 UIO_DIR_PATH, "uio", uio_minor_num,
		 UIO_MAP_PATH, uio_minor_num, "size");

	/* read the size */
	ret = read_val(path, &fce_mu->size);
	if (ret) {
		perror("uio fce read size");
		return NULL;
	}

	/* create path /dev/uio<n> */
	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s%d",
		 UIO_DEV_PATH, uio_minor_num);

	/* open uio device */
	fce_mu->fd = open(path, O_RDWR | O_SYNC);
	if (fce_mu->fd < 0) {
		perror("uio fce open");
		return NULL;
	}

	/* map the uio memory */
	map = mmap(NULL, fce_mu->size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fce_mu->fd, 0);
	if (map == MAP_FAILED) {
		perror("uio fce mmap");
		close(fce_mu->fd);
		return NULL;
	}

	/* store MU base address and MU buffer */
	fce_mu->base = map;
	fce_mu->mu_buf = (uint8_t *)fce_mu->base + MU_BUF_OFFSET;

	/* Initialize MU */
	imx_mu_init(fce_mu->base);

	return fce_mu;
}

int
fce_mu_close(int fd)
{
	struct uio_fce_mu *fce_mu = NULL;
	int ret;

	if (fd == g_fce_mu.fd)
		fce_mu = &g_fce_mu;

	if (!fce_mu) {
		printf("MU not available for fd = %d\n", fd);
		return -1;
	}

	ret = munmap(fce_mu->base, fce_mu->size);
	if (ret) {
		perror("uio fce unmap");
		return errno;
	}

	close(fd);

	return 0;
}

int v2x_prime_mmap(void)
{
	struct uio_fce_mu *fce_mu = &g_fce_mu;
	int fd;

	fce_mu->iomem.phys_addr = 0xa4220000;
	fce_mu->iomem.size = DMA_MEM_SZ_MAX;
	fce_mu->iomem.pos = 0;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open /dev/mem");
		return -1;
	}

	fce_mu->iomem.virt_addr = mmap(NULL, fce_mu->iomem.size,
				       PROT_READ | PROT_WRITE, MAP_SHARED,
				       fd, fce_mu->iomem.phys_addr);
	if (fce_mu->iomem.virt_addr == MAP_FAILED) {
		perror("mmap physical memory");
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

void v2x_prime_munmap(void)
{
	struct uio_fce_mu *fce_mu = &g_fce_mu;

	munmap((void *)fce_mu->iomem.virt_addr, fce_mu->iomem.size);
}
