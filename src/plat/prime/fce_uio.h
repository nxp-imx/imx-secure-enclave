/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef FCE_UIO_H
#define FCE_UIO_H

#include <sys/types.h>
#include <stdint.h>

#define MAX_ARR_LEN	512
#define ARR_LEN	64

struct io_mem {
	uint8_t *virt_addr;
	off_t phys_addr;
	size_t pos;
	size_t size;
};

struct uio_fce_mu {
	int fd;
	void *base;
	long size;
	uint8_t *mu_buf;
	struct io_mem iomem;
};

struct uio_fce_mu *fce_mu_open(void);
int fce_mu_close(int fd);

int v2x_prime_mmap(void);
void v2x_prime_munmap(void);

#endif /* FCE_UIO_H */
