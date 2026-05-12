/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef UIO_H
#define UIO_H

#include <sys/types.h>
#include <stdint.h>

#include <internal/prime_handle.h>
#include "atu_ioctl.h"

#define MAX_ARR_LEN	512
#define ARR_LEN	64

#define UIO_DIR_PATH        "/sys/class/uio"
#define UIO_DEV_PATH	    "/dev/uio"
#define PRIME_UIO_NAME	    "PRIME UIO"
#define UIO_MAP_PATH	    "maps/map"
#define MU_BUF_OFFSET	    0x8000
#define MU_MAP_OFFSET		0
#define RESERVED_MAP_OFFSET	1

#define V2X_PRIME_DEVICE "/dev/prime"

#define PRIME_MAX_SESSIONS_PER_PROCESS		8

typedef struct prime_service {
	prime_hdl_t hdl;
	uint64_t hmac_keyslot_map;
	uint64_t aes_keyslot_map;
	uint64_t physical_addr;
	uint64_t size;
	uint32_t inbound_addr;
	void *mmap_addr;
	int fd;
} prime_service_t;

extern prime_service_t g_session[PRIME_MAX_SESSIONS_PER_PROCESS];

struct uio_prime_mu {
	int fd;
	int uio_minor;
	void *base;
	long size;
	uint8_t *mu_buf;
	off_t phys_addr;
};

struct uio_prime_mu *prime_mu_open(void);
int prime_mu_close(int fd);

int v2x_prime_mmap(void);
void v2x_prime_munmap(void);

void delete_prime_session(prime_service_t *s_ptr);
prime_service_t *add_prime_session(void);
prime_service_t *prime_session_to_ptr(prime_hdl_t hdl);
int map_uio_memory(uint8_t uio_id, long *size, uint64_t *addr);

#endif /* UIO_H */
