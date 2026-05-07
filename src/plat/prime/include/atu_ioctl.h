// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef ATU_IOCTL_H
#define ATU_IOCTL_H

#include <linux/ioctl.h>
#include <stdint.h>

#define ATU_IOC_MAGIC 'A'

/**
 * One mapping request/response
 */
struct atu_conf_params {
	uint64_t outbound_addr;	/* IN: physical (outbound) base */
	uint32_t win_size;	/* IN: window size (power-of-two, >=1MB) */
	uint32_t inbound_addr;	/* OUT: inbound (CPU-visible) base */
};

/**
 * Memory request structure - matches kernel driver
 */
struct atu_resv_mem_req {
	uint64_t phys_addr;	/* Physical address (output for reserve, input for free)*/
	uint32_t size;		/* Size in bytes (input for reserve, input for free) */
	uint32_t inbound_addr;	/* OUT: inbound (CPU-visible) base */
};

/**
 * Memory information structure - matches kernel driver
 */
struct atu_resv_mem_info {
	uint64_t phys_addr;  /* Physical start address of reserved memory */
	uint32_t size;       /* Total size of reserved memory */
};

/* IOCTL command definitions - must match kernel driver */
/* Configure a new ATU mapping (phys,size -> virt)  */
#define ATU_IOC_CONFIG		_IOWR(ATU_IOC_MAGIC, 1, struct atu_conf_params)

/* Deconfigure an ATU mapping (by phys) */
#define ATU_IOC_DECONFIG	_IOR(ATU_IOC_MAGIC, 2, struct atu_conf_params)

#define ATU_GET_RESV_MEM	_IOWR(ATU_IOC_MAGIC, 3, struct atu_resv_mem_req)
#define ATU_FREE_RESV_MEM	_IOW(ATU_IOC_MAGIC, 4, struct atu_resv_mem_req)
#define ATU_GET_RESV_MEM_INFO	_IOR(ATU_IOC_MAGIC, 5, struct atu_resv_mem_info)

#endif /* ATU_IOCTL_H */
