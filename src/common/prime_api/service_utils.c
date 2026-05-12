/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "internal/prime_handle.h"
#include "internal/prime_service.h"

#include "sab_prime_process_msg.h"
#include "keyslot.h"

/**
 * Structure describing memory allocation for prime handles
 */
typedef struct {
	uint64_t physical_addr;   //!< Physical address of allocated memory
	uint64_t virtual_addr;    //!< Virtual address of allocated memory
	uint32_t requested_size;  //!< Requested memory size
} prime_mem_alloc_t;

/**
 * Allocate Prime handle and reserve memory
 */
int prime_handle_alloc(prime_mem_alloc_t *mem_info, prime_service_t *handle)
{
	struct atu_resv_mem_req req = {0};
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	void *mmap_addr;
	int ret;

	req.size = mem_info->requested_size;

	// Open the V2X Prime device
	handle->fd = open(V2X_PRIME_DEVICE, O_RDWR);
	if (handle->fd < 0) {
		printf("Prime Library: Failed to open %s\n", V2X_PRIME_DEVICE);
		return -1;
	}

	// Make atu_resv_mem ioctl call
	ret = ioctl(handle->fd, ATU_GET_RESV_MEM, &req);
	if (ret < 0) {
		printf("Prime Library: ATU_GET_RESV_MEM ioctl failed\n");
		return ret;
	}

#ifdef DEBUG
	printf("Received: PA: 0x%lx, Req size: %x, Allocated: 0x%x, inbound_addr 0x%x\n",
	       req.phys_addr, mem_info->requested_size, req.size, req.inbound_addr);
#endif
	// Calculate offset from base address
	uint64_t offset = req.phys_addr - prime_mu->phys_addr;

	mmap_addr = mmap(NULL, req.size,
			 PROT_READ | PROT_WRITE, MAP_SHARED,
			 handle->fd, (off_t)offset);

	if (mmap_addr == MAP_FAILED) {
		printf("Prime Library: mmap failed: %s\n", strerror(errno));

		// Free the reserved memory
		struct atu_resv_mem_req free_req = {
			.phys_addr = req.phys_addr,
			.size = req.size
		};
		ioctl(handle->fd, ATU_FREE_RESV_MEM, &free_req);
		close(handle->fd);
		return -ENOMEM;
	}

	// Attach memory and size with handle
	handle->physical_addr = req.phys_addr;
	handle->size = req.size;
	handle->mmap_addr = mmap_addr;
	handle->inbound_addr = req.inbound_addr;

	// Update mem_info with allocated values
	mem_info->physical_addr = req.phys_addr;
	mem_info->virtual_addr = (uint64_t)mmap_addr;
	mem_info->requested_size = req.size;

	return 0;
}

/**
 * Release Prime handle and free memory
 */
void deallocate_user_memory(prime_service_t *handle)
{
	struct atu_resv_mem_req req = {0};
	int ret;

	if (handle->fd < 0) {
		printf("Memory not mapped\n");
		return;
	}

	// Unmap the memory
	if (handle->mmap_addr)
		munmap(handle->mmap_addr, handle->size);

	// Call atu_free_mem ioctl
	req.phys_addr = handle->physical_addr;
	req.size = handle->size;

	ret = ioctl(handle->fd, ATU_FREE_RESV_MEM, &req);
	if (ret < 0)
		printf("ATU_FREE_RESV_MEM ioctl failed: %s\n", strerror(errno));

	close(handle->fd);
}

int32_t configure_user_memory(open_service_args_t *op_serv_args, prime_service_t *handle)
{
	int fd, rc;
	struct atu_conf_params param;

	if (!(op_serv_args->physical_addr >> 32)) {
		/* 32 bit address, no need to map ATU */
		handle->physical_addr = op_serv_args->physical_addr;
		handle->size = op_serv_args->size;
		return 0;
	}

	fd = open(V2X_PRIME_DEVICE, O_RDWR);
	if (fd < 0) {
		printf("Failed to open prime device /dev/prime\n");
		return -1;
	}

	param.outbound_addr = op_serv_args->physical_addr;
	param.win_size = op_serv_args->size;

	rc = ioctl(fd, ATU_IOC_CONFIG, &param);
	if (rc) {
		if (errno != EEXIST) {
			printf("ATU CONFIG failed: %s (%d)\n", strerror(errno), errno);
			close(fd);
			return rc;
		}
		close(fd);
		fd = 0;
	}

	// Attach memory and size with handle
	handle->physical_addr = op_serv_args->physical_addr;
	handle->size = op_serv_args->size;
	handle->inbound_addr = param.inbound_addr;
	handle->fd = fd;

#ifdef DEBUG
	printf("CONFIG OK: phys=0x%llx  virt=0x%llx  size=0x%llx\n",
	       (unsigned long long)param.outbound_addr,
	       (unsigned long long)param.inbound_addr,
	       (unsigned long long)param.win_size);
#endif
	return 0;
}

uint32_t allocate_memory_to_user(open_service_args_t *op_serv_args,
				 prime_service_t *handle)
{
	prime_mem_alloc_t mem_alloc = {0};
	int32_t ret;

	op_serv_args->physical_addr = 0;
	op_serv_args->virtual_addr = 0;

	// Prepare memory allocation request
	mem_alloc.requested_size = op_serv_args->size;

	// Allocate Prime handle and reserve memory
	ret = prime_handle_alloc(&mem_alloc, handle);
	if (ret < 0) {
		printf("Prime Service: Failed to allocate handle: %d\n", ret);
		return PRIME_ERR_MEMORY_ALLOC;
	}

	// Populate the parameters in open_service_args_t
	op_serv_args->service_hdl = handle->hdl;
	op_serv_args->physical_addr = mem_alloc.physical_addr;
	op_serv_args->virtual_addr = mem_alloc.virtual_addr;
	op_serv_args->size = mem_alloc.requested_size;

	return ret;
}

void deconfigure_user_memory(prime_service_t *handle)
{
	int rc;
	struct atu_conf_params param;

	param.outbound_addr = handle->physical_addr;
	param.win_size = handle->size;

	if (!handle->fd) //for handles which do not own the PA
		return;

	rc = ioctl(handle->fd, ATU_IOC_DECONFIG, &param);
	if (rc) {
		printf("DECONFIG failed: %s (%d)\n", strerror(errno), errno);
		close(handle->fd);
		return;
	}

	close(handle->fd);
}

void free_keyslot(prime_service_t *handle)
{
	if (handle->hmac_keyslot_map) {
		release_keyslot(handle->hmac_keyslot_map, HMAC_KEYSLOT);
		handle->hmac_keyslot_map = 0;
	}

	if (handle->aes_keyslot_map) {
		release_keyslot(handle->aes_keyslot_map, AES_KEYSLOT);
		handle->aes_keyslot_map = 0;
	}
}
