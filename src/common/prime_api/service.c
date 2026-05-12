/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

#include "internal/prime_handle.h"
#include "internal/prime_service.h"

#include "sab_prime_process_msg.h"
#include "service_utils.h"

/* per-process session mapping */
prime_service_t g_session[PRIME_MAX_SESSIONS_PER_PROCESS] = {0};
static atomic_uint_fast32_t g_handle_counter = 1;

void delete_prime_session(prime_service_t *s_ptr)
{
	if (s_ptr) {
		s_ptr->hdl = 0u;
		s_ptr->physical_addr = 0u;
		s_ptr->size = 0u;
		s_ptr->inbound_addr = 0u;
		s_ptr->mmap_addr = NULL;
		s_ptr->fd = 0u;
	}
}

prime_service_t *add_prime_session(void)
{
	uint8_t i;
	prime_service_t *s_ptr = NULL;

	for (i = 0u; i < PRIME_MAX_SESSIONS_PER_PROCESS; i++) {
		if (!g_session[i].hdl) {
			/* Found an empty slot. */
			s_ptr = &g_session[i];
			return s_ptr;
		}
	}
	return s_ptr;
}

prime_service_t *prime_session_to_ptr(prime_hdl_t hdl)
{
	uint8_t i;

	for (i = 0u; i < PRIME_MAX_SESSIONS_PER_PROCESS; i++) {
		if (hdl == g_session[i].hdl)
			return &g_session[i];
	}

	return NULL;
}

prime_err_t prime_open_service(open_service_args_t *op_serv_args,
		prime_hdl_t *serv_hdl)
{
	prime_service_t *handle;
	uint32_t counter_val;
	int ret;

	if (!op_serv_args || !serv_hdl) {
		printf("Prime Service: Invalid arguments\n");
		return PRIME_ERR_INVALID_PARAM;
	}

	handle = add_prime_session();
	if (!handle) {
		printf("Failed to get empty slot for session\n");
		return PRIME_ERR_MEMORY_ALLOC;
	}

	counter_val = (uint32_t)atomic_fetch_add_explicit(&g_handle_counter, 1,
						    memory_order_relaxed);

	/* Prevent counter wrap-around by resetting if approaching max value */
	if (counter_val >= UINT32_MAX - 1)
		atomic_store_explicit(&g_handle_counter, 1, memory_order_relaxed);

	handle->hdl = (prime_hdl_t)((uint32_t)getpid() << 16) ^ counter_val;

	// Store physical address as service handle for later reference
	op_serv_args->service_hdl = handle->hdl;
	*serv_hdl = handle->hdl;

	// Initialize output parameters
	if (!op_serv_args->physical_addr && !op_serv_args->size) {
		printf("Invalid address and size arguments\n");
		goto err;
	} else if (op_serv_args->physical_addr && op_serv_args->size) {
		ret = configure_user_memory(op_serv_args, handle);
		if (ret)
			goto err;
	} else if (!op_serv_args->physical_addr && op_serv_args->size) {
		ret = allocate_memory_to_user(op_serv_args, handle);
		if (ret)
			goto err;
	}

	return PRIME_ERR_NONE;

err:
	delete_prime_session(handle);

	return PRIME_ERR_SERVICE_OPEN;
}

void prime_close_service(prime_hdl_t ser_hdl)
{
	prime_service_t *handle;

	if (ser_hdl == PRIME_HANDLE_NONE) {
		printf("Prime Service: Invalid service handle\n");
		return;
	}

	handle = prime_session_to_ptr(ser_hdl);
	if (!handle) {
		printf("Invalid handle\n");
		return;
	}

	free_keyslot(handle);

	if (!handle->physical_addr && !handle->size)
		return;

	if (handle->mmap_addr)
		// make memory free ioctl
		deallocate_user_memory(handle);
	else
		//Make deconfigure atu ioctl
		deconfigure_user_memory(handle);

	delete_prime_session(handle);
}
