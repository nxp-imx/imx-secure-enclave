// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SERVICE_UTILS_H
#define SERVICE_UTILS_H

#include "internal/prime_service.h"
#include "uio.h"

int32_t configure_user_memory(open_service_args_t *op_serv_args, prime_service_t *handle);
void deconfigure_user_memory(prime_service_t *handle);
uint32_t allocate_memory_to_user(open_service_args_t *op_serv_args,
				 prime_service_t *handle);
void deallocate_user_memory(prime_service_t *handle);
void free_keyslot(prime_service_t *handle);
#endif
