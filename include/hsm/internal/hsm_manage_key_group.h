// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_MANAGE_KEY_GROUP_H
#define HSM_MANAGE_KEY_GROUP_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

#define MAX_VALID_KEY_GROUP (0x64)

typedef uint8_t hsm_op_manage_key_group_flags_t;
typedef struct {
	//!< it must be a value in the range 0-1023.
	//Keys belonging to the same group can be cached in the HSM local memory
	//through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the operation properties.
	hsm_op_manage_key_group_flags_t flags;
	uint8_t reserved;
} op_manage_key_group_args_t;

/**
 * This command is designed to perform the following operations:
 *  - lock/unlock down a key group in the HSM local memory so that the keys are
 *    available to the HSM without additional latency
 *  - un-lock a key group. HSM may export the key group into the external NVM to
 *    free up local memory as needed
 *  - delete an existing key group
 *
 * User can call this function only after having opened a key management service
 * flow.
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_manage_key_group(hsm_hdl_t key_management_hdl,
			       op_manage_key_group_args_t *args);

//!< The entire key group will be cached in the HSM local memory.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_CACHE_LOCKDOWN \
	((hsm_op_manage_key_group_flags_t)(1u << 0))

//!< HSM may export the key group in the external NVM to free up the local
//	 memory. HSM will copy the key group in the local memory again in case
//	 of key group usage/update.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_CACHE_UNLOCK \
	((hsm_op_manage_key_group_flags_t)(1u << 1))

#ifdef PSA_COMPLIANT
//!< Import the key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_IMPORT \
	((hsm_op_manage_key_group_flags_t)(1u << 2))

//!< Export the key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_EXPORT \
	((hsm_op_manage_key_group_flags_t)(1u << 3))

//!< When used in conjunction with SYNC key group or SYNC key store and storage
//	 only, the request is completed only when the monotonic counter has been updated.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_MONOTONIC \
	((hsm_op_manage_key_group_flags_t)(1u << 5))

//!< The request is completed only when the update has been written in the NVM.
//	 Not applicable for cache lockdown/unlock.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_SYNC_KEYSTORE \
	((hsm_op_manage_key_group_flags_t)(1u << 6))
#else
//!< Delete an existing key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE \
	((hsm_op_manage_key_group_flags_t)(1u << 2))
#endif

//!< The request is completed only when the update has been written in the NVM.
//	 Not applicable for cache lockdown/unlock.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_STRICT_OPERATION \
	((hsm_op_manage_key_group_flags_t)(1u << 7))

/** @} end of key group management service flow */
#endif
