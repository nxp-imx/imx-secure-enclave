// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef HSM_COMMIT_H
#define HSM_COMMIT_H

#include "common/utils.h"
#include "hsm_utils.h"

/* Commit information type bitmask definitions */
#define HSM_COMMIT_NXP_SRK_REVOCATION	BIT(0)  /* Bit 0: NXP SRK revocation */
#define HSM_COMMIT_NXP_FW_VERSION	BIT(1)  /* Bit 1: NXP FW fuse version */
/* Bits 2-3: Reserved */
#define HSM_COMMIT_OEM_SRK_REVOCATION	BIT(4)  /* Bit 4: OEM SRK revocation */
#define HSM_COMMIT_OEM_FW_VERSION	BIT(5)  /* Bit 5: OEM FW fuse version */
/* Bits 6-31: Reserved */

/**
 * struct op_commit_args - Arguments for commit operation
 * @info_type: Bitmask of information types to commit
 * @committed_info: [OUT] Bitmask of information actually committed
 */
typedef struct {
	uint32_t info_type;
	uint32_t committed_info;
} op_commit_args_t;

/**
 * hsm_commit() - Commit SRK revocation and FW version to fuses
 * @session_hdl: HSM session handle
 * @args: Pointer to commit operation arguments
 *
 * This command commits into fuses any new SRK revocation and FW version
 * information found in NXP (EdgeLock Secure Enclave FW) and OEM containers.
 *
 * Note: This command is only available in boot EdgeLock Secure Enclave FW.
 *
 * Return: HSM error code
 *   - HSM_NO_ERROR: Operation successful (0xD6)
 *   - HSM_GENERAL_ERROR: General error (0x29)
 *   - HSM_INVALID_PARAM: Invalid information encoded in request (0xF4)
 *   - HSM_EVENT_QUEUE_NOT_EMPTY: OEM version/SRK revocation targeted but
 *                                 event queue not empty (0xC0)
 */
hsm_err_t hsm_commit(hsm_hdl_t session_hdl, op_commit_args_t *args);

#endif
