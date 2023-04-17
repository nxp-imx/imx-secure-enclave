// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_DEV_ATTEST_H
#define HSM_DEV_ATTEST_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group27 Dev attest
 * @{
 */
typedef struct {
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lmda_val;
	uint8_t  ssm_state;
	uint8_t  uid_sz;
	/* Memory for storing uid/sha_rom_patch/sha_fw/signature
	 * will be allocated by HSM library.
	 * Caller of the func hsm_dev_attest(), needs to
	 * ensure freeing up of this memory.
	 */
	uint8_t  *uid;
	uint16_t rom_patch_sha_sz;
	uint16_t sha_fw_sz;
	uint8_t  *sha_rom_patch;
	uint8_t  *sha_fw;
	uint32_t nounce;
	uint32_t rsp_nounce;
	/* 0 means pass. 1 means fail. */
	uint8_t attest_result;
	uint8_t reserved;
	uint16_t sign_sz;
	uint8_t  *signature;
} op_dev_attest_args_t;

/**
 * Perform device attestation operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_dev_attest(hsm_hdl_t sess_hdl, op_dev_attest_args_t *args);

/** @} end of dev attest operation */
#endif
