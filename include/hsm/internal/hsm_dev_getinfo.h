/*
 * Copyright 2022-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef HSM_DEV_GET_INFO_H
#define HSM_DEV_GET_INFO_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group29 Dev Info
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
	 * Caller of the func hsm_dev_getinfo(), needs to
	 * ensure freeing up of this memory.
	 */
	uint8_t  *uid;
	uint16_t rom_patch_sha_sz;
	uint16_t sha_fw_sz;
	uint8_t  *sha_rom_patch;
	uint8_t  *sha_fw;
	uint16_t oem_srkh_sz;
	uint8_t  *oem_srkh;
	uint8_t  imem_state;
	uint8_t  csal_state;
	uint8_t  trng_state;
} op_dev_getinfo_args_t;

/**
 * Perform device attestation operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_dev_getinfo(hsm_hdl_t sess_hdl, op_dev_getinfo_args_t *args);

/** @} end of dev info operation */
#endif
