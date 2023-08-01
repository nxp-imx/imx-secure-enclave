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

/**
 * Device Attestation Nounce sizes
 */
#define DEV_ATTEST_NOUNCE_SIZE_V1    (4)
#define DEV_ATTEST_NOUNCE_SIZE_V2    (16)

/**
 * Structure describing the device attestation operation member arguments
 * Memory for storing uid/sha_rom_patch/sha_fw/signature will be allocated
 * by HSM library.
 * Caller of the func hsm_dev_attest(), needs to ensure freeing up memory.
 */
typedef struct {
	uint16_t soc_id;
	//!< SoC ID
	uint16_t soc_rev;
	//!< SoC Revision
	uint16_t lmda_val;
	//!< Lmda Lifecycle value
	uint8_t  ssm_state;
	//!< Security Subsystem State Machine state
	uint8_t  uid_sz;
	//!< buffer size in bytes for Chip Unique Identifier
	uint8_t  *uid;
	//!< pointer to the Chip Unique Identifier buffer
	uint16_t rom_patch_sha_sz;
	//!< buffer size in bytes for SHA256 of Sentinel ROM patch fuses
	uint16_t sha_fw_sz;
	//!< buffer size in bytes for first 256 bits of installed FW SHA
	uint8_t  *sha_rom_patch;
	//!< pointer to the buffer containing SHA256 of Sentinel ROM patch fuses
	uint8_t  *sha_fw;
	//!< pointer to the buffer containing first 256 bits of installed FW SHA
	uint16_t nounce_sz;
	//!< buffer size in bytes for request nounce value
	uint8_t *nounce;
	//!< pointer to the input/request nounce value buffer
	uint16_t rsp_nounce_sz;
	//!< size in bytes for FW nounce buffer, returned with FW resp
	uint8_t *rsp_nounce;
	//!< pointer to the FW nounce buffer, returned with FW resp
	uint16_t oem_srkh_sz;
	//!< buffer size in bytes for OEM SRKH (version 2)
	uint8_t  *oem_srkh;
	//!< pointer to the buffer of OEM SRKH (version 2)
	uint8_t  imem_state;
	//!< IMEM state (version 2)
	uint8_t  csal_state;
	//!< CSAL state (version 2)
	uint8_t  trng_state;
	//!< TRNG state (version 2)
	uint16_t info_buf_sz;
	//!< size in bytes for info buffer
	uint8_t *info_buf;
	//!< pointer to the info buffer, for verification of the signature
	uint8_t attest_result;
	//!< Attest Result. 0 means pass. 1 means fail.
	uint16_t sign_sz;
	//!< buffer size in bytes for signature
	uint8_t  *signature;
	//!< pointer to the signature buffer
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
