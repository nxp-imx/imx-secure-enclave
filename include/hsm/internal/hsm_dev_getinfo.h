// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_DEV_GET_INFO_H
#define HSM_DEV_GET_INFO_H

#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group29 Dev Info
 * @{
 */

/**
 * Structure detailing the device getinfo operation member arguments
 * Memory for storing uid/sha_rom_patch/sha_fw/signature will be allocated
 * by HSM library.
 * Caller of the func hsm_dev_getinfo(), needs to ensure freeing up memory.
 */
typedef struct {
	uint16_t soc_id;
	//!< SoC ID.
	uint16_t soc_rev;
	//!< SoC revision number.
	uint16_t lmda_val;
	//!< indicates the lmda lifecycle value.
	uint8_t  ssm_state;
	//!< security subsystem state machine.
	uint8_t  uid_sz;
	//!< chip unique identifier size.
	uint8_t  *uid;
	//!< pointer to the chip unique identifier.
	uint16_t rom_patch_sha_sz;
	//!< indicates the size of Sha256 of sentinel rom patch fuses.
	uint16_t sha_fw_sz;
	//!< indicates the size of first 256 bits of installed fw sha.
	uint8_t  *sha_rom_patch;
	//!< pointer to the Sha256 of sentinel rom patch fuses digest.
	uint8_t  *sha_fw;
	//!< pointer to the first 256 bits of installed fw sha digest.
	uint16_t oem_srkh_sz;
	//!< indicates the size of FW OEM SRKH.
	uint8_t  *oem_srkh;
	//!< pointer to the FW OEM SRKH.
	uint8_t  imem_state;
	//!< indicates the imem state.
	uint8_t  csal_state;
	//!< crypto Lib random context initialization state.
	uint8_t  trng_state;
	//!< indicates TRNG state.
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

/**
 * LMDA values
 */
typedef enum {
	/**< LMDA value for OEM Open state */
	HSM_LMDA_OEM_OPEN                 = 0x10,
	/**< LMDA value for OEM Closed state */
	HSM_LMDA_OEM_CLOSED               = 0x40,
	/**< LMDA value for OEM Locked state */
	HSM_LMDA_OEM_LOCKED               = 0x200,
} hsm_lmda_val_t;

/**
 * return the lifecycle value corresponding to the given LMDA value
 * \param lmda_val LMDA value
 *
 * \return lc Lifecycle value
 */
hsm_key_lifecycle_t hsm_get_lc_from_lmda(hsm_lmda_val_t lmda_val);

/** @} end of dev info operation */
#endif
