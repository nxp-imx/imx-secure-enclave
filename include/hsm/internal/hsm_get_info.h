// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_GET_INFO_H
#define HSM_GET_INFO_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group25 Get Info
 * @{
 */

/**
 * Structure describing the get info operation member arguments
 */
typedef struct {
	uint32_t user_sab_id;
//!< Stores User identifier (32bits)
	uint8_t *chip_unique_id;
//!< Stores the chip unique identifier
//!<	Memory for storing chip_unique_id will be allocated by HSM library.
//!<	Caller of the func hsm_get_info(), needs to
//!<	ensure freeing up of this memory.
	uint16_t chip_unq_id_sz;
//!< Size of the chip unique identifier in bytes
	uint16_t chip_monotonic_counter;
//!< Stores the chip monotonic counter value (16bits)
	uint16_t chip_life_cycle;
//!< Stores the chip current life cycle bitfield (16bits)
	uint32_t version;
//!< Stores the module version (32bits)
	uint32_t version_ext;
//!< Stores the module extended version (32bits)
	uint8_t  fips_mode;
//!< Stores the FIPS mode bitfield (8bits).
//!< Bitmask definition:\n
//!< bit0 - FIPS mode of operation:\n
//!<   - value 0 - part is running in FIPS non-approved mode.\n
//!<   - value 1 - part is running in FIPS approved mode.\n
//!< bit1 - FIPS certified part:\n
//!<   - value 0 - part is not FIPS certified.\n
//!<   - value 1 - part is FIPS certified.\n
//!< bit2-7: reserved
//!<   - value 0.
} op_get_info_args_t;

/**
 * Perform device attestation operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_get_info(hsm_hdl_t sess_hdl, op_get_info_args_t *args);

/** @} end of Get info operation */
#endif
