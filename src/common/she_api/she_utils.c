// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>

#include "sab_msg_def.h"
#include "internal/she_utils.h"
#include "internal/she_get_info.h"
#include "plat_utils.h"
#include "sab_common_err.h"
#include "plat_err_def.h"

#define SHE_ERR_SUPPORT 0

/* Print warnings if any with the SAB Success rating */
static she_err_t sab_success_rating_to_she_warning(uint8_t sab_success_rating)
{
	she_err_t she_warn = plat_sab_success_rating_to_she_warning[sab_success_rating];

	switch (she_warn) {
	case SHE_NO_ERROR:
		break;

	case SAB_INVALID_LIFECYCLE:
		se_info("\nSHE Warning: SAB_INVALID_LIFECYCLE (0x%x)\n", she_warn);
		break;

	case SAB_KEY_STORE_COUNTER:
		se_info("\nSHE Warning: SAB_KEY_STORE_COUNTER (0x%x)\n", she_warn);
		break;

	case SHE_NO_DEBUGGING_RATING:
		se_info("\nSHE Warning: SHE_NO_DEBUGGING (0x%x)\n", she_warn);
		break;

	case SHE_BUSY_RATING:
		se_info("\nSHE Warning: SHE_BUSY (0x%x)\n", she_warn);
		break;

	case SHE_UNKNOWN_WARNING:
		se_info("\nSHE Warning: SHE_UNKNOWN_WARNING (0x%x)\n", she_warn);
		se_info("Unknown SAB Warning Rating (0x%x)\n", sab_success_rating);
		break;
	}

	return SHE_NO_ERROR;
}

/* SAB Error ratings to SHE Error */
static she_err_t sab_err_rating_to_she_err(uint8_t sab_err_rating)
{
	she_err_t she_err = plat_sab_err_rating_to_she_err_map[sab_err_rating];

	switch (she_err) {
	case SHE_NO_ERROR:
		se_err("\nSHE Error: SHE_NO_ERROR (0x%x)\n", she_err);
		break;

	case SAB_INVALID_MESSAGE:
		se_err("\nSHE Error: SAB_INVALID_MESSAGE (0x%x)\n", she_err);
		break;

	case SAB_INVALID_ADDRESS:
		se_err("\nSHE Error: SAB_INVALID_ADDRESS (0x%x)\n", she_err);
		break;

	case SAB_UNKNOWN_ID:
		se_err("\nSHE Error: SAB_UNKNOWN_ID (0x%x)\n", she_err);
		break;

	case SAB_INVALID_PARAM:
		se_err("\nSHE Error: SAB_INVALID_PARAM (0x%x)\n", she_err);
		break;

	case SAB_NVM_ERROR:
		se_err("\nSHE Error: SAB_NVM_ERROR (0x%x)\n", she_err);
		break;

	case SAB_OUT_OF_MEMORY:
		se_err("\nSHE Error: SAB_OUT_OF_MEMORY (0x%x)\n", she_err);
		break;

	case SAB_UNKNOWN_HANDLE:
		se_err("\nSHE Error: SAB_UNKNOWN_HANDLE (0x%x)\n", she_err);
		break;

	case SAB_UNKNOWN_KEY_STORE:
		se_err("\nSHE Error: SAB_UNKNOWN_KEY_STORE (0x%x)\n", she_err);
		break;

	case SAB_KEY_STORE_AUTH:
		se_err("\nSHE Error: SAB_KEY_STORE_AUTH (0x%x)\n", she_err);
		break;

	case SAB_KEY_STORAGE_ERROR:
		se_err("\nSHE Error: SAB_KEY_STORAGE_ERROR (0x%x)\n", she_err);
		break;

	case SAB_ID_CONFLICT:
		se_err("\nSHE Error: SAB_ID_CONFLICT (0x%x)\n", she_err);
		break;

	case SAB_RNG_NOT_STARTED:
		se_err("\nSHE Error: SAB_RNG_NOT_STARTED (0x%x)\n", she_err);
		break;

	case SAB_CMD_NOT_SUPPORTED:
		se_err("\nSHE Error: SAB_CMD_NOT_SUPPORTED (0x%x)\n", she_err);
		break;

	case SAB_INVALID_LIFECYCLE:
		se_err("\nSHE Error: SAB_INVALID_LIFECYCLE (0x%x)\n", she_err);
		break;

	case SAB_KEY_STORE_CONFLICT:
		se_err("\nSHE Error: SAB_KEY_STORE_CONFLICT (0x%x)\n", she_err);
		break;

	case SAB_KEY_STORE_COUNTER:
		se_err("\nSHE Error: SAB_KEY_STORE_COUNTER (0x%x)\n", she_err);
		break;

	case SAB_FEATURE_NOT_SUPPORTED:
		se_err("\nSHE Error: SAB_FEATURE_NOT_SUPPORTED (0x%x)\n", she_err);
		break;

	case SAB_SELF_TEST_FAILURE:
		se_err("\nSHE Error: SAB_SELF_TEST_FAILURE (0x%x)\n", she_err);
		break;

	case SAB_NOT_READY:
		se_err("\nSHE Error: SAB_NOT_READY (0x%x)\n", she_err);
		break;

	case SAB_FEATURE_DISABLED:
		se_err("\nSHE Error: SAB_FEATURE_DISABLED (0x%x)\n", she_err);
		break;

	case SHE_SEQUENCE_ERROR_RATING:
		se_err("\nSHE Error: SHE_SEQUENCE_ERROR (0x%x)\n", she_err);
		break;

	case SHE_KEY_NOT_AVAILABLE_RATING:
		se_err("\nSHE Error: SHE_KEY_NOT_AVAILABLE (0x%x)\n", she_err);
		break;

	case SHE_KEY_INVALID_RATING:
		se_err("\nSHE Error: SHE_KEY_INVALID (0x%x)\n", she_err);
		break;

	case SHE_KEY_EMPTY_RATING:
		se_err("\nSHE Error: SHE_KEY_EMPTY (0x%x)\n", she_err);
		break;

	case SHE_NO_SECURE_BOOT_RATING:
		se_err("\nSHE Error: SHE_NO_SECURE_BOOT (0x%x)\n", she_err);
		break;

	case SHE_KEY_WRITE_PROTECTED_RATING:
		se_err("\nSHE Error: SHE_KEY_WRITE_PROTECTED (0x%x)\n", she_err);
		break;

	case SHE_KEY_UPDATE_ERROR_RATING:
		se_err("\nSHE Error: SHE_KEY_UPDATE_ERROR (0x%x)\n", she_err);
		break;

	case SHE_RNG_SEED_RATING:
		se_err("\nSHE Error: SHE_RNG_SEED (0x%x)\n", she_err);
		break;

	case SHE_NO_DEBUGGING_RATING:
		se_err("\nSHE Error: SHE_NO_DEBUGGING (0x%x)\n", she_err);
		break;

	case SHE_BUSY_RATING:
		se_err("\nSHE Error: SHE_BUSY (0x%x)\n", she_err);
		break;

	case SHE_MEMORY_FAILURE_RATING:
		se_err("\nSHE Error: SHE_MEMORY_FAILURE (0x%x)\n", she_err);
		break;

	case SHE_LIB_ERROR:
		se_err("\nSHE Error: SHE_LIB_ERROR (0x%x)\n", she_err);
		break;

	case SHE_FATAL_FAILURE:
		se_err("\nSHE Error: SHE_FATAL_FAILURE (0x%x)\n", she_err);
		break;

	case SHE_GENERAL_ERROR:
		se_err("\nSHE Error: SHE_GENERAL_ERROR (0x%x)\n", she_err);
		break;
	}

	return she_err;
}

she_err_t sab_rating_to_she_err(uint32_t sab_err, void *phdl)
{
	she_err_t she_err = SHE_GENERAL_ERROR;

	if (GET_STATUS_CODE(sab_err) == plat_sab_success_tag(phdl))
		she_err = sab_success_rating_to_she_warning(GET_RATING_CODE(sab_err));
	else
		she_err = sab_err_rating_to_she_err(GET_RATING_CODE(sab_err));

	return she_err;
}

static uint8_t is_lib_err(uint32_t err)
{
	uint8_t ret = 0;

	/**
	 * If the library error is one of these,
	 * they need to be treated as SAB error
	 */
	if (err == SAB_LIB_CMD_UNSUPPORTED ||
	    err == SAB_LIB_CMD_INVALID ||
	    err == SAB_LIB_SHE_CANCEL_ERROR)
		ret = 1;

	return ret;
}

she_err_t plat_err_to_she_err(uint8_t msg_id, uint32_t lib_err, uint8_t dir)
{
	she_err_t ret = SHE_NO_ERROR;

	if (lib_err != PLAT_SUCCESS) {
		plat_lib_err_map(msg_id, lib_err);

		if (dir == SHE_PREPARE)
			ret = SHE_LIB_ERROR;
	}

	return ret;
}

she_err_t lib_err_to_she_err(uint32_t lib_err)
{
	she_err_t ret = SHE_LIB_ERROR;
	uint32_t lib_err_status = PARSE_LIB_ERR_STATUS(lib_err);

	if (lib_err_status == SAB_LIB_SUCCESS)
		return SHE_NO_ERROR;

	if (PARSE_LIB_ERR_PATH(lib_err) == ENGN_RCV_RESP_PATH_FLAG)
		return SHE_NO_ERROR;

	if (is_lib_err(lib_err))
		ret = sab_err_rating_to_she_err(GET_RATING_CODE(lib_err_status));

	return ret;
}

void se_get_info(uint32_t session_hdl, op_get_info_args_t *args)
{
	she_err_t err;

	err = she_get_info(session_hdl, args);
	if (err != SHE_NO_ERROR)
		se_err("\nGlobal Info: she_get_info failed err:0x%x\n", err);
}

void se_get_soc_info(uint32_t session_hdl,
		     uint16_t *soc_id,
		     uint16_t *soc_rev)
{
	struct she_session_hdl_s *s_ptr;
	uint32_t ret;

	s_ptr = she_session_hdl_to_ptr(session_hdl);
	if (s_ptr)
		ret = plat_os_abs_get_soc_info(s_ptr->phdl,
					       soc_id,
					       soc_rev);
	if (!s_ptr || ret != PLAT_SUCCESS)
		se_err("Global Info: failed to get SoC info.\n");
}
