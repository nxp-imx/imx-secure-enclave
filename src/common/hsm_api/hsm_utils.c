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

#include <stdio.h>

#include "sab_msg_def.h"
#include "internal/hsm_utils.h"
#include "plat_utils.h"
#include "sab_common_err.h"
#include "plat_err_def.h"

#define HSM_ERR_SUPPORT 0

/* Print warnings if any with the SAB Success rating */
static hsm_err_t sab_success_rating_to_hsm_warning(uint8_t sab_success_rating)
{
	hsm_err_t hsm_warning = plat_sab_success_rating_to_hsm_warning[sab_success_rating];

	switch (hsm_warning) {

	case HSM_NO_ERROR:
		break;

	case HSM_KEY_STORE_COUNTER:
		se_info("\nHSM Warning: HSM_KEY_STORE_COUNTER (0x%x)\n", hsm_warning);
		break;

	case HSM_OEM_OPEN_LC_SIGNED_MSG_VERIFICATION_FAIL:
		se_info("\nHSM Warning: HSM_OEM_OPEN_LC_SIGNED_MSG_VERIFICATION_FAIL (0x%x)\n",
				hsm_warning);
		break;

	case HSM_UNKNOWN_WARNING:
		se_info("\nHSM Warning: HSM_UNKNOWN_WARNING (0x%x)\n", hsm_warning);
		se_info("Unknown SAB Warning Rating (0x%x)\n", sab_success_rating);
		break;
	}

	return HSM_NO_ERROR;
}

/* SAB Error ratings to HSM Error */
static hsm_err_t sab_err_rating_to_hsm_err(uint8_t sab_err_rating)
{
	hsm_err_t hsm_err = plat_sab_err_rating_to_hsm_err_map[sab_err_rating];

	switch (hsm_err) {

	case HSM_GENERAL_ERROR:
		se_err("\nHSM Error: HSM_GENERAL_ERROR (0x%x)\n", hsm_err);
		break;

	case HSM_FATAL_FAILURE:
		se_err("\nHSM Error: HSM_FATAL_FAILURE (0x%x)\n", hsm_err);
		break;

	case HSM_INVALID_ADDRESS:
		se_err("\nHSM Error: HSM_INVALID_ADDRESS (0x%x)\n", hsm_err);
		break;

	case HSM_UNKNOWN_ID:
		se_err("\nHSM Error: HSM_UNKNOWN_ID (0x%x)\n", hsm_err);
		break;

	case HSM_INVALID_PARAM:
		se_err("\nHSM Error: HSM_INVALID_PARAM (0x%x)\n", hsm_err);
		break;

	case HSM_NVM_ERROR:
		se_err("\nHSM Error: HSM_NVM_ERROR (0x%x)\n", hsm_err);
		break;

	case HSM_OUT_OF_MEMORY:
		se_err("\nHSM Error: HSM_OUT_OF_MEMORY (0x%x)\n", hsm_err);
		break;

	case HSM_UNKNOWN_HANDLE:
		se_err("\nHSM Error: HSM_UNKNOWN_HANDLE (0x%x)\n", hsm_err);
		break;

	case HSM_UNKNOWN_KEY_STORE:
		se_err("\nHSM Error: HSM_UNKNOWN_KEY_STORE (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_STORE_AUTH:
		se_err("\nHSM Error: HSM_KEY_STORE_AUTH (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_STORE_ERROR:
		se_err("\nHSM Error: HSM_KEY_STORE_ERROR (0x%x)\n", hsm_err);
		break;

	case HSM_ID_CONFLICT:
		se_err("\nHSM Error: HSM_ID_CONFLICT (0x%x)\n", hsm_err);
		break;

	case HSM_RNG_NOT_STARTED:
		se_err("\nHSM Error: HSM_RNG_NOT_STARTED (0x%x)\n", hsm_err);
		break;

	case HSM_CMD_NOT_SUPPORTED:
		se_err("\nHSM Error: HSM_CMD_NOT_SUPPORTED (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_STORE_CONFLICT:
		se_err("\nHSM Error: HSM_KEY_STORE_CONFLICT (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_STORE_COUNTER:
		se_err("\nHSM Error: HSM_KEY_STORE_COUNTER (0x%x)\n", hsm_err);
		break;

	case HSM_FEATURE_NOT_SUPPORTED:
		se_err("\nHSM Error: HSM_FEATURE_NOT_SUPPORTED (0x%x)\n", hsm_err);
		break;

	case HSM_NOT_READY_RATING:
		se_err("\nHSM Error: HSM_NOT_READY_RATING (0x%x)\n", hsm_err);
		break;

	case HSM_FEATURE_DISABLED:
		se_err("\nHSM Error: HSM_FEATURE_DISABLED (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_GROUP_FULL:
		se_err("\nHSM Error: HSM_KEY_GROUP_FULL (0x%x)\n", hsm_err);
		break;

	case HSM_CANNOT_RETRIEVE_KEY_GROUP:
		se_err("\nHSM Error: HSM_CANNOT_RETRIEVE_KEY_GROUP (0x%x)\n", hsm_err);
		break;

	case HSM_KEY_NOT_SUPPORTED:
		se_err("\nHSM Error: HSM_KEY_NOT_SUPPORTED (0x%x)\n", hsm_err);
		break;

	case HSM_CANNOT_DELETE_PERMANENT_KEY:
		se_err("\nHSM Error: HSM_CANNOT_DELETE_PERMANENT_KEY (0x%x)\n", hsm_err);
		break;

	case HSM_OUT_TOO_SMALL:
		se_err("\nHSM Error: HSM_OUT_TOO_SMALL (0x%x)\n", hsm_err);
		break;

	case HSM_CRC_CHECK_ERR:
		se_err("\nHSM Error: HSM_CRC_CHECK_ERR (0x%x)\n", hsm_err);
		break;

	case HSM_OEM_CLOSED_LC_SIGNED_MSG_VERIFICATION_FAIL:
		se_err("\nHSM Error: HSM_OEM_CLOSED_LC_SIGNED_MSG_VERIFICATION_FAIL (0x%x)\n",
				hsm_err);
		break;

	case HSM_SERVICES_DISABLED:
		se_err("\nHSM Error: HSM_SERVICES_DISABLED (0x%x)\n", hsm_err);
		break;

	case HSM_UNKNOWN_ERROR:
		se_err("\nHSM Error: HSM_UNKNOWN_ERROR (0x%x)\n", hsm_err);
		se_err("Unknown SAB Error Rating (0x%x)\n", sab_err_rating);
		break;

#if HSM_ERR_SUPPORT
		/* The section contains HSM Error cases for SAB ratings which are
		 * not currently being used
		 **/
	case HSM_INVALID_MESSAGE:
		se_err("\nHSM Error: HSM_INVALID_MESSAGE (0x%x)\n", hsm_err);
		break;

	case HSM_INVALID_LIFECYCLE:
		se_err("\nHSM Error: HSM_INVALID_LIFECYCLE (0x%x)\n", hsm_err);
		break;

	case HSM_SELF_TEST_FAILURE:
		se_err("\nHSM Error: HSM_SELF_TEST_FAILURE (0x%x)\n", hsm_err);
		break;

#endif
	}

	return hsm_err;
}

hsm_err_t sab_rating_to_hsm_err(uint32_t sab_err)
{
	hsm_err_t hsm_err = HSM_GENERAL_ERROR;

	if (GET_STATUS_CODE(sab_err) == SAB_SUCCESS_STATUS)
		hsm_err = sab_success_rating_to_hsm_warning(GET_RATING_CODE(sab_err));
	else
		hsm_err = sab_err_rating_to_hsm_err(GET_RATING_CODE(sab_err));

	return hsm_err;
}
