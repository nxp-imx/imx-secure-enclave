// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>

#include "sab_msg_def.h"
#include "internal/hsm_utils.h"
#include "plat_utils.h"
#include "sab_common_err.h"
#include "plat_err_def.h"

#ifdef PSA_COMPLIANT
#include <string.h>
#include "internal/hsm_dev_getinfo.h"
#include "internal/se_version.h"

struct global_info_s global_info;
#endif

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

	case HSM_DATA_ALREADY_RETRIEVED:
		se_err("\nHSM Error: HSM_DATA_ALREADY_RETRIEVED (0x%x)\n", hsm_err);
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

uint32_t get_tlv_data_len(uint8_t *len_buf,
			  uint32_t len_buf_length,
			  uint32_t *data_len)
{
	if (!len_buf)
		return 0;

	uint8_t len_of_len = 0;
	uint32_t temp_len = 0;
	uint8_t i = 0;

	if (len_buf[0] < TLV_LEN_GREATER_THAN_ONE_BYTE) {
		temp_len = len_buf[0];
	} else {
		/**
		 * Read number of bytes containing the length of TLV variable
		 * Length field, in case it is greater than 127 bytes.
		 */
		len_of_len = len_buf[0] & 0x0F;

		if (len_of_len >= len_buf_length)
			goto out;

		while (i < len_of_len) {
			i++;
			temp_len <<= 8;
			temp_len = temp_len | len_buf[i];
		}
	}

out:
	if (data_len)
		*data_len = temp_len;

	return len_of_len + 1;
}

uint32_t decode_from_tlv_buf(uint8_t **data,
			     uint32_t *len,
			     uint8_t tag,
			     uint8_t tag_len,
			     uint8_t *tlv_buf,
			     uint32_t tlv_buf_len)
{
	uint64_t next_tlv_data_buf_idx = 0;
	uint8_t len_of_len;

	if (!data || !len || !tlv_buf || !tlv_buf_len)
		goto out;

	if (tlv_buf[0] != tag)
		goto out;

	if (tag_len >= tlv_buf_len) {
		next_tlv_data_buf_idx = tag_len;
		goto out;
	}

	len_of_len = get_tlv_data_len(&tlv_buf[tag_len],
				      tlv_buf_len - tag_len,
				      len);

	if (*len) {
		*data = plat_os_abs_malloc(*len);
		if (!*data) {
			se_err("Malloc failure.\n");
			goto out;
		}

		if (((tag_len + len_of_len) < tlv_buf_len) &&
		    (*len <= (tlv_buf_len - tag_len - len_of_len)))
			plat_os_abs_memcpy(*data,
					   &tlv_buf[tag_len + len_of_len],
					   *len);
	}

	next_tlv_data_buf_idx = tag_len + len_of_len + *len;
out:
	return TO_UINT32_T(next_tlv_data_buf_idx);
}

#ifdef PSA_COMPLIANT
const char *get_soc_id_str(uint16_t soc_id)
{
	switch (soc_id) {
	case SOC_IMX8ULP:
		return "i.MX8ULP";
	case SOC_IMX93:
		return "i.MX93";
	}

	return NULL;
}

const char *get_soc_rev_str(uint16_t soc_rev)
{
	switch (soc_rev) {
	case SOC_REV_A0:
		return "A0";
	case SOC_REV_A1:
		return "A1";
	case SOC_REV_A2:
		return "A2";
	}

	return NULL;
}

const char *get_soc_lf_str(uint16_t lifecycle)
{
	switch (lifecycle) {
	case SOC_LF_OPEN:
		return "Open";
	case SOC_LF_CLOSED:
		return "Closed";
	case SOC_LF_CLOSED_LOCKED:
		return "Closed and Locked";
	}

	return NULL;
}

void populate_global_info(hsm_hdl_t hsm_session_hdl)
{
	hsm_err_t err;
	op_dev_getinfo_args_t dev_getinfo_args = {0};

	plat_os_abs_memset((uint8_t *)&dev_getinfo_args, 0, sizeof(dev_getinfo_args));
	plat_os_abs_memset((uint8_t *)&global_info, 0, sizeof(global_info));

	err = hsm_dev_getinfo(hsm_session_hdl, &dev_getinfo_args);
	if (err != HSM_NO_ERROR) {
		se_err("\nhsm_dev_getinfo(ROM) failed err:0x%x\n", err);
		se_err("\nError: failed to populate Global Info\n");
	}

	global_info.soc_id = dev_getinfo_args.soc_id;
	global_info.soc_rev = dev_getinfo_args.soc_rev;

	if (global_info.soc_id == SOC_IMX93 && global_info.soc_rev == SOC_REV_A1)
		global_info.ver = HSM_API_VERSION_2;
	else
		global_info.ver = HSM_API_VERSION_1;

	global_info.lifecycle = dev_getinfo_args.lmda_val;
	global_info.lib_newness_ver = LIB_NEWNESS_VER;
	global_info.lib_major_ver = LIB_MAJOR_VER;
	global_info.lib_minor_ver = LIB_MINOR_VER;
	global_info.nvm_newness_ver = NVM_NEWNESS_VER;
	global_info.nvm_major_ver = NVM_MAJOR_VER;
	global_info.nvm_minor_ver = NVM_MINOR_VER;
	if (strlen(LIB_COMMIT_ID) == GINFO_COMMIT_ID_SZ)
		plat_os_abs_memcpy(global_info.se_commit_id,
				   LIB_COMMIT_ID,
				   GINFO_COMMIT_ID_SZ);
}

uint8_t hsm_get_dev_attest_api_ver(void)
{
	return global_info.ver;
}

void show_global_info(void)
{
	se_info("-------------------------------------------------------\n");
	se_info("Global Info:\n");
	se_info("-------------------------------------------------------\n");
	se_info("%s %s\n",
		get_soc_id_str(global_info.soc_id),
		get_soc_rev_str(global_info.soc_rev));
	se_info("%s Lifecycle\n", get_soc_lf_str(global_info.lifecycle));
	se_info("LIB Version %u.%u.%u\n",
		global_info.lib_newness_ver,
		global_info.lib_major_ver,
		global_info.lib_minor_ver);
	se_info("NVM Version %u.%u.%u\n",
		global_info.nvm_newness_ver,
		global_info.nvm_major_ver,
		global_info.nvm_minor_ver);
	se_info("Build ID %s\n", global_info.se_commit_id);
	se_info("-------------------------------------------------------\n");
}
#endif
