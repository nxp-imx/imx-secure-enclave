// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>

#include "sab_msg_def.h"
#ifdef PSA_COMPLIANT
#include "internal/hsm_dev_getinfo.h"
#endif
#include "internal/hsm_get_info.h"
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

	case HSM_INVALID_LIFECYCLE_OP:
		se_err("\nHSM Error: HSM_INVALID_LIFECYCLE_OP (0x%x)\n", hsm_err);
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

hsm_err_t plat_err_to_hsm_err(uint8_t msg_id, uint32_t lib_err, uint8_t dir)
{
	hsm_err_t ret = HSM_NO_ERROR;

	if (lib_err != PLAT_SUCCESS) {
		plat_lib_err_map(msg_id, lib_err);

		if (dir == HSM_PREPARE)
			ret = HSM_LIB_ERROR;
	}

	return ret;
}

hsm_err_t lib_err_to_hsm_err(uint32_t lib_err)
{
	hsm_err_t ret = HSM_LIB_ERROR;
	uint32_t lib_err_status = PARSE_LIB_ERR_STATUS(lib_err);

	if (lib_err_status == SAB_LIB_SUCCESS)
		return HSM_NO_ERROR;

	if (PARSE_LIB_ERR_PATH(lib_err) == ENGN_RCV_RESP_PATH_FLAG)
		return HSM_NO_ERROR;

	if (is_lib_err(lib_err))
		ret = sab_err_rating_to_hsm_err(GET_RATING_CODE(lib_err_status));

	return ret;
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

void se_get_info(uint32_t session_hdl, op_get_info_args_t *args)
{
	hsm_err_t err;

	err = hsm_get_info(session_hdl, args);
	if (err != HSM_NO_ERROR)
		se_err("\nGlobal Info: hsm_get_info failed err:0x%x\n", err);
}

void se_get_soc_info(uint32_t session_hdl,
		     uint32_t *soc_id,
		     uint32_t *soc_rev)
{
#ifdef PSA_COMPLIANT
	hsm_err_t err;
	op_dev_getinfo_args_t dev_getinfo_args = {0};
#else
	struct hsm_session_hdl_s *s_ptr;
	uint32_t ret;
#endif
	if (!soc_id || !soc_rev)
		return;

#ifdef PSA_COMPLIANT
	plat_os_abs_memset((uint8_t *)&dev_getinfo_args, 0, sizeof(dev_getinfo_args));

	err = hsm_dev_getinfo(session_hdl, &dev_getinfo_args);
	if (err != HSM_NO_ERROR)
		se_err("\nGlobal Info: hsm_dev_getinfo(ROM) failed err:0x%x\n",
		       err);

	*soc_id = dev_getinfo_args.soc_id;
	*soc_rev = dev_getinfo_args.soc_rev;
#else
	s_ptr = session_hdl_to_ptr(session_hdl);
	if (s_ptr)
		ret = plat_os_abs_get_soc_info(s_ptr->phdl,
					       soc_id,
					       soc_rev);
	if (!s_ptr || ret != PLAT_SUCCESS)
		se_err("Global Info: failed to get SoC info.\n");
#endif
}
