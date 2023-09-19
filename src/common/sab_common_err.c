// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "plat_utils.h"

void sab_err_map(uint8_t msg_type, uint8_t sab_cmd, uint32_t rsp_code)
{
	struct sab_err_map_s *sab_err_map_ptr = NULL;
	uint8_t sab_err_str[256];
	uint8_t i = 0;

	sab_err_map_ptr = get_sab_err_str_map();

	if (GET_STATUS_CODE(rsp_code) == SAB_STATUS_SUCCESS(msg_type)) {
		/* print for warnings. */
		return;
	}

	for (i = 0; i < SAB_ERR_MAP_N; i++) {
		if (rsp_code == sab_err_map_ptr[i].sab_err) {
			if (sprintf(sab_err_str,
				    "SAB Error: SAB CMD [0x%x] Resp [0x%x] - %s.\n",
				    sab_cmd,
				    rsp_code,
				    sab_err_map_ptr[i].sab_err_str) < 0)
				se_warn("unable to write string array for mapped error\n");
			break;
		}
	}

	if (i == SAB_ERR_MAP_N) {
		if (sprintf(sab_err_str,
			    "SAB Error: SAB CMD [0x%x]  Resp [0x%x] - Unknown error code\n",
			    sab_cmd,
			    rsp_code) < 0)
			se_warn("unable to write string array for unknown error\n");
	}

	printf("\n%s\n", sab_err_str);
}

void sab_lib_err_map(uint8_t msg_id, uint32_t sab_lib_err)
{
	if (sab_lib_err == SAB_LIB_SUCCESS)
		return;

	switch (sab_lib_err) {
	case SAB_LIB_CMD_UNSUPPORTED:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_CMD_UNSUPPORTED (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_CMD_INVALID:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_CMD_INVALID (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_INVALID_MSG_HANDLER:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_INVALID_MSG_HANDLER (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_CMD_MSG_PREP_FAIL:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_CMD_MSG_PREP_FAIL (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_CMD_RSP_TRANSACT_FAIL:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_CMD_RSP_TRANSACT_FAIL (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_RSP_PROC_FAIL:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_RSP_PROC_FAIL (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_CRC_FAIL:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_CRC_FAIL (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_SHE_CANCEL_ERROR:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_SHE_CANCEL_ERROR (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	case SAB_LIB_ERROR:
		se_err("\nSAB LIB Error: CMD [0x%x] SAB_LIB_ERROR (0x%x)\n",
		       msg_id, sab_lib_err);
		break;

	default:
		break;
	}
}

void plat_lib_err_map(uint8_t msg_id, uint32_t plat_lib_err)
{
	switch (plat_lib_err) {
	case PLAT_MEMCPY_FAIL:
		se_err("\nPLAT LIB Error: CMD [0x%x] PLAT_MEMCPY_FAIL\n",
		       msg_id);
		break;
	case PLAT_ERR_OUT_OF_MEMORY:
		se_err("\nPLAT LIB Error: CMD [0x%x] PLAT_ERR_OUT_OF_MEMORY\n",
		       msg_id);
		break;
	case PLAT_DATA_BUF_SETUP_FAIL:
		se_err("\nPLAT LIB Error: CMD [0x%x] PLAT_DATA_BUF_SETUP_FAIL\n",
		       msg_id);
		break;
	case PLAT_SIGNED_MESSAGE_SETUP_FAIL:
		se_err("\nPLAT LIB Error: CMD [0x%x] PLAT_SIGNED_MESSAGE_SETUP_FAIL\n",
		       msg_id);
		break;
	default:
		break;
	}
}
