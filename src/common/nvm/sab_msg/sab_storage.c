/*
 * Copyright 2022 NXP
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

#include "sab_messaging.h"
#include "sab_msg_def.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t sab_open_storage_command(struct plat_os_abs_hdl *phdl,
				  uint32_t session_handle,
				  uint32_t *storage_handle,
				  uint32_t mu_type,
				  uint8_t flags)
{
	struct sab_cmd_storage_open_msg cmd = {0};
	struct sab_cmd_storage_open_rsp rsp = {0};
	int32_t error = 1;
	uint32_t ret = SAB_FAILURE_STATUS;

	do {
		/* Send the Storage open command to Platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_STORAGE_OPEN_REQ,
				      (uint32_t)
				      sizeof(struct sab_cmd_storage_open_msg),
				      mu_type);
		cmd.session_handle = session_handle;
		cmd.input_address_ext = 0u;
		cmd.output_address_ext = 0u;
		cmd.flags = flags;
		cmd.crc = plat_compute_msg_crc((uint32_t *)&cmd,
					       (uint32_t)
					       (sizeof(cmd) - sizeof(uint32_t))
					      );

		/* Send the message to Platform. */
		error = plat_send_msg_and_get_resp(phdl,
						   (uint32_t *)&cmd,
						   (uint32_t)
							sizeof(struct
							sab_cmd_storage_open_msg
							),
						   (uint32_t *)&rsp,
						   (uint32_t)
							sizeof(struct
							sab_cmd_storage_open_rsp
							)
						   );
		if (error != 0) {
			ret = rsp.rsp_code ? rsp.rsp_code : ret;
			break;
		}

		ret = rsp.rsp_code;
		*storage_handle = rsp.storage_handle;

	} while (false);

	return ret;
}

uint32_t sab_close_storage_command(struct plat_os_abs_hdl *phdl,
				   uint32_t storage_handle,
				   uint32_t mu_type)
{
	struct sab_cmd_storage_close_msg cmd = {0};
	struct sab_cmd_storage_close_rsp rsp = {0};
	int32_t error = 1;
	uint32_t ret = SAB_FAILURE_STATUS;

	do {
		/* Send the Storage close command to Platform. */
		plat_fill_cmd_msg_hdr(&cmd.hdr,
				      SAB_STORAGE_CLOSE_REQ,
				      (uint32_t) sizeof(struct
							sab_cmd_storage_close_msg),
				      mu_type);
		cmd.storage_handle = storage_handle;
		error = plat_send_msg_and_get_resp(phdl, (uint32_t *)&cmd,
						   (uint32_t) sizeof(struct
								sab_cmd_storage_close_msg),
						   (uint32_t *)&rsp,
						   (uint32_t) sizeof(struct
								sab_cmd_storage_close_rsp)
						  );

		if (error != 0) {
			ret = rsp.rsp_code ? rsp.rsp_code : ret;
			break;
		}

		ret = rsp.rsp_code;
	} while (false);

	return ret;
}
