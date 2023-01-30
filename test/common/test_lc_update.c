/*
 * Copyright 2023 NXP
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
#include <stdint.h>

#include "hsm_api.h"
#include "common.h"

void lc_update_info(hsm_hdl_t sess_hdl)
{
	op_lc_update_msg_args_t args;
#if HSM_DEV_GETINFO
	op_dev_getinfo_args_t dev_getinfo_args = {0};
	hsm_err_t err;

	err = hsm_dev_getinfo(sess_hdl, &dev_getinfo_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_dev_getinfo(ROM) failed err:0x%x\n", err);
	else {
		if (dev_getinfo_args.imem_state == 0xca) {
			/* Firmware is present.
			 * Tests can be performed.
			 */
			args.new_lc_state = HSM_OEM_OPEN_STATE;
			err = hsm_lc_update(sess_hdl, &args);
			if (err != HSM_NO_ERROR) {
				printf("hsm_lc_update(ROM) failed err:0x%x\n", err);
			}
		}
	}
#endif
}