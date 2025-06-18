// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/reboot.h>
#include <sys/syscall.h>

#include "crrm_api.h"

hsm_err_t crrm_test_recovery_install(hsm_hdl_t crrm_hdl)
{
	op_get_boot_mode_args_t gargs = {0};
	op_set_boot_mode_args_t sargs = {0};
	hsm_err_t err;
	int32_t ret;

	err = crrm_get_boot_mode(crrm_hdl, &gargs);
	printf("Current Boot mode is 0x%x\n", gargs.boot_mode);

	if (gargs.boot_mode == RECOVERY_DOWNLOAD_BOOT_MODE) {
		sargs.new_boot_mode = RECOVERY_INSTALL_BOOT_MODE;
		/* expecting flash_install.bin is already available in eMMC part1*/
		err = crrm_set_boot_mode(crrm_hdl, &sargs);
		printf("Boot mode is new : 0x%x: stored : %d\n",
		       sargs.new_boot_mode, sargs.stored_boot_mode);

		if (sargs.stored_boot_mode == RECOVERY_INSTALL_BOOT_MODE) {
			/*
			 * TODO will call ELE reset API to reset the board.
			 * https://jira.sw.nxp.com/browse/S400-4404
			 * currently ELE RESET is resulting in ele abort
			 */
			ret = syscall(__NR_reboot,
				      LINUX_REBOOT_MAGIC1,
				      LINUX_REBOOT_MAGIC2,
				      LINUX_REBOOT_CMD_RESTART2,
				      "board_reset");

			if (ret == -1) {
				printf("Reboot error: %d\n", errno);
				printf("Execute reset command from SM console\n");
			}
		} else {
			printf("Failed to set RECOVERY_INSTALL mode\n");
		}
	}

	return err;
}
