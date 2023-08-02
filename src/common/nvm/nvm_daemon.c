/*
 * Copyright 2022-2023 NXP
 */

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *
 * @file nvm_daemon.c
 *
 * @brief Background process to handle secure-enclave blob interaction
 *
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include "nvm.h"
#include "plat_os_abs.h"
#include "plat_utils.h"

/** Status variable required by nvm_manager call */
static void *nvm_ctx;

/**
 *
 * @brief Changes the status of NVM for closing the NVM session
 *
 * This function is called when the NVM process receives a SIGTERM (command to
 * stop the service) or SIGINT (CTRL + C) signal.
 *
 * The flow to reach this handler, depends on where the signal interrupt occurred:
 *	i. Either directly in user space of NVM process, or
 *	ii. In case of NVM waiting on read in kernel space, the signal would be
 *	    first handled in kernel space and reach this user space handler for
 *	    the same signal.)
 *
 * It changes the status of NVM to close the NVM session.
 *
 */
void kill_daemon(int ip)
{
	set_nvmd_status_stop(nvm_ctx);
}

/**
 *
 * @brief The main function of the nvm_daemon
 *
 * This function simply calls a helper function provided by secure-enclave
 * library.
 * This helper function must run in a separate thread before using
 * secure-enclave based HSM API(s), and handles HSM fs requests for
 * blob handling.
 *
 * @param argc the number of command line arguments, including program name
 * @param argv an array giving the command line arguments
 *
 * @return helper function should never exit, but returns 1 if it does
 *
 */

int main(int argc, char *argv[])
{
	struct sigaction action = {0};
	int flags = 0;
	uint32_t err = 0;

	if (argc < 4) {
		printf("Usage: ./nvm_daemon <file_name> <directory> <flag>\n");
		return 0;
	}

	/* Register handler to close NVM session upon daemon's closure */
	action.sa_handler = kill_daemon;

	/* handle kill signal */
	if (sigaction(SIGTERM, &action, NULL))
		se_warn("failed to register kill signal handler\n");

	/* handle ctrl-c */
	if (sigaction(SIGINT, &action, NULL))
		se_warn("failed to register ctrl-c signal handler\n");

	flags = atoi(argv[3]);

	if (flags < 0) {
		se_err("Invalid flag value %d\n", flags);
		return 0;
	}

	err = nvm_manager((uint8_t)(flags), &nvm_ctx, argv[1], argv[2]);
	if (err)
		printf("Error: NVM Daemon exited with error(0x%x).\n", err);

	/* return an error as the daemon is never supposed to end */
	return 0;
}
