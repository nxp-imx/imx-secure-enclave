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

/** Status variable required by nvm_manager call */
static void *nvm_ctx;

/**
 *
 * @brief Close the NVM session and exit process
 *
 * This function is called when the process receives a SIGTERM signal.
 * It closes the NVM session before exiting.
 *
 */
void kill_daemon(int ip)
{
	nvm_close_session(nvm_ctx);
	exit(0);
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
	int err = 0;

	if (argc < 3) {
		printf("Usage: ./nvm_daemon <file_name> <directory>\n");
		return 0;
	}

	/* Register handler to close NVM session upon daemon's closure */
	action.sa_handler = kill_daemon;
	sigaction(SIGTERM, &action, NULL); /* handle kill signal */
	sigaction(SIGINT, &action, NULL);  /* handle ctrl-c */

	flags |= NVM_FLAGS_HSM;
	if (plat_os_abs_has_v2x_hw()) {
		flags |= NVM_FLAGS_V2X;
	}

	err = nvm_manager(flags, &nvm_ctx, argv[1], argv[2]);
	if (err)
		printf("Error: NVM Daemon exited with error(0x%x).\n", err);

	/* return an error as the daemon is never supposed to end */
	return 0;
}
