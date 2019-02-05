
/*
 * Copyright 2019 NXP
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
#include <errno.h>
#include "she.h"

#define SECO_MU_PATH "/dev/seco_mu"

she_hdl *she_platform_open_session(void) {
	return (she_hdl *)fopen(SECO_MU_PATH, "w+");
};

void she_platform_close_session(she_hdl *hdl) {
	fclose((FILE *)hdl);
}

int she_platform_send_mu_message(she_hdl *hdl, char *message, int size) {
	return fwrite(message, 1, size, (FILE *)hdl);
}

int she_platform_read_mu_message(she_hdl *hdl, char *message, int size) {
	return fread(message, 1, size, (FILE *)hdl);
};