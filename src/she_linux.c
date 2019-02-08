
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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "she_api.h"

#define SECO_MU_PATH "/dev/seco_mu"

struct she_linux_hdl{
	FILE *fptr;
	void *sec_mem;
	int sec_mem_size;
	int shared_buf_off;
};

she_hdl *she_platform_open_session(void) {
	struct she_linux_hdl *lhdl = malloc(sizeof(struct she_linux_hdl));

	if (lhdl) {
		lhdl->fptr = fopen(SECO_MU_PATH, "w+");
		lhdl->sec_mem = NULL;
	}
	return (she_hdl *)lhdl;
};

void she_platform_close_session(she_hdl *hdl) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	if (lhdl->sec_mem)
		munmap(lhdl->sec_mem, lhdl->sec_mem_size);
	fclose(lhdl->fptr);
	free(hdl);
}

int she_platform_send_mu_message(she_hdl *hdl, char *message, int size) {
	return fwrite(message, 1, size, ((struct she_linux_hdl *)hdl)->fptr);
}

int she_platform_read_mu_message(she_hdl *hdl, char *message, int size) {
	return fread(message, 1, size, ((struct she_linux_hdl *)hdl)->fptr);
};

void she_platform_configure_shared_buf(she_hdl *hdl, int shared_buf_off, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	lhdl->shared_buf_off = shared_buf_off;
	lhdl->sec_mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(lhdl->fptr), shared_buf_off);
	lhdl->sec_mem_size = size;
}

int she_platform_copy_to_shared_buf(she_hdl *hdl, int dst_off, void *src, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	if (!lhdl->sec_mem)
		return 0;
	/* TODO: check on the size vs. lenght of the allocated sec_mem buffer. */
	memcpy(lhdl->sec_mem + dst_off, src, size);

	return size;
}

int she_platform_copy_from_shared_buf(she_hdl *hdl, int src_off, void *dst, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	if (!lhdl->sec_mem)
		return 0;
	memcpy(dst, lhdl->sec_mem + src_off, size);

	return size;
}

int she_platform_shared_buf_offset(she_hdl *hdl) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	return lhdl->shared_buf_off;
}