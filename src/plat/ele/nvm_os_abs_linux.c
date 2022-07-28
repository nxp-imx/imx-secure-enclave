/*
 * Copyright 2021-2022 NXP
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
#include "she_api.h"
#include "plat_os_abs.h"
#include "ele_mu_ioctl.h"

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				  uint8_t *src, uint32_t size,
				  uint8_t *nvm_fname)
{
	int32_t fd = -1;
	int32_t l = 0;
	char *path;

	switch (phdl->type) {
	case MU_CHANNEL_PLAT_HSM_NVM:
		path = nvm_fname;
		break;
	default:
		path = NULL;
		break;
	}
	if (path != NULL) {
		/* Open or create the file with access reserved
		 * to the current user.
		 */
		fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
		if (fd >= 0) {
			/* Write the data. */
			l = (int32_t)write(fd, src, size);

			(void)close(fd);
		}
	}

	return l;
}

int32_t plat_os_abs_storage_read(struct plat_os_abs_hdl *phdl,
				 uint8_t *dst, uint32_t size,
				 uint8_t *nvm_fname)
{
	int32_t fd = -1;
	int32_t l = 0;
	char *path;

	switch (phdl->type) {
	case MU_CHANNEL_PLAT_HSM_NVM:
		path = nvm_fname;
		break;
	default:
		path = NULL;
		break;
	}

	if (path != NULL) {
		/* Open the file as read only. */
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			/* Read the data. */
			l = (int32_t)read(fd, dst, size);

			(void)close(fd);
		}
	}
	return l;
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t plat_os_abs_storage_write_chunk(struct plat_os_abs_hdl *phdl,
					uint8_t *src,
					uint32_t size,
					uint64_t blob_id,
					uint8_t *nvm_storage_dname)
{
	int32_t fd = -1;
	int32_t l = 0;
	int n = -1;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		path = malloc(strlen(nvm_storage_dname) + 16u);
		if (path != NULL) {
			n = mkdir(nvm_storage_dname,
				  S_IRUSR|S_IWUSR);
			if (n)
				goto exit;

			n = snprintf(path,
				     strlen(nvm_storage_dname) + 16u,
				     "%s%016lx",
				     nvm_storage_dname,
				     blob_id);
		}
	} else {
		path = NULL;
	}

	if (n > 0) {
		/* Open or create the file with access reserved
		 * to the current user.
		 */
		fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
		if (fd >= 0) {
			/* Write the data. */
			l = (int32_t)write(fd, src, size);

			(void)close(fd);
		}
	}
exit:
	free(path);
	return l;
}

int32_t plat_os_abs_storage_read_chunk(struct plat_os_abs_hdl *phdl,
				       uint8_t *dst, uint32_t size,
				       uint64_t blob_id,
				       uint8_t *nvm_storage_dname)
{
	int32_t fd = -1;
	int32_t l = 0;
	int n = -1;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		path = malloc(strlen(nvm_storage_dname) + 16u);

		if (path != NULL) {
			n = mkdir(nvm_storage_dname,
				  S_IRUSR|S_IWUSR);
			if (n)
				goto exit;
			n = snprintf(path,
				     strlen(nvm_storage_dname) + 16u,
				     "%s%016lx",
				     nvm_storage_dname,
				     blob_id);
		}
	}

	if (n > 0) {
		/* Open the file as read only. */
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			/* Read the data. */
			l = (int32_t)read(fd, dst, size);

			(void)close(fd);
		}
	}
exit:
	free(path);
	return l;
}
