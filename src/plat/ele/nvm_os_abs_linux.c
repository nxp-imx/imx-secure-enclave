/*
 * Copyright 2021-2023 NXP
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

#include "errno.h"

#include "she_api.h"
#include "plat_os_abs.h"
#include "plat_utils.h"
#include "ele_mu_ioctl.h"

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				   uint8_t *src, uint32_t size,
				   uint8_t *nvm_fname)
{
	int32_t fd = -1;
	int64_t l = 0;
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
			l = write(fd, src, size);
			if (l < 0) {
				l = PLAT_WRITE_FAILURE;
				se_err("Write error [%d]:%s\n", errno, strerror(errno));
			}

			(void)close(fd);
		}
	}

	return TO_UINT32_T(l);
}

uint32_t plat_os_abs_storage_read(struct plat_os_abs_hdl *phdl,
				  uint8_t *dst, uint32_t size,
				  uint8_t *nvm_fname)
{
	int32_t fd = -1;
	int64_t l = 0;
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
			l = read(fd, dst, size);
			if (l < 0) {
				l = PLAT_READ_FAILURE;
				se_err("Read error [%d]:%s\n", errno, strerror(errno));
			}

			(void)close(fd);
		}
	}
	return TO_UINT32_T(l);
}

int get_chunk_file_path(char **path,
			uint8_t *nvm_storage_dname,
			uint64_t blob_id)
{
	int ret = -1;
	uint64_t path_len;
	uint8_t blob_id_sz = sizeof(blob_id);

	if (!nvm_storage_dname)
		goto exit;

	/* 1 extra byte in path_len is for accommodating null termination char
	 * \0 in path string.
	 */
	path_len = strlen(nvm_storage_dname) + blob_id_sz * 2 + 1u;

	if (path_len > (2 * MAX_FNAME_DNAME_SZ))
		goto exit;

	*path = malloc(path_len);

	if (*path) {
		ret = mkdir(nvm_storage_dname, S_IRUSR|S_IWUSR);

		if ((ret < 0) && (errno != EEXIST))
			goto exit;

		ret = snprintf(*path,
				path_len,
				"%s%0*lx",
				nvm_storage_dname,
				(int)blob_id_sz * 2,
				blob_id);

		if (ret != (path_len - 1))
			ret = -1;
	}

exit:
	return ret;
}

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write_chunk(struct plat_os_abs_hdl *phdl,
					 uint8_t *src,
					 uint32_t size,
					 uint64_t blob_id,
					 uint8_t *nvm_storage_dname)
{
	int32_t fd = -1;
	int64_t l = 0;
	int n = -1;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM)
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);

	if (n > 0) {
		/* Open or create the file with access reserved
		 * to the current user.
		 */
		fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
		if (fd >= 0) {
			/* Write the data. */
			l = write(fd, src, size);
			if (l < 0) {
				l = PLAT_WRITE_FAILURE;
				se_err("Write error [%d]:%s\n", errno, strerror(errno));
			}

			(void)close(fd);
		}
	}
exit:
	if (path)
		free(path);

	return TO_UINT32_T(l);
}

uint32_t plat_os_abs_storage_read_chunk(struct plat_os_abs_hdl *phdl,
					uint8_t *dst, uint32_t size,
					uint64_t blob_id,
					uint8_t *nvm_storage_dname)
{
	int32_t fd;
	int64_t l = 0;
	int n = -1;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM)
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);

	if (n > 0) {
		/* Open the file as read only. */
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			/* Read the data. */
			l = read(fd, dst, size);
			if (l < 0) {
				l = PLAT_READ_FAILURE;
				se_err("Read error [%d]:%s\n", errno, strerror(errno));
			}

			(void)close(fd);
		}
	}

	if (path)
		free(path);

	return TO_UINT32_T(l);
}
