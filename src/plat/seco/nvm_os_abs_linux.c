// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
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

#include "she_api.h"
#include "plat_os_abs.h"
#include "plat_utils.h"
#include "seco_mu_ioctl.h"

static char SECO_NVM_SHE_STORAGE_FILE[] = "/etc/seco_she_nvm";

static char V2X_NVM_SHE_STORAGE_FILE[] = "/etc/v2x_she_nvm";
static char V2X_NVM_HSM_STORAGE_FILE[] = "/etc/v2x_hsm/v2x_nvm_master";
static char V2X_NVM_HSM_STORAGE_CHUNK_PATH[] = "/etc/v2x_hsm/";


/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				   uint8_t *src, uint32_t size,
				   uint8_t *nvm_fname)
{
	int32_t fd;
	int64_t l = 0;
	char *path;

	switch (phdl->type) {
	case MU_CHANNEL_PLAT_SHE_NVM:
		path = SECO_NVM_SHE_STORAGE_FILE;
		break;
	case MU_CHANNEL_PLAT_HSM_NVM:
		path = nvm_fname;
		break;
	case MU_CHANNEL_V2X_SHE_NVM:
		path = V2X_NVM_SHE_STORAGE_FILE;
		break;
	case MU_CHANNEL_V2X_HSM_NVM:
		path = V2X_NVM_HSM_STORAGE_FILE;
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
	int32_t fd;
	int64_t l = 0;
	char *path;

	switch (phdl->type) {
	case MU_CHANNEL_PLAT_SHE_NVM:
		path = SECO_NVM_SHE_STORAGE_FILE;
		break;
	case MU_CHANNEL_PLAT_HSM_NVM:
		path = nvm_fname;
		break;
	case MU_CHANNEL_V2X_SHE_NVM:
		path = V2X_NVM_SHE_STORAGE_FILE;
		break;
	case MU_CHANNEL_V2X_HSM_NVM:
		path = V2X_NVM_HSM_STORAGE_FILE;
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

	path_len = strlen(nvm_storage_dname);

	if (path_len > MAX_FNAME_DNAME_SZ)
		goto exit;

	/* 1 extra byte in path_len is for accommodating null termination char
	 * \0 in path string.
	 */
	path_len += (blob_id_sz * 2);

	*path = (char *)plat_os_abs_malloc(path_len);

	if (*path) {
		/* 0x600 for S_IRUSR | S_IWUSR */
		ret = mkdir(nvm_storage_dname, 0x600);

		if (ret < 0 && errno != EEXIST)
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
	int32_t fd;
	int64_t l = 0;
	int n = -1;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		n = get_chunk_file_path(&path, V2X_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
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
			l = write(fd, src, size);
			if (l < 0) {
				l = PLAT_WRITE_FAILURE;
				se_err("Write error [%d]:%s\n", errno, strerror(errno));
			}

			(void)close(fd);
		}
	}

	if (path)
		plat_os_abs_free(path);

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

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		n = get_chunk_file_path(&path, V2X_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
	} else {
		path = NULL;
	}

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
		plat_os_abs_free(path);

	return TO_UINT32_T(l);
}
