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

static uint32_t get_dir_name(char *path, char *dir_name)
{
	int dir_name_len;
	uint32_t ret = PLAT_FAILURE;
	char *last_slash = strrchr(path, '/');

	if (strlen(last_slash)) {
		dir_name_len = (strlen(path) - strlen(last_slash));

		ret = plat_os_abs_memcpy_v2(dir_name, path, dir_name_len);
		if (ret != PLAT_SUCCESS)
			dir_name_len = 0;

		dir_name[dir_name_len] = '\0';
	}
	return ret;
}

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				   uint8_t *src, uint32_t size,
				   uint8_t *nvm_fname)
{
	int32_t fd;
	int64_t l;
	char nvm_storage_dname[256];

	if (phdl->type == MU_CHANNEL_PLAT_SHE_NVM ||
	    phdl->type == MU_CHANNEL_PLAT_HSM_NVM ||
	    phdl->type == MU_CHANNEL_V2X_SHE_NVM ||
	    phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		/* Open or create the file with access reserved
		 * to the current user.
		 */
		if (get_dir_name(nvm_fname, nvm_storage_dname)) {
			l = PLAT_WRITE_FAILURE;
			goto exit;
		}

		l = mkdir(nvm_storage_dname, 0x600);
		if (l < 0 && errno != EEXIST) {
			l = PLAT_WRITE_FAILURE;
			goto exit;
		}

		/* 0x600 for S_IRUSR | S_IWUSR */
		fd = open(nvm_fname,
			  O_CREAT | O_WRONLY | O_SYNC,
			  0x600);
		if (fd >= 0) {
			/* Write the data. */
			l = write(fd, src, size);
			if (l < 0) {
				l = PLAT_WRITE_FAILURE;
				se_err("Write error [%d]:%s\n", errno,
				       strerror(errno));
			}

			(void)close(fd);
		}
	}
exit:

	return TO_UINT32_T(l);
}

uint32_t plat_os_abs_storage_read(struct plat_os_abs_hdl *phdl,
				  uint8_t *dst, uint32_t size,
				  uint8_t *nvm_fname)
{
	int32_t fd;
	int64_t l = 0;

	if (phdl->type == MU_CHANNEL_PLAT_SHE_NVM ||
	    phdl->type == MU_CHANNEL_PLAT_HSM_NVM ||
	    phdl->type == MU_CHANNEL_V2X_SHE_NVM ||
	    phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		/* Open the file as read only. */
		fd = open(nvm_fname, O_RDONLY);
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

uint32_t get_chunk_file_path(char **path,
			     uint8_t *nvm_storage_dname,
			     struct sab_blob_id *blob_id)
{
	int ret = 0;
	uint64_t path_len;
	uint8_t blob_id_sz = SAB_BLOB_ID_STRUCT_SIZE;

	if (!nvm_storage_dname)
		goto exit;

	path_len = strlen(nvm_storage_dname);

	if (path_len > MAX_FNAME_DNAME_SZ)
		goto exit;

	/* 1 extra byte in path_len is for accommodating null termination char
	 * \0 in path string.
	 */
	path_len += (blob_id_sz * 2) + 1u;

	*path = (char *)plat_os_abs_malloc(path_len);

	if (*path) {
		/* 0x600 for S_IRUSR | S_IWUSR */
		ret = mkdir(nvm_storage_dname, 0x600);

		if (ret < 0 && errno != EEXIST)
			goto exit;

		ret = snprintf(*path,
			       path_len,
			       "%s%0*x%0*x",
			       nvm_storage_dname,
			       (int)(sizeof(blob_id->ext) * 2),
			       blob_id->ext,
			       (int)(sizeof(blob_id->id) * 2),
			       blob_id->id);

		if (ret != (path_len - 1))
			ret = 0;
	}
exit:
	return (ret <= 0 ? 0u : ret);
}

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write_chunk(struct plat_os_abs_hdl *phdl,
					 uint8_t *src,
					 uint32_t size,
					 struct sab_blob_id *blob_id,
					 uint8_t *nvm_storage_dname)
{
	int32_t fd;
	int64_t l = 0;
	uint32_t n = 0;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_SHE_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else {
		path = NULL;
	}

	if (n > 0) {
		/* Open or create the file with access reserved
		 * to the current user.
		 */
		/* 0x600 for S_IRUSR | S_IWUSR */
		fd = open(path, O_CREAT | O_WRONLY | O_SYNC, 0x600);
		if (fd >= 0) {
			/* Write the data. */
			l = write(fd, src, size);
			if (l < 0) {
				l = PLAT_WRITE_FAILURE;
				se_err("chunk-Write error [%d]:%s\n", errno,
				       strerror(errno));
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
					struct sab_blob_id *blob_id,
					uint8_t *nvm_storage_dname)
{
	int32_t fd;
	int64_t l = 0;
	uint32_t n = 0;
	char *path = NULL;

	if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
	} else if (phdl->type == MU_CHANNEL_V2X_SHE_NVM) {
		n = get_chunk_file_path(&path, nvm_storage_dname, blob_id);
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
				se_err("Chunk-Read error [%d]:%s\n", errno,
				       strerror(errno));
			}

			(void)close(fd);
		}
	}

	if (path)
		plat_os_abs_free(path);

	return TO_UINT32_T(l);
}
