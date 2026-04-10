// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
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

#include "session.h"
#include "plat_os_abs.h"
#include "plat_utils.h"

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				   uint8_t *src, uint32_t size,
				   uint8_t *nvm_fname)
{
	int32_t fd;
	int64_t l = 0;
	char *path;

	switch (phdl->type) {
	case HSM_NVM:
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

			fsync(fd);
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
	case HSM_NVM:
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
		ret = mkdir(nvm_storage_dname, S_IRUSR|S_IWUSR);

		if ((ret < 0) && (errno != EEXIST))
			goto exit;

		ret = snprintf(*path,
				path_len,
				"%s%0*x%0*x%0*x",
				nvm_storage_dname,
				(int)(sizeof(blob_id->ext) * 2),
				blob_id->ext,
				(int)(sizeof(blob_id->id) * 2),
				blob_id->id,
				(int)(sizeof(blob_id->metadata) * 2),
				blob_id->metadata);

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

	if (phdl->type == HSM_NVM)
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

			fsync(fd);
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

	if (phdl->type == HSM_NVM)
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
		plat_os_abs_free(path);

	return TO_UINT32_T(l);
}

uint32_t plat_os_abs_storage_remove_file(char *filename, char *dirname)
{
	uint32_t ret = PLAT_SUCCESS;
	int err;
	int dir_fd;

	err = remove(filename);
	if (err) {
		se_err("remove error [%d]: %s\n", errno, strerror(errno));

		ret = PLAT_FAILURE;
		if (errno == ENOENT)
			ret = PLAT_ERR_NO_SUCH_FILE_DIR;
	}

	dir_fd = open(dirname, O_DIRECTORY | O_RDONLY);
	if (dir_fd < 0) {
		se_err("failed to open directory and sync [%d]: %s\n",
		       errno, strerror(errno));
	} else {
		fsync(dir_fd);
		close(dir_fd);
	}

	return ret;
}
