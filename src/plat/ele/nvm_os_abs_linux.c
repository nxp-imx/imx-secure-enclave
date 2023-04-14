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

/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				   uint8_t *src, uint32_t size,
				   uint8_t *nvm_fname)
{
	int32_t fd;
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
	int32_t fd;
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

	path_len = strlen(nvm_storage_dname);

	if (path_len > MAX_FNAME_DNAME_SZ)
		goto exit;

	/* 1 extra byte in path_len is for accommodating null termination char
	 * \0 in path string.
	 */
	path_len += (blob_id_sz * 2) + 1u;

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
	int32_t fd;
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

#ifdef MT_SAB_STORAGE_KEY_DB_REQ
int plat_os_abs_storage_open_key_db_fd(uint8_t *path, int flags, uint32_t mode)
{
	return open(path, flags, mode);
}

int plat_os_abs_storage_close_key_db_fd(int fd)
{
	return close(fd);
}

uint32_t plat_os_abs_storage_get_file_size(int fd, size_t *file_size)
{
	uint32_t err = PLAT_FAILURE;
	struct stat f_stat = { 0 };

	if (!file_size)
		goto out;

	if (!fstat(fd, &f_stat) && f_stat.st_size >= 0) {
		*file_size = (size_t)f_stat.st_size;
		err = PLAT_SUCCESS;
	} else {
		se_err("fstat error [%d]:%s\n", errno, strerror(errno));
	}

out:
	return err;
}

uint32_t plat_os_abs_storage_pread(int fd, void *buffer, size_t size, off_t offset,
				   size_t *size_read)
{
	uint32_t err = PLAT_FAILURE;
	ssize_t read;

	if (!buffer || !size_read)
		goto out;

	read = pread(fd, buffer, size, offset);
	if (read >= 0) {
		*size_read = (size_t)read;
		err = PLAT_SUCCESS;
	} else {
		se_err("Read error [%d]:%s\n", errno, strerror(errno));
	}

out:
	return err;
}

uint32_t plat_os_abs_storage_pwrite(int fd, void *buffer, size_t size, off_t offset,
				    size_t *size_written)
{
	uint32_t err = PLAT_FAILURE;
	ssize_t write;

	if (!buffer || !size_written)
		goto out;

	write = pwrite(fd, buffer, size, offset);
	if (write >= 0) {
		if (fsync(fd)) {
			se_err("Sync error [%d]:%s\n", errno, strerror(errno));
		} else {
			*size_written = (size_t)write;
			err = PLAT_SUCCESS;
		}
	} else {
		se_err("Write error [%d]:%s\n", errno, strerror(errno));
	}

out:
	return err;
}

uint32_t plat_os_abs_storage_file_truncate(int fd, off_t length)
{
	uint32_t err = PLAT_FAILURE;

	if (!ftruncate(fd, length)) {
		if (!fsync(fd))
			err = PLAT_SUCCESS;
	}

	return err;
}

uint32_t plat_os_abs_storage_remove_file(char *filename)
{
	uint32_t ret = PLAT_FAILURE;
	int err;

	err = remove(filename);
	if (!err || (err && errno == ENOENT))
		ret = PLAT_SUCCESS;

	return ret;
}
#endif
