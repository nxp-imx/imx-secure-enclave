// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <stdio.h>
#include <dirent.h>
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

	return l;
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
	return l;
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

	return l;
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

	return l;
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

/* Open directory for reading files */
void *plat_os_abs_open_dir(uint8_t *dirname)
{
	DIR *dir = opendir((const char *)dirname);

	if (!dir)
		se_err("Failed to open directory [%d]: %s\n", errno, strerror(errno));

	return (void *)dir;
}

/* Read next filename from directory */
uint8_t *plat_os_abs_read_dir(void *dir_handle)
{
	struct dirent *entry;
	DIR *dir = (DIR *)dir_handle;

	if (!dir)
		return NULL;

	entry = readdir(dir);
	if (!entry)
		return NULL;

	return (uint8_t *)entry->d_name;
}

/* Close directory */
void plat_os_abs_close_dir(void *dir_handle)
{
	DIR *dir = (DIR *)dir_handle;

	if (dir)
		closedir(dir);
}

/* Get file size */
uint32_t plat_os_abs_storage_get_size(struct plat_os_abs_hdl *phdl,
				      uint8_t *nvm_fname)
{
	struct stat file_stat;
	char *path;
	uint32_t file_size = 0;

	path = (char *)nvm_fname;
	if (path) {
		/* Get file statistics */
		if (stat(path, &file_stat) == 0) {
			if (file_stat.st_size < 0) {
				se_err("Invalid file size (negative): %s\n", path);
				file_size = 0;
			} else if (file_stat.st_size > UINT32_MAX) {
				se_err("File size exceeds UINT32_MAX: %s (size: %ld)\n",
				       path, (long)file_stat.st_size);
				file_size = 0;
			} else {
				file_size = (uint32_t)file_stat.st_size;
			}
		} else {
			se_err("Failed to stat file [%d]: %s\n",
			       errno, strerror(errno));
		}
	}

	return file_size;
}

/* Truncate a file to specified size */
uint32_t plat_os_abs_storage_truncate(struct plat_os_abs_hdl *phdl,
				      uint8_t *nvm_fname,
				      uint32_t size)
{
	char *path;
	uint32_t ret = PLAT_SUCCESS;

	path = (char *)nvm_fname;

	if (path) {
		if (truncate(path, (off_t)size) != 0) {
			se_err("Failed to truncate file [%d]: %s\n",
			       errno, strerror(errno));
			ret = PLAT_FAILURE;
		}
	} else {
		ret = PLAT_FAILURE;
	}

	return ret;
}

/* Delete a file */
uint32_t plat_os_abs_storage_delete(struct plat_os_abs_hdl *phdl, uint8_t *filename)
{
	uint32_t ret = PLAT_SUCCESS;
	int err;

	if (!filename) {
		se_err("Error: NULL filename provided\n");
		return PLAT_FAILURE;
	}

	err = remove((const char *)filename);
	if (err) {
		se_err("Failed to delete file [%d]: %s\n", errno, strerror(errno));
		ret = PLAT_FAILURE;

		if (errno == ENOENT)
			ret = PLAT_ERR_NO_SUCH_FILE_DIR;
	}

	return ret;
}
