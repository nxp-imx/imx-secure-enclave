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
#include "seco_mu_ioctl.h"

static char SECO_NVM_SHE_STORAGE_FILE[] = "/etc/seco_she_nvm";

static char V2X_NVM_SHE_STORAGE_FILE[] = "/etc/v2x_she_nvm";
static char V2X_NVM_HSM_STORAGE_FILE[] = "/etc/v2x_hsm/v2x_nvm_master";
static char V2X_NVM_HSM_STORAGE_CHUNK_PATH[] = "/etc/v2x_hsm/";


/* Write data in a file located in NVM. Return the size of the written data. */
int32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl,
				  uint8_t *src, uint32_t size,
				  uint8_t *nvm_fname)
{
	int32_t fd = -1;
	int32_t l = 0;
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
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		path = malloc(strlen(V2X_NVM_HSM_STORAGE_CHUNK_PATH) + 16u);

		if (path != NULL) {
			n = mkdir(V2X_NVM_HSM_STORAGE_CHUNK_PATH,
				  S_IRUSR|S_IWUSR);
			if (n)
				goto exit;

			n = snprintf(path,
				     strlen(V2X_NVM_HSM_STORAGE_CHUNK_PATH) + 16u,
				     "%s%016lx",
				     V2X_NVM_HSM_STORAGE_CHUNK_PATH,
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
	} else if (phdl->type == MU_CHANNEL_V2X_HSM_NVM) {
		path = malloc(strlen(V2X_NVM_HSM_STORAGE_CHUNK_PATH) + 16u);

		if (path != NULL) {
			n = mkdir(V2X_NVM_HSM_STORAGE_CHUNK_PATH,
				  S_IRUSR|S_IWUSR);
			if (n)
				goto exit;
			n = snprintf(path,
				     strlen(V2X_NVM_HSM_STORAGE_CHUNK_PATH) + 16u,
				     "%s%016lx",
				     V2X_NVM_HSM_STORAGE_CHUNK_PATH,
				     blob_id);
		}
	} else {
		path = NULL;
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
