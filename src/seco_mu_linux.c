
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <zlib.h>
#include "she_api.h"
#include "she_platform.h"
#include "seco_mu_ioctl.h"

#define SECO_MU_PATH "/dev/seco_mu_0"
#define SECO_NVM_PATH "/dev/seco_mu_1"
#define SECO_NVM_DEFAULT_STORAGE_FILE "/etc/seco_nvm"

struct she_platform_hdl {
	int32_t fd;
	pthread_t tid;
};

/* Open a SHE session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct she_platform_hdl *she_platform_open_she_session(void)
{
	struct she_platform_hdl *phdl = malloc(sizeof(struct she_platform_hdl));

	if (phdl) {
		phdl->fd = open(SECO_MU_PATH, O_RDWR);
		/* If open failed return NULL handle. */
		if (phdl->fd < 0) {
			free(phdl);
			phdl = NULL;
		}
	}
	return phdl;
};

/* Open a storage session over the MU. */
struct she_platform_hdl *she_platform_open_storage_session(void)
{
	struct she_platform_hdl *phdl = malloc(sizeof(struct she_platform_hdl));

	if (phdl) {
		phdl->fd = open(SECO_NVM_PATH, O_RDWR);
		/* If open failed return NULL handle. */
		if (phdl->fd < 0) {
			free(phdl);
			phdl = NULL;
		} else {
			/* If open is successful then configure the device to accept incoming commands. */
			if (ioctl(phdl->fd, SECO_MU_IOCTL_ENABLE_CMD_RCV)) {
				free(phdl);
				phdl = NULL;
			}
		}
	}
	return phdl;
};

/* Close a previously opened session (SHE or storage). */
void she_platform_close_session(struct she_platform_hdl *phdl)
{
	/* Close the device. */
	(void)close(phdl->fd);

	free(phdl);
}

/* Send a message to Seco on the MU. Return the size of the data written. */
uint32_t she_platform_send_mu_message(struct she_platform_hdl *phdl, uint8_t *message, uint32_t size)
{
	return write(phdl->fd, message, size);
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
uint32_t she_platform_read_mu_message(struct she_platform_hdl *phdl, uint8_t *message, uint32_t size)
{
	return read(phdl->fd, message, size);
};

/* Map the shared buffer allocated by Seco. */
int32_t she_platform_configure_shared_buf(struct she_platform_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
	int32_t error;
	struct seco_mu_ioctl_shared_mem_cfg cfg;

	cfg.base_offset = shared_buf_off;
	cfg.size = size;
	error = ioctl(phdl->fd, SECO_MU_IOCTL_SHARED_BUF_CFG, &cfg);

	return error;
}


uint64_t she_platform_data_buf(struct she_platform_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
{
	struct seco_mu_ioctl_setup_iobuf io;
	uint32_t err;

	io.user_buf = src;
	io.length = size;
	io.flags = flags;

	err = ioctl(phdl->fd, SECO_MU_IOCTL_SETUP_IOBUF, &io);

	if (err)
		io.seco_addr = 0;

	return io.seco_addr;
}

/* Start a new thread. Return 0 in case of success or an non-null code in case of error. */
int32_t she_platform_create_thread(struct she_platform_hdl *phdl, void * (*func)(void *arg), void * arg)
{
	int32_t err;
	err = pthread_create(&phdl->tid, NULL, func, arg);
	return err;
}

/* Cancel a previously created thread. Return 0 in case of success or an non-null code in case of error. */
int32_t she_platform_cancel_thread(struct she_platform_hdl *phdl)
{
	int32_t err;
	err = pthread_cancel(phdl->tid);

	return err;
}


uint32_t she_platform_crc(uint8_t *data, uint32_t size)
{
	return  crc32(0, data, size);
}


/* Write data in a file located in NVM. Return the size of the written data. */
uint32_t she_platform_storage_write(struct she_platform_hdl *phdl, uint8_t *src, uint32_t size)
{
	int32_t fd = -1;
	uint32_t l = 0;

	/* Open or create the file with access reserved to the current user. */
	fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
	if (fd >= 0) {
		/* Write the data. */
		l = write(fd, src, size);

		(void)close(fd);
	}

	return l;
}

uint32_t she_platform_storage_read(struct she_platform_hdl *phdl, uint8_t *dst, uint32_t size)
{
	int32_t fd = -1;
	uint32_t l = 0;

	/* Open the file as read only. */
	fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_RDONLY);
	if (fd >= 0) {
		/* Read the data. */
		l = read(fd, dst, size);

		(void)close(fd);
	}

	return l;
}
