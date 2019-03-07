
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <zlib.h>
#include "she_api.h"
#include "she_platform.h"

#define SECO_MU_PATH "/dev/seco_mu"
#define SECO_NVM_PATH "/dev/seco_nvm"

struct she_platform_hdl {
	int32_t fd;
	uint8_t *sec_mem;
	uint32_t sec_mem_size;
	uint32_t shared_buf_off;
};

/* Open a SHE session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct she_platform_hdl *she_platform_open_she_session(void)
{
	struct she_platform_hdl *phdl = malloc(sizeof(struct she_platform_hdl));

	if (phdl) {
		/* Force secure memory pointer to NULL since it hasn't been allocated yet. */
		phdl->sec_mem = NULL;

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
		/* Force secure memory pointer to NULL since it hasn't been allocated yet. */
		phdl->sec_mem = NULL;

		phdl->fd = open(SECO_NVM_PATH, O_RDWR);
		/* If open failed return NULL handle. */
		if (phdl->fd < 0) {
			free(phdl);
			phdl = NULL;
		}
	}
	return phdl;
};

/* Close a previously opened session (SHE or storage). */
void she_platform_close_session(struct she_platform_hdl *phdl)
{
	/* Unmap the secure memory if needed. */
	if (phdl->sec_mem) {
		(void)munmap(phdl->sec_mem, phdl->sec_mem_size);
	}

	/* Close the device. */
	(void)close(phdl->fd);

	free(phdl);
}

/* Send a message to Seco on the MU. Return the size of the data written. */
uint32_t she_platform_send_mu_message(struct she_platform_hdl *phdl, uint32_t *message, uint32_t size)
{
	return write(phdl->fd, message, size);
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
uint32_t she_platform_read_mu_message(struct she_platform_hdl *phdl, uint32_t *message, int32_t size)
{
	return read(phdl->fd, message, size);
};

/* Map the shared buffer allocated by Seco. */ 
int32_t she_platform_configure_shared_buf(struct she_platform_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
	int32_t error;
	phdl->shared_buf_off = shared_buf_off;
	phdl->sec_mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, phdl->fd, shared_buf_off);
	if (phdl->sec_mem != MAP_FAILED) {
		phdl->sec_mem_size = size;
		error = 0;
	} else {
		/* mmap failed. force the shared memory pointer to NULL and report error. */
		phdl->sec_mem = NULL;
		phdl->sec_mem_size = 0;
		error = 1;
	}
	return error;
}

/* Copy data to the shared buffer. Return the copied length. */
uint32_t she_platform_copy_to_shared_buf(struct she_platform_hdl *phdl, uint32_t dst_off, void *src, uint32_t size)
{
	uint32_t l = 0;

	/* Ensure that secure memory is mapped and that the data will not overflow the allocated space. */
	if ((phdl->sec_mem) && (dst_off + size < phdl->sec_mem_size)) {
		(void)memcpy(phdl->sec_mem + dst_off, src, size);
	}

	return size;
}

/* Copy data to the shared buffer. Return the copied length. */
uint32_t she_platform_copy_from_shared_buf(struct she_platform_hdl *phdl, uint32_t src_off, void *dst, uint32_t size)
{
	uint32_t l = 0;

	/* Ensure that secure memory is mapped and that we won't read out of the allocated space. */
	if ((phdl->sec_mem) && (src_off + size < phdl->sec_mem_size)) {
		(void)memcpy(dst, phdl->sec_mem + src_off, size);
	}

	return size;
}

/* Returns the offset of the allocated section in secure memory. */
uint32_t she_platform_shared_buf_offset(struct she_platform_hdl *phdl)
{
	return phdl->shared_buf_off;
}

/* Start a new thread. Return 0 in case of success or an non-null code in case of error. */
int32_t she_platform_create_thread(void * (*func)(void *), void * arg)
{
	pthread_t tid;
	return pthread_create(&tid, NULL, func, arg);
}


/* Write data in a file located in NVM. Return the size of the written data. */
#define SECO_NVM_DEFAULT_STORAGE_FILE "/etc/seco_nvm"
uint32_t she_platform_storage_write(struct she_platform_hdl *phdl, uint32_t offset, uint32_t size)
{
	int32_t fd = -1;
	uint32_t l = 0;
	uint32_t crc;

	do {
		/* Open or create the file with access reserved to the current user. */
		fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			break;
		}

		/* Write the length of the data as header in the file. */
		l = write(fd, &size, sizeof(uint32_t));
		if (l != sizeof(uint32_t)) {
			break;
		}

		/* compute CRC of the data to be stored and write it as header in the file. */
		crc = crc32(0, phdl->sec_mem + offset, size);
		l = write(fd, &crc, sizeof(uint32_t));
		if (l != sizeof(uint32_t)) {
			break;
		}

		/* Write the data. */
		l = write(fd, phdl->sec_mem + offset, size);
	} while (0);

	if (fd >= 0) {
		(void)close(fd);
	}

	return l;
}


uint32_t she_platform_storage_read(struct she_platform_hdl *phdl, uint32_t offset, uint32_t max_size)
{
	int32_t fd = -1;
	uint32_t l = 0;
	uint32_t crc, crc_ref;
	uint32_t size;

	do {
		/* Open the file as read only. */
		fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_RDONLY);
		if (fd < 0) {
			break;
		}

		/* Read the size of the data contained in the file. */
		l = read(fd, &size, sizeof(uint32_t));
		if (l != sizeof(uint32_t)) {
			break;
		}

		/* If out put buffer is too small don read anything. */
		if (max_size < size) {
			break;
		}

		/* Read the CRC in the file to check that data were not corrupted.*/
		l = read(fd, &crc_ref, sizeof(uint32_t));
		if (l != sizeof(uint32_t)) {
			break;
		}

		/* Read the data. */
		l = read(fd, phdl->sec_mem + offset, size);

		/* Compute the CRC of the data and check against the one from the file. */
		crc = crc32(0, phdl->sec_mem + offset, size);
		if (crc != crc_ref) {
			(void)memset(phdl->sec_mem + offset, 0, size);
			l = 0;
		}
	} while (0);

	if (fd >= 0) {
		(void)close(fd);
	}

	return l;
}