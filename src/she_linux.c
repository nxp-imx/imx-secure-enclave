
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

struct she_linux_hdl{
	int fd;
	void *sec_mem;
	int sec_mem_size;
	int shared_buf_off;
};

she_hdl *she_platform_open_session(she_session_type type) {
	struct she_linux_hdl *lhdl = malloc(sizeof(struct she_linux_hdl));

	if (lhdl) {
		switch (type) {
			case SHE_NVM:
				lhdl->fd = open(SECO_NVM_PATH, O_RDWR);
				break;
			case SHE_USER:
			default:
				lhdl->fd = open(SECO_MU_PATH, O_RDWR);
				break;
		}
		//TODO: handle fopen error
		lhdl->sec_mem = NULL;
	}
	return (she_hdl *)lhdl;
};

void she_platform_close_session(she_hdl *hdl) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	if (lhdl->sec_mem)
		munmap(lhdl->sec_mem, lhdl->sec_mem_size);
	close(lhdl->fd);
	free(hdl);
}

int she_platform_send_mu_message(she_hdl *hdl, char *message, int size) {
	return write(((struct she_linux_hdl *)hdl)->fd, message, size);
}

int she_platform_read_mu_message(she_hdl *hdl, char *message, int size) {
	return read(((struct she_linux_hdl *)hdl)->fd, message, size);
};

void she_platform_configure_shared_buf(she_hdl *hdl, int shared_buf_off, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	lhdl->shared_buf_off = shared_buf_off;
	lhdl->sec_mem = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, lhdl->fd, shared_buf_off);
	lhdl->sec_mem_size = size;
}

int she_platform_copy_to_shared_buf(she_hdl *hdl, int dst_off, void *src, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	if (!lhdl->sec_mem)
		return 0;
	/* TODO: check on the size vs. lenght of the allocated sec_mem buffer. */
	memcpy(lhdl->sec_mem + dst_off, src, size);

	return size;
}

int she_platform_copy_from_shared_buf(she_hdl *hdl, int src_off, void *dst, int size) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;

	if (!lhdl->sec_mem)
		return 0;
	memcpy(dst, lhdl->sec_mem + src_off, size);

	return size;
}

int she_platform_shared_buf_offset(she_hdl *hdl) {
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	return lhdl->shared_buf_off;
}


void she_platform_create_thread(void * (*func)(void *), void * arg) {
	pthread_t tid;
	pthread_create(&tid, NULL, func, arg);
}


#define SECO_NVM_DEFAULT_STORAGE_FILE "/etc/seco_nvm"
/* return size of data writen to nvm  */
uint32_t seco_storage_write(she_hdl *hdl, uint32_t offset, uint32_t size)
{
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	int fd;
	int l;
	uint32_t crc;

	fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return 0;

	l = write(fd, &size, sizeof(uint32_t));
	if (l != sizeof(uint32_t)) {
		close(fd);
		return 0;
	}

	/* compute CRC of the data to be stored and write it as header in the file. */
	crc = crc32(0, lhdl->sec_mem + offset, size);
	l = write(fd, &crc, sizeof(uint32_t));
	if (l != sizeof(uint32_t)) {
		close(fd);
		return 0;
	}

	l = write(fd, lhdl->sec_mem + offset, size);

	close(fd);

	return l;
}


uint32_t seco_storage_read(she_hdl *hdl, uint32_t offset, uint32_t max_size)
{
	struct she_linux_hdl *lhdl = (struct she_linux_hdl *)hdl;
	int fd;
	int l;
	uint32_t crc, crc_ref;
	uint32_t size;

	fd = open(SECO_NVM_DEFAULT_STORAGE_FILE, O_CREAT|O_RDONLY, S_IRUSR|S_IWUSR);
	if (fd < 0)
		return 0;


	l = read(fd, &size, sizeof(uint32_t));
	if (l != sizeof(uint32_t)) {
		close(fd);
		return 0;
	}

	if (max_size < size) {
		printf("not enough space in out buffer don't read anything.\n");
		return 0;
	}

	l = read(fd, &crc_ref, sizeof(uint32_t));
	if (l != sizeof(uint32_t)) {
		close(fd);
		return 0;
	}

	l = read(fd, lhdl->sec_mem + offset, size);

	/* check CRC */
	crc = crc32(0, lhdl->sec_mem + offset, size);
	if (crc != crc_ref) {
		memset(lhdl->sec_mem + offset, 0, size);
		l = 0;
	}

	close(fd);

	return l;
}