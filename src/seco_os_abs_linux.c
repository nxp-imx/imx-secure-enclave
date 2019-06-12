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
#include <unistd.h>
#include <zlib.h>
#include "she_api.h"
#include "seco_os_abs.h"
#include "seco_mu_ioctl.h"

#define SECO_MU_SHE_PATH "/dev/seco_mu_0"
#define SECO_MU_SHE_NVM_PATH "/dev/seco_mu_1"
/* For now use same MU for SHE or HSM - both not supported simulteaneously */
#define SECO_MU_HSM_PATH "/dev/seco_mu_0"
#define SECO_MU_HSM_NVM_PATH "/dev/seco_mu_1"

#define SECO_NVM_SHE_STORAGE_FILE "/etc/seco_she_nvm"
#define SECO_NVM_HSM_STORAGE_FILE "/etc/seco_hsm_nvm"

#define SHE_STORAGE_DEFAULT_DID             0x0u
#define SHE_STORAGE_DEFAULT_TZ              0x0u
#define SHE_STORAGE_DEFAULT_MU              0x1u
#define SHE_STORAGE_DEFAULT_INTERRUPT_IDX   0x0u
#define SHE_STORAGE_DEFAULT_PRIORITY        0x0u
#define SHE_STORAGE_DEFAULT_OPERATING_MODE  0x0u


struct seco_os_abs_hdl {
    int32_t fd;
    uint32_t type;
};


/* Open a SHE session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct seco_os_abs_hdl *seco_os_abs_open_mu_channel(uint32_t type, struct seco_mu_params *mu_params)
{
    char *device_path;
    struct seco_os_abs_hdl *phdl = malloc(sizeof(struct seco_os_abs_hdl));

    switch (type) {
    case MU_CHANNEL_SHE:
        device_path = SECO_MU_SHE_PATH;
        break;
    case MU_CHANNEL_SHE_NVM:
        device_path = SECO_MU_SHE_NVM_PATH;
        break;
    case MU_CHANNEL_HSM:
        device_path = SECO_MU_HSM_PATH;
        break;
    case MU_CHANNEL_HSM_NVM:
        device_path = SECO_MU_HSM_NVM_PATH;
        break;
    default:
        device_path = NULL;
        break;
    }

    if ((phdl != NULL) && (device_path != NULL) && (mu_params != NULL)) {
        phdl->fd = open(device_path, O_RDWR);
        /* If open failed return NULL handle. */
        if (phdl->fd < 0) {
            free(phdl);
            phdl = NULL;
        } else {
            phdl->type = type;
            mu_params->mu_id = SHE_STORAGE_DEFAULT_MU;
            mu_params->interrupt_idx = SHE_STORAGE_DEFAULT_INTERRUPT_IDX;
            mu_params->tz = SHE_STORAGE_DEFAULT_TZ;
            mu_params->did = SHE_STORAGE_DEFAULT_DID;
            mu_params->priority = SHE_STORAGE_DEFAULT_PRIORITY;
            mu_params->operating_mode = SHE_STORAGE_DEFAULT_OPERATING_MODE;

            if ((device_path == SECO_MU_SHE_NVM_PATH)
                || (device_path == SECO_MU_HSM_NVM_PATH)) {
                /* for NVM: configure the device to accept incoming commands. */
                if (ioctl(phdl->fd, SECO_MU_IOCTL_ENABLE_CMD_RCV)) {
                    free(phdl);
                    phdl = NULL;
                }
            }
        }
    }
    return phdl;
}


/* Close a previously opened session (SHE or storage). */
void seco_os_abs_close_session(struct seco_os_abs_hdl *phdl)
{
    /* Close the device. */
    (void)close(phdl->fd);

    free(phdl);
}

/* Send a message to Seco on the MU. Return the size of the data written. */
int32_t seco_os_abs_send_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    return (int32_t)write(phdl->fd, message, size);
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
int32_t seco_os_abs_read_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    return (int32_t)read(phdl->fd, message, size);
};

/* Map the shared buffer allocated by Seco. */
int32_t seco_os_abs_configure_shared_buf(struct seco_os_abs_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
    int32_t error;
    struct seco_mu_ioctl_shared_mem_cfg cfg;

    cfg.base_offset = shared_buf_off;
    cfg.size = size;
    error = ioctl(phdl->fd, SECO_MU_IOCTL_SHARED_BUF_CFG, &cfg);

    return error;
}


uint64_t seco_os_abs_data_buf(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
{
    struct seco_mu_ioctl_setup_iobuf io;
    int32_t err;

    io.user_buf = src;
    io.length = size;
    io.flags = flags;

    err = ioctl(phdl->fd, SECO_MU_IOCTL_SETUP_IOBUF, &io);

    if (err != 0) {
        io.seco_addr = 0;
    }

    return io.seco_addr;
}

uint32_t seco_os_abs_crc(uint8_t *data, uint32_t size)
{
    return ((uint32_t)crc32(0xFFFFFFFF, data, size) ^ 0xFFFFFFFF);
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t seco_os_abs_storage_write(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_SHE_NVM:
        path = SECO_NVM_SHE_STORAGE_FILE;
        break;
    case MU_CHANNEL_HSM_NVM:
        path = SECO_NVM_HSM_STORAGE_FILE;
        break;
    default:
        path = NULL;
        break;
    }

    if (path != NULL) {
        /* Open or create the file with access reserved to the current user. */
        fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
        if (fd >= 0) {
            /* Write the data. */
            l = (int32_t)write(fd, src, size);

            (void)close(fd);
        }
    }

    return l;
}

int32_t seco_os_abs_storage_read(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_SHE_NVM:
        path = SECO_NVM_SHE_STORAGE_FILE;
        break;
    case MU_CHANNEL_HSM_NVM:
        path = SECO_NVM_HSM_STORAGE_FILE;
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

void seco_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len)
{
    (void)memset(dst, (int32_t)val, len);
}

void seco_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
    (void)memcpy(dst, src, len);
}

uint8_t *seco_os_abs_malloc(uint32_t size)
{
    return (uint8_t *)malloc(size);
}

void seco_os_abs_free(void *ptr)
{
    free(ptr);
}

