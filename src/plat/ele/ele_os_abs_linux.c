/*
 * Copyright 2021-2022 NXP
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
#include "plat_os_abs.h"
#include "ele_mu_ioctl.h"


#define SHE_DEFAULT_DID             0x7u
#define SHE_DEFAULT_TZ              0x0u
#define SHE_DEFAULT_MU              0x2u
#define SHE_DEFAULT_INTERRUPT_IDX   0x0u

/*
 * MU1: SHE user + SHE storage
 * MU2: HSM user + HSM storage
 * MU3: unused
 */

static char ELE_MU_HSM_PATH_PRIMARY[] = "/dev/ele_mu2_ch0";
static char ELE_MU_HSM_NVM_PATH[] = "/dev/ele_mu2_ch1";
static char ELE_MU_HSM_PATH_SECONDARY[] = "/dev/ele_mu2_ch2";

static char ELE_NVM_HSM_STORAGE_FILE[] = "/etc/ele_hsm/ele_nvm_master";
static char ELE_NVM_HSM_STORAGE_CHUNK_PATH[] = "/etc/ele_hsm/";

/* Open a session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct plat_os_abs_hdl *plat_os_abs_open_mu_channel(uint32_t type, struct plat_mu_params *mu_params)
{
    char *device_path;
    struct plat_os_abs_hdl *phdl = malloc(sizeof(struct plat_os_abs_hdl));
    struct ele_mu_ioctl_get_mu_info info_ioctl;
    int32_t error;
    uint8_t is_nvm = 0u;

    switch (type) {
    case MU_CHANNEL_PLAT_HSM:
        device_path = ELE_MU_HSM_PATH_PRIMARY;
        break;
    case MU_CHANNEL_PLAT_HSM_2ND:
        device_path = ELE_MU_HSM_PATH_SECONDARY;
        break;
    case MU_CHANNEL_PLAT_HSM_NVM:
        device_path = ELE_MU_HSM_NVM_PATH;
        is_nvm = 1u;
        break;
    default:
        device_path = NULL;
        break;
    }

    if ((phdl != NULL) && (device_path != NULL) && (mu_params != NULL)) {
        phdl->fd = open(device_path, O_RDWR);
        /* If open failed return NULL handle. */
        if (phdl->fd < 0) {
            if (type == MU_CHANNEL_PLAT_HSM) {
                device_path = ELE_MU_HSM_PATH_SECONDARY;
                phdl->fd = open(device_path, O_RDWR);
                if (phdl->fd < 0) {
                    free(phdl);
                    phdl = NULL;
                }
            } else {
                free(phdl);
                phdl = NULL;
            }
        }

        if (phdl != NULL) {
            phdl->type = type;

            error = ioctl(phdl->fd, ELE_MU_IOCTL_GET_MU_INFO, &info_ioctl);
            if (error == 0) {
                mu_params->mu_id = info_ioctl.ele_mu_id;
                mu_params->interrupt_idx = info_ioctl.interrupt_idx;
                mu_params->tz = info_ioctl.tz;
                mu_params->did = info_ioctl.did;
            } else {
                mu_params->mu_id = SHE_DEFAULT_MU;
                mu_params->interrupt_idx = SHE_DEFAULT_INTERRUPT_IDX;
                mu_params->tz = SHE_DEFAULT_TZ;
                mu_params->did = SHE_DEFAULT_DID;
            }

            if (is_nvm != 0u) {
                /* for NVM: configure the device to accept incoming commands. */
                if (ioctl(phdl->fd, ELE_MU_IOCTL_ENABLE_CMD_RCV)) {
                    free(phdl);
                    phdl = NULL;
                }
            }
        }
    }
    return phdl;
}

/* Check if the V2X accelerator is present on this HW. */
uint32_t plat_os_abs_has_v2x_hw(void)
{
    uint32_t ret = 0U;

    return ret;
}


/* Close a previously opened session (SHE or storage). */
void plat_os_abs_close_session(struct plat_os_abs_hdl *phdl)
{
    /* Close the device. */
    (void)close(phdl->fd);

    free(phdl);
}

/* Send a message to Seco on the MU. Return the size of the data written. */
int32_t plat_os_abs_send_mu_message(struct plat_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    return (int32_t)write(phdl->fd, message, size);
}

/* Read a message from Seco on the MU. Return the size of the data that were read. */
int32_t plat_os_abs_read_mu_message(struct plat_os_abs_hdl *phdl, uint32_t *message, uint32_t size)
{
    return (int32_t)read(phdl->fd, message, size);
};

/* Map the shared buffer allocated by Seco. */
int32_t plat_os_abs_configure_shared_buf(struct plat_os_abs_hdl *phdl, uint32_t shared_buf_off, uint32_t size)
{
    int32_t error;
    struct ele_mu_ioctl_shared_mem_cfg cfg;

    cfg.base_offset = shared_buf_off;
    cfg.size = size;
    error = ioctl(phdl->fd, ELE_MU_IOCTL_SHARED_BUF_CFG, &cfg);

    return error;
}


uint64_t plat_os_abs_data_buf(struct plat_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
{
    struct ele_mu_ioctl_setup_iobuf io;
    int32_t err;

    io.user_buf = src;
    io.length = size;
    io.flags = flags;

    err = ioctl(phdl->fd, ELE_MU_IOCTL_SETUP_IOBUF, &io);

    if (err != 0) {
        io.ele_addr = 0;
    }

    return io.ele_addr;
}

uint32_t plat_os_abs_crc(uint8_t *data, uint32_t size)
{
    return ((uint32_t)crc32(0xFFFFFFFFu, data, size) ^ 0xFFFFFFFFu);
}

/* Write data in a file located in NVM. Return the size of the written data. */
int32_t plat_os_abs_storage_write(struct plat_os_abs_hdl *phdl, uint8_t *src, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_PLAT_HSM_NVM:
        path = ELE_NVM_HSM_STORAGE_FILE;
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

int32_t plat_os_abs_storage_read(struct plat_os_abs_hdl *phdl, uint8_t *dst, uint32_t size)
{
    int32_t fd = -1;
    int32_t l = 0;
    char *path;

    switch(phdl->type) {
    case MU_CHANNEL_PLAT_HSM_NVM:
        path = ELE_NVM_HSM_STORAGE_FILE;
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
int32_t plat_os_abs_storage_write_chunk(struct plat_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint64_t blob_id)
{
    int32_t fd = -1;
    int32_t l = 0;
    int n = -1;
    char *path = NULL;

    if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
        path = malloc(sizeof(ELE_NVM_HSM_STORAGE_CHUNK_PATH)+16u);

        if (path != NULL) {
            (void)mkdir(ELE_NVM_HSM_STORAGE_CHUNK_PATH, S_IRUSR|S_IWUSR);
            n = snprintf(path, sizeof(ELE_NVM_HSM_STORAGE_CHUNK_PATH)+16u,
                            "%s%016lx", ELE_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
        }
    } else {
        path = NULL;
    }

    if (n > 0) {
        /* Open or create the file with access reserved to the current user. */
        fd = open(path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
        if (fd >= 0) {
            /* Write the data. */
            l = (int32_t)write(fd, src, size);

            (void)close(fd);
        }
    }

    free(path);
    return l;
}

int32_t plat_os_abs_storage_read_chunk(struct plat_os_abs_hdl *phdl, uint8_t *dst, uint32_t size, uint64_t blob_id)
{
    int32_t fd = -1;
    int32_t l = 0;
    int n = -1;
    char *path;

    if (phdl->type == MU_CHANNEL_PLAT_HSM_NVM) {
        path = malloc(sizeof(ELE_NVM_HSM_STORAGE_CHUNK_PATH)+16u);

        if (path != NULL) {
            (void)mkdir(ELE_NVM_HSM_STORAGE_CHUNK_PATH, S_IRUSR|S_IWUSR);
            n = snprintf(path, sizeof(ELE_NVM_HSM_STORAGE_CHUNK_PATH)+16u,
                            "%s%016lx", ELE_NVM_HSM_STORAGE_CHUNK_PATH, blob_id);
        }
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
    free(path);
    return l;
}

void plat_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len)
{
    (void)memset(dst, (int32_t)val, len);
}

void plat_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
    (void)memcpy(dst, src, len);
}

uint8_t *plat_os_abs_malloc(uint32_t size)
{
    return (uint8_t *)malloc(size);
}

void plat_os_abs_free(void *ptr)
{
    free(ptr);
}

void plat_os_abs_start_system_rng(struct plat_os_abs_hdl *phdl)
{
    /*
     * Nothing to do on Linux. The SCU RPC is automatically called at boot time.
     * No need to call it again from here.
     */
}

int32_t plat_os_abs_send_signed_message(struct plat_os_abs_hdl *phdl, uint8_t *signed_message, uint32_t msg_len)
{
    /* Send the message to the kernel that will forward to SCU.*/
    struct ele_mu_ioctl_signed_message msg;
    int32_t err = 0;

    msg.message = signed_message;
    msg.msg_size = msg_len;
    err = ioctl(phdl->fd, ELE_MU_IOCTL_SIGNED_MESSAGE, &msg);

    if (err == 0) {
        err = (int32_t)msg.error_code;
    }

    return err;
}
