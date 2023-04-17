// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
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


#define SHE_DEFAULT_DID             0x0u
#define SHE_DEFAULT_TZ              0x0u
#define SHE_DEFAULT_MU              0x1u
#define SHE_DEFAULT_INTERRUPT_IDX   0x0u

/*
 * MU1: SHE user + SHE storage
 * MU2: HSM user + HSM storage
 * MU3: unused
 */

static char SECO_MU_SHE_PATH[] = "/dev/seco_mu1_ch0";
static char SECO_MU_SHE_NVM_PATH[] = "/dev/seco_mu1_ch1";
static char SECO_MU_HSM_PATH_PRIMARY[] = "/dev/seco_mu2_ch0";
static char SECO_MU_HSM_NVM_PATH[] = "/dev/seco_mu2_ch1";
static char SECO_MU_HSM_PATH_SECONDARY[] = "/dev/seco_mu2_ch2";

/*
 * V2X MUs
 */
static char V2X_MU_SV0_PATH[] = "/dev/seco_mu4_ch0";
static char V2X_MU_SV1_PATH[] = "/dev/seco_mu5_ch0";
static char V2X_MU_SHE_PATH[] = "/dev/seco_mu6_ch0";
static char V2X_MU_SG0_PATH[] = "/dev/seco_mu7_ch0";
static char V2X_MU_SG1_PATH[] = "/dev/seco_mu8_ch0";
static char V2X_MU_SHE_NVM_PATH[] = "/dev/seco_mu6_ch1";
static char V2X_MU_SG1_NVM_PATH[] = "/dev/seco_mu8_ch1";

/* Open a SHE session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct plat_os_abs_hdl *plat_os_abs_open_mu_channel(uint32_t type, struct plat_mu_params *mu_params)
{
    char *device_path;
    struct plat_os_abs_hdl *phdl = malloc(sizeof(struct plat_os_abs_hdl));
    struct seco_mu_ioctl_get_mu_info info_ioctl;
    int32_t error;
    uint8_t is_nvm = 0u;

    switch (type) {
    case MU_CHANNEL_PLAT_SHE:
        device_path = SECO_MU_SHE_PATH;
        break;
    case MU_CHANNEL_PLAT_SHE_NVM:
        device_path = SECO_MU_SHE_NVM_PATH;
        is_nvm = 1u;
        break;
    case MU_CHANNEL_PLAT_HSM:
        device_path = SECO_MU_HSM_PATH_PRIMARY;
        break;
    case MU_CHANNEL_PLAT_HSM_2ND:
        device_path = SECO_MU_HSM_PATH_SECONDARY;
        break;
    case MU_CHANNEL_PLAT_HSM_NVM:
        device_path = SECO_MU_HSM_NVM_PATH;
        is_nvm = 1u;
        break;
    case MU_CHANNEL_V2X_SV0:
        device_path = V2X_MU_SV0_PATH;
        break;
    case MU_CHANNEL_V2X_SV1:
        device_path = V2X_MU_SV1_PATH;
        break;
    case MU_CHANNEL_V2X_SHE:
        device_path = V2X_MU_SHE_PATH;
        break;
    case MU_CHANNEL_V2X_SG0:
        device_path = V2X_MU_SG0_PATH;
        break;
    case MU_CHANNEL_V2X_SG1:
        device_path = V2X_MU_SG1_PATH;
        break;
    case MU_CHANNEL_V2X_SHE_NVM:
        device_path = V2X_MU_SHE_NVM_PATH;
        is_nvm = 1u;
        break;
    case MU_CHANNEL_V2X_HSM_NVM:
        device_path = V2X_MU_SG1_NVM_PATH;
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
                device_path = SECO_MU_HSM_PATH_SECONDARY;
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

            error = ioctl(phdl->fd, SECO_MU_IOCTL_GET_MU_INFO, &info_ioctl);
            if (error == 0) {
                mu_params->mu_id = info_ioctl.seco_mu_idx;
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
                if (ioctl(phdl->fd, SECO_MU_IOCTL_ENABLE_CMD_RCV)) {
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
    uint32_t ret;
    struct stat buf;

    /* Just check if one of the MU driver is present. */
    if (stat(V2X_MU_SV0_PATH, &buf) == 0) {
        ret = 1U;
    } else {
        ret = 0U;
    }

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
    struct seco_mu_ioctl_shared_mem_cfg cfg;

    cfg.base_offset = shared_buf_off;
    cfg.size = size;
    error = ioctl(phdl->fd, SECO_MU_IOCTL_SHARED_BUF_CFG, &cfg);

    return error;
}


uint64_t plat_os_abs_data_buf(struct plat_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags)
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

void plat_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len)
{
    (void)memset(dst, (int32_t)val, len);
}

void plat_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
	if (len == NO_LENGTH)
		len = strlen(src);

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
    struct seco_mu_ioctl_signed_message msg;
    int32_t err = 0;

    msg.message = signed_message;
    msg.msg_size = msg_len;
    err = ioctl(phdl->fd, SECO_MU_IOCTL_SIGNED_MESSAGE, &msg);

    if (err == 0) {
        err = (int32_t)msg.error_code;
    }

    return err;
}
