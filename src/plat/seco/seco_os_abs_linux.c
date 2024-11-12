// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2024 NXP
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
#include "plat_utils.h"
#include "seco_mu_ioctl.h"
#include "internal/hsm_session.h"

/*
 * MU1: SHE user + SHE storage
 * MU2: HSM user + HSM storage
 * MU3: unused
 */

char SECO_MU_SHE_PATH[] = "/dev/she1_ch0";
// This device is for SHE channel on SE, best effort high priority.
char SECO_MU_SHE_NVM_PATH[] = "/dev/she1_ch1";
// This device is for SHE NVM channel on SE.
char SECO_MU_HSM_PATH_PRIMARY[] = "/dev/hsm1_ch0";
// This device is for HSM1 channel 0 on SE, best effort high priority.
char SECO_MU_HSM_NVM_PATH[] = "/dev/hsm1_ch1";
// This device is for HSM NVM channel on SE.
char SECO_MU_HSM_PATH_SECONDARY[] = "/dev/hsm1_ch2";
// This device is for HSM1 channel 2 on SE, best effort high priority.

/*
 * V2X MUs
 */
char V2X_MU_SV0_PATH[] = "/dev/v2x_sv0_ch0";
// This device is for SV0 channel on V2X, low latency high priority.
char V2X_MU_SV1_PATH[] = "/dev/v2x_sv1_ch0";
// This device is for SV1 channel on V2X, low latency low priority.
char V2X_MU_SHE_PATH[] = "/dev/v2x_she_ch0";
// This device is for SHE channel on V2X, low latency  high priority.
char V2X_MU_SG0_PATH[] = "/dev/v2x_sg0_ch0";
// This device is for SG0 channel on V2X, low latency high priority.
char V2X_MU_SG1_PATH[] = "/dev/v2x_sg1_ch0";
// This device is for SG1 channel on V2X, low latency low priority.
char V2X_SHE_DBG_MU_NVM_PATH[] = "/dev/v2x_dbg_ch0";
// This device is for SHE NVM channel on DEBUG MU.
char V2X_MU_SHE_NVM_PATH[] = "/dev/v2x_she_ch1";
// This device is for SHE NVM channel on V2X.
char V2X_MU_SG1_NVM_PATH[] = "/dev/v2x_sg1_ch1";
// This device is for V2X NVM channel on V2X.

/* Open a SHE session and returns a pointer to the handle or NULL in case of error.
 * Here it consists in opening the decicated seco MU device file.
 */
struct plat_os_abs_hdl *plat_os_abs_open_mu_channel(uint32_t type, struct plat_mu_params *mu_params)
{
    char *device_path;
	struct plat_os_abs_hdl *phdl = (struct plat_os_abs_hdl *)
				       plat_os_abs_malloc(sizeof(struct plat_os_abs_hdl));
    struct seco_mu_ioctl_get_mu_info info_ioctl;
    int32_t error;
    uint8_t is_nvm = 0u;

	switch (type) {
	case SHE1:
		device_path = SECO_MU_SHE_PATH;
		break;
	case SHE_NVM:
		device_path = SECO_MU_SHE_NVM_PATH;
		is_nvm = 1u;
		break;
	case HSM1:
		device_path = SECO_MU_HSM_PATH_PRIMARY;
		break;
	case HSM_NVM:
		device_path = SECO_MU_HSM_NVM_PATH;
		is_nvm = 1u;
		break;
	case V2X_SV0:
		device_path = V2X_MU_SV0_PATH;
		break;
	case V2X_SV1:
		device_path = V2X_MU_SV1_PATH;
		break;
	case V2X_SHE:
		device_path = V2X_MU_SHE_PATH;
		break;
	case V2X_SG0:
		device_path = V2X_MU_SG0_PATH;
		break;
	case V2X_SG1:
		device_path = V2X_MU_SG1_PATH;
		break;
	case V2X_SHE_NVM:
		device_path = V2X_MU_SHE_NVM_PATH;
		is_nvm = 1u;
		break;
	case V2X_SHE_DEBUG_MU_NVM:
		device_path = V2X_SHE_DBG_MU_NVM_PATH;
		is_nvm = 1u;
		break;
	case V2X_HSM_NVM:
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
		if (type == HSM1) {
			device_path = SECO_MU_HSM_PATH_SECONDARY;
			phdl->fd = open(device_path, O_RDWR);
			if (phdl->fd < 0) {
				plat_os_abs_free(phdl);
				phdl = NULL;
			}
		} else {
			plat_os_abs_free(phdl);
			phdl = NULL;
		}
        }

	if (phdl) {
		phdl->type = type;

		error = ioctl(phdl->fd, SECO_MU_IOCTL_GET_MU_INFO, &info_ioctl);
		if (error == 0) {
			mu_params->mu_id = info_ioctl.seco_mu_idx;
			mu_params->interrupt_idx = info_ioctl.interrupt_idx;
			mu_params->tz = info_ioctl.tz;
			mu_params->did = info_ioctl.did;
			phdl->mu_info.cmd_tag = info_ioctl.cmd_tag;
			phdl->mu_info.rsp_tag = info_ioctl.rsp_tag;
			phdl->mu_info.success_tag = info_ioctl.success_tag;
			phdl->mu_info.base_api_ver = info_ioctl.base_api_ver;
			phdl->mu_info.fw_api_ver = info_ioctl.fw_api_ver;
		} else {
			(void)close(phdl->fd);
			plat_os_abs_free(phdl);
			phdl = NULL;
		}

		if (is_nvm && phdl) {
			/* for NVM: configure the device to accept incoming commands. */
			if (ioctl(phdl->fd, SECO_MU_IOCTL_ENABLE_CMD_RCV)) {
				/* Close the device. */
				(void)close(phdl->fd);
				plat_os_abs_free(phdl);
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

	plat_os_abs_free(phdl);
}

/*
 * Send a message to platform on the MU. Return the size of the data written.
 * In case of error, return 0 size.
 */
uint32_t plat_os_abs_send_mu_message(struct plat_os_abs_hdl *phdl,
				     uint32_t *message,
				     uint32_t size)
{
	int64_t ret;

	ret = write(phdl->fd, message, size);

	if (ret < 0) {
		ret = PLAT_WRITE_FAILURE;
		se_err("\nPLAT write error[%d]: %s\n",
		       errno,
		       strerror(errno));
	}

	return TO_UINT32_T(ret);
}

/*
 * Read a message from platform on the MU. Return the size of the data read.
 * In case of error, return 0 size.
 */
uint32_t plat_os_abs_read_mu_message(struct plat_os_abs_hdl *phdl,
				     uint32_t *message,
				     uint32_t size)
{
	int64_t ret;

	ret = read(phdl->fd, message, size);

	if (ret < 0) {
		ret = PLAT_READ_FAILURE;
		se_err("\nPLAT read error[%d]: %s\n",
		       errno,
		       strerror(errno));
	}

	return TO_UINT32_T(ret);
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

/* Map the shared buffer allocated by Seco. */
uint32_t plat_os_abs_configure_shared_buf_v2(struct plat_os_abs_hdl *phdl,
					     uint32_t shared_buf_off,
					     uint32_t size)
{
	int32_t ret;
	uint32_t error = PLAT_SUCCESS;
	struct seco_mu_ioctl_shared_mem_cfg cfg;

	cfg.base_offset = shared_buf_off;
	cfg.size = size;
	ret = ioctl(phdl->fd, SECO_MU_IOCTL_SHARED_BUF_CFG, &cfg);

	if (ret != 0)
		error = PLAT_CONF_SHARED_BUF_FAIL;

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

uint32_t plat_os_abs_data_buf_v2(struct plat_os_abs_hdl *phdl,
				 uint64_t *addr,
				 uint8_t *src,
				 uint32_t size,
				 uint32_t flags)
{
	struct seco_mu_ioctl_setup_iobuf io;
	uint32_t err = PLAT_SUCCESS;
	int32_t ret;

	if (!addr) {
		err = PLAT_DATA_BUF_SETUP_FAIL;
		return err;
	}

	io.user_buf = src;
	io.length = size;
	io.flags = flags;

	ret = ioctl(phdl->fd, SECO_MU_IOCTL_SETUP_IOBUF, &io);

	*addr = io.seco_addr;

	if (ret != 0) {
		*addr = 0;
		err = PLAT_DATA_BUF_SETUP_FAIL;
	}

	return err;
}

void plat_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len)
{
    (void)memset(dst, (int32_t)val, len);
}

void plat_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len)
{
	if (len == NO_LENGTH)
		len = TO_UINT32_T(strlen(src));

	(void)memcpy(dst, src, len);
}

uint32_t plat_os_abs_memcpy_v2(uint8_t *dst, uint8_t *src, uint32_t len)
{
	uint32_t err = PLAT_SUCCESS;
	void *ret;

	if (!dst || !src) {
		err = PLAT_MEMCPY_FAIL;
		goto out;
	}

	if (len == NO_LENGTH)
		len = TO_UINT32_T(strlen(src));

	ret = (void *)memcpy(dst, src, len);

	if (!ret)
		err = PLAT_MEMCPY_FAIL;

out:
	return err;
}

uint8_t *plat_os_abs_malloc(uint32_t size)
{
    return (uint8_t *)malloc(size);
}

uint32_t plat_os_abs_malloc_v2(uint8_t **mem_p, uint32_t size)
{
	uint32_t ret = PLAT_SUCCESS;

	if (!mem_p || !size) {
		ret = PLAT_ERR_OUT_OF_MEMORY;
		goto out;
	}

	*mem_p =  (uint8_t *)malloc(size);

	if (!(*mem_p) || errno == ENOMEM) {
		ret = PLAT_ERR_OUT_OF_MEMORY;
		se_err("\nPLAT malloc error[%d]: %s\n",
		       errno,
		       strerror(errno));
	}

out:
	return ret;
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

uint32_t plat_os_abs_send_signed_message(struct plat_os_abs_hdl *phdl,
					 uint8_t *signed_message,
					 uint32_t msg_len)
{
    /* Send the message to the kernel that will forward to SCU.*/
    struct seco_mu_ioctl_signed_message msg;
    int32_t err = 0;

    msg.message = signed_message;
    msg.msg_size = msg_len;
    err = ioctl(phdl->fd, SECO_MU_IOCTL_SIGNED_MESSAGE, &msg);

	if (err < 0) {
		err = PLAT_FAILURE;
		se_err("\nPLAT ioctl error[%d]: %s\n",
		       errno,
		       strerror(errno));
	} else if (err == 0) {
		err = msg.error_code;
	}

	return TO_UINT32_T(err);
}

uint32_t plat_os_abs_send_signed_message_v2(struct plat_os_abs_hdl *phdl,
					    uint8_t *signed_message,
					    uint32_t msg_len)
{
	/* Send the message to the kernel that will forward to SCU.*/
	struct seco_mu_ioctl_signed_message msg;
	uint32_t err = PLAT_SUCCESS;
	int32_t ret;

	if (!phdl) {
		err = PLAT_SIGNED_MESSAGE_SETUP_FAIL;
		goto out;
	}

	msg.message = signed_message;
	msg.msg_size = msg_len;

	ret = ioctl(phdl->fd, SECO_MU_IOCTL_SIGNED_MESSAGE, &msg);

	if (ret < 0) {
		err = PLAT_SIGNED_MESSAGE_SETUP_FAIL;
		se_err("\nPLAT ioctl error[%d]: %s\n",
		       errno,
		       strerror(errno));
		return err;
	} else if (ret == 0) {
		/* Fix me imx_sc_to_linux_errno() in imx-scu.c return -EIO. */
		err = msg.error_code;
		return PLAT_SUCCESS;
	}

out:
	return err;
}

uint32_t plat_os_abs_get_soc_info(struct plat_os_abs_hdl *phdl,
				  uint16_t *soc_id,
				  uint16_t *soc_rev,
				  uint8_t *board_type)
{
	struct seco_mu_ioctl_get_soc_info soc_info;
	int32_t ret = PLAT_SUCCESS;

	if (!phdl || !soc_id || !soc_rev || !board_type) {
		ret = PLAT_FAILURE;
		goto out;
	}

	ret = ioctl(phdl->fd, SECO_MU_IOCTL_GET_SOC_INFO, &soc_info);
	if (ret < 0) {
		ret = PLAT_FAILURE;
		se_err("\nPLAT ioctl error[%d]: %s\n",
		       errno,
		       strerror(errno));
	}

	*soc_id = soc_info.soc_id;
	*soc_rev = soc_info.soc_rev;
	*board_type = soc_info.board_type;
out:
	return TO_UINT32_T(ret);
}

uint32_t plat_get_perf_timer(struct plat_os_abs_hdl *phdl,
			     struct timespec *t_start,
			     struct timespec *t_end)
{
	struct seco_time_frame perf_time;
	int32_t ret = PLAT_SUCCESS;

	if (!phdl || !t_start || !t_end)
		return PLAT_FAILURE;

	ret = ioctl(phdl->fd, SECO_MU_IOCTL_GET_TIMER, &perf_time);
	if (ret < 0) {
		se_err("\nPLAT ioctl error[%d]: %s\n",
		       errno,
		       strerror(errno));
		return PLAT_FAILURE;
	}

	*t_start = perf_time.t_start;
	*t_end = perf_time.t_end;

	return TO_UINT32_T(ret);
}

uint32_t plat_os_abs_cmd_snd_rcv_rsp(struct plat_os_abs_hdl *phdl,
				     uint32_t *tx_buf, uint32_t *tx_buf_sz,
				     uint32_t *rx_buf, uint32_t *rx_buf_sz)
{
    struct seco_ioctl_cmd_snd_rcv_rsp_info cmd_snd_rcv_rsp_info;
    int32_t err;

    cmd_snd_rcv_rsp_info.tx_buf = tx_buf;
    cmd_snd_rcv_rsp_info.tx_buf_sz = *tx_buf_sz;
    cmd_snd_rcv_rsp_info.rx_buf = rx_buf;
    cmd_snd_rcv_rsp_info.rx_buf_sz = *rx_buf_sz;

    err = ioctl(phdl->fd, SECO_IOCTL_CMD_SEND_RCV_RSP, &cmd_snd_rcv_rsp_info);

    if (err < 0) {
        err = PLAT_FAILURE;
	if (cmd_snd_rcv_rsp_info.tx_buf_sz < 0)
		printf("\nPLAT send error[%d]: %s\n",
		       errno,
		       strerror(errno));

	if (cmd_snd_rcv_rsp_info.rx_buf_sz < 0)
		printf("\nPLAT read error[%d]: %s\n",
		       errno,
		       strerror(errno));
    }
    else {
        err = PLAT_SUCCESS;
        *tx_buf_sz = cmd_snd_rcv_rsp_info.tx_buf_sz;
        *rx_buf_sz = cmd_snd_rcv_rsp_info.rx_buf_sz;
    }

    return err;
}
