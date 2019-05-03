
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
#include "seco_ioctl.h"


#define SECO_MU_PATH "/dev/seco_she"


struct she_hdl_s {
    int32_t fd;
};

uint32_t she_storage_create(uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates_number, uint8_t *signed_message, uint32_t msg_len)
{
    struct seco_ioctl_she_storage_create ioctl_msg;
    int32_t fd;
    uint32_t ret = SHE_STORAGE_CREATE_FAIL;

    do {
        fd = open(SECO_MU_PATH, O_RDWR);
        if (fd < 0) {
            break;
        }
        ioctl_msg.key_storage_identifier = key_storage_identifier;
        ioctl_msg.password = password;
        ioctl_msg.max_updates_number = max_updates_number;
        ioctl_msg.signed_message = signed_message;
        ioctl_msg.msg_len = msg_len;

        ioctl(fd, SECO_MU_IOCTL_SHE_STORAGE_CREATE, &ioctl_msg);

        ret = ioctl_msg.error_code;

        close(fd);
    } while(0);

    return ret;
}

/* Open a SHE user session and return a pointer to the session handle. */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t password, void (*async_cb)(void *priv, she_err_t err), void *priv)
{
    struct she_hdl_s *hdl = NULL;
    struct seco_ioctl_she_open_session ioctl_msg;

    do {
        if ((async_cb != NULL) || (priv != NULL)) {
            /* Not supported yet */
            break;
        }

        /* allocate the handle (free when closing the session). */
        hdl = malloc(sizeof(struct she_hdl_s));
        if (hdl == NULL) {
            break;
        }

        hdl->fd = open(SECO_MU_PATH, O_RDWR);
        if (hdl->fd < 0) {
            free(hdl);
            hdl = NULL;
            break;
        }

        ioctl_msg.key_storage_identifier = key_storage_identifier;
        ioctl_msg.password = password;

        ioctl(hdl->fd, SECO_MU_IOCTL_SHE_OPEN_SESSION, &ioctl_msg);

        if (ioctl_msg.error_code != 0) {
            close(hdl->fd);
            free(hdl);
            hdl = NULL;
        }
    } while(0);
    return hdl;
};

/* Close a previously opened SHE session. */
void she_close_session(struct she_hdl_s *hdl) {
    if (hdl) {
        ioctl(hdl->fd, SECO_MU_IOCTL_SHE_CLOSE_SESSION, NULL);
        close(hdl->fd);
        free(hdl);
    }
}

/* MAC generation command processing. */
she_err_t she_cmd_generate_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac)
{
    struct seco_ioctl_she_generate_mac ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.message_length = message_length;
        ioctl_msg.message = message;
        ioctl_msg.mac = mac;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_GENERATE_MAC, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

/* MAC verify command processing. */
she_err_t she_cmd_verify_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status)
{
    struct seco_ioctl_she_verify_mac ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if ((hdl != NULL) && (verification_status != NULL)) {
        *verification_status = SHE_MAC_VERIFICATION_FAILED;

        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.message_length = message_length;
        ioctl_msg.message = message;
        ioctl_msg.mac = mac;
        ioctl_msg.mac_length = mac_length;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_VERIFY_MAC, &ioctl_msg) < 0) {
            *verification_status = ioctl_msg.verification_status;
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
};

/* CBC encrypt command. */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext)
{
    struct seco_ioctl_she_enc_cbc ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.data_length = data_length;
        ioctl_msg.iv = iv;
        ioctl_msg.plaintext = plaintext;
        ioctl_msg.ciphertext = ciphertext;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_ENC_CBC, &ioctl_msg) < 0){
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
};

/* CBC decrypt command. */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext)
{
    struct seco_ioctl_she_dec_cbc ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.data_length = data_length;
        ioctl_msg.iv = iv;
        ioctl_msg.ciphertext = ciphertext;
        ioctl_msg.plaintext = plaintext;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_DEC_CBC, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

/* ECB encrypt command. */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext)
{
    struct seco_ioctl_she_enc_ecb ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.plaintext = plaintext;
        ioctl_msg.ciphertext = ciphertext;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_ENC_ECB, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

/* ECB decrypt command. */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext)
{
    struct seco_ioctl_she_dec_ecb ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key_ext = key_ext;
        ioctl_msg.key_id = key_id;
        ioctl_msg.ciphertext = ciphertext;
        ioctl_msg.plaintext = plaintext;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_DEC_ECB, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

/* Load key command processing. */
she_err_t she_cmd_load_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
    struct seco_ioctl_she_load_key ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.m1 = m1;
        ioctl_msg.m2 = m2;
        ioctl_msg.m3 = m3;
        ioctl_msg.m4 = m4;
        ioctl_msg.m5 = m5;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_LOAD_KEY, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

she_err_t she_cmd_load_plain_key(struct she_hdl_s *hdl, uint8_t *key)
{
    struct seco_ioctl_she_load_plain_key ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.key = key;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_LOAD_PLAIN_KEY, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_export_ram_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5)
{
    struct seco_ioctl_she_export_ram_key ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.m1 = m1;
        ioctl_msg.m2 = m2;
        ioctl_msg.m3 = m3;
        ioctl_msg.m4 = m4;
        ioctl_msg.m5 = m5;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_EXPORT_RAM_KEY, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}

she_err_t she_cmd_init_rng(struct she_hdl_s *hdl)
{
    struct seco_ioctl_she_init_rng ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_INIT_RNG, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_extend_seed(struct she_hdl_s *hdl, uint8_t *entropy)
{
    struct seco_ioctl_she_extend_seed ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.entropy = entropy;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_EXTEND_SEED, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_rnd(struct she_hdl_s *hdl, uint8_t *rnd)
{
    struct seco_ioctl_she_generate_rnd ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        ioctl_msg.rnd = rnd;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_GENERATE_RND, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_get_status(struct she_hdl_s *hdl, uint8_t *sreg)
{
    struct seco_ioctl_she_get_status ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if ((hdl != NULL) && (sreg != NULL)) {
        *sreg = 0;
        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_GET_STATUS, &ioctl_msg) < 0) {
            *sreg = ioctl_msg.sreg;
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_get_id(struct she_hdl_s *hdl, uint8_t *challenge, uint8_t *id, uint8_t *sreg, uint8_t *mac)
{
    struct seco_ioctl_she_get_id ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if ((hdl != NULL) && (sreg != NULL)) {
        ioctl_msg.challenge = challenge;
        ioctl_msg.id = id;
        ioctl_msg.mac = mac;

        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_GET_ID, &ioctl_msg) < 0) {
            *sreg = ioctl_msg.sreg;
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}


she_err_t she_cmd_cancel(struct she_hdl_s *hdl)
{
    struct seco_ioctl_she_cancel ioctl_msg;
    she_err_t ret = ERC_GENERAL_ERROR;

    if (hdl != NULL) {
        if (ioctl(hdl->fd, SECO_MU_IOCTL_SHE_CANCEL, &ioctl_msg) < 0) {
            ret = (she_err_t)ioctl_msg.err;
        }
    }

    return ret;
}
