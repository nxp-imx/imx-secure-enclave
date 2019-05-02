
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


#define SECO_SHE_NVM_PATH "/dev/seco_she_nvm"


struct seco_nvm_hdl {
    int32_t fd;
};

/**
 * open an nvm storage session and provide existing storage data if existing.
 */
struct seco_nvm_hdl *seco_nvm_open_session(uint32_t flags, uint8_t *data, uint32_t len)
{
    struct seco_nvm_hdl *nvm_hdl = NULL;
    struct seco_ioctl_nvm_open_session ioctl_msg;

    do {
        /* allocate the handle (free when closing the session). */
        nvm_hdl = malloc(sizeof(struct seco_nvm_hdl));
        if (nvm_hdl == NULL) {
            break;
        }
        nvm_hdl->fd = open(SECO_SHE_NVM_PATH, O_RDWR);
        if (nvm_hdl->fd < 0) {
            free(nvm_hdl);
            nvm_hdl = NULL;
            break;
        }

        ioctl_msg.flags = flags;
        ioctl_msg.data = data;
        ioctl_msg.len = len;

        ioctl(nvm_hdl->fd, SECO_MU_IOCTL_NVM_OPEN_SESSION, &ioctl_msg);
    } while(0);
    return nvm_hdl;
}

void seco_nvm_close_session(struct seco_nvm_hdl *nvm_hdl)
{
    if (nvm_hdl) {
        ioctl(nvm_hdl->fd, SECO_MU_IOCTL_NVM_CLOSE_SESSION, NULL);
        close(nvm_hdl->fd);
        free(nvm_hdl);
    }
}

uint32_t seco_nvm_get_data_len(struct seco_nvm_hdl *nvm_hdl)
{
    struct seco_ioctl_nvm_get_data_len ioctl_msg;

    ioctl(nvm_hdl->fd, SECO_MU_IOCTL_NVM_GET_DATA_LEN, &ioctl_msg);

    return ioctl_msg.data_len;
}

uint32_t seco_nvm_get_data(struct seco_nvm_hdl *nvm_hdl, uint8_t *dst)
{
    struct seco_ioctl_nvm_get_data ioctl_msg;

    ioctl_msg.dst = dst;

    ioctl(nvm_hdl->fd, SECO_MU_IOCTL_NVM_GET_DATA, &ioctl_msg);

    return ioctl_msg.error;
}

/**
 * confirm to SECO if the data has been written correctly to NVM
 * error: 0 means that the write to NVM was succesful. any other value means that an error occured.
 */
uint32_t seco_nvm_write_status(struct seco_nvm_hdl *nvm_hdl, uint32_t error)
{
    struct seco_ioctl_nvm_write_status ioctl_msg;

    ioctl_msg.error = error;
    ioctl(nvm_hdl->fd, SECO_MU_IOCTL_NVM_WRITE_STATUS, &ioctl_msg);

    return ioctl_msg.error;
}


/*
 * Storage manager
 */
struct she_storage_context {
    struct seco_nvm_hdl *nvm_hdl;
    pthread_t tid;
    char *storage_path;
};

void *seco_nvm_manager_thread(void *arg)
{
    struct she_storage_context *ctx = (struct she_storage_context *)arg;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint32_t err = 1;
    int32_t fd = -1;

    do {
        data_len = seco_nvm_get_data_len(ctx->nvm_hdl);

        // TODO: check length against a max value tbd.
        data = malloc(data_len);
        if (!data) {
            break;
        }

        err = seco_nvm_get_data(ctx->nvm_hdl, data);
        if (err != 0) {
            break;
        }

        err = 1;
        fd = open(ctx->storage_path, O_CREAT|O_WRONLY|O_SYNC, S_IRUSR|S_IWUSR);
        if (fd >= 0) {
            /* Write the data. */
            if (write(fd, data, data_len) == data_len) {
                /* write successful.*/
                err = 0;
            }
            (void)close(fd);
        }

        free(data);
        data = NULL;
        data_len = 0;

        err = seco_nvm_write_status(ctx->nvm_hdl, err);
        if (err != 0) {
            break;
        }
    } while(1);
    free(data);
    return NULL;
}


#define SECO_NVM_DEFAULT_STORAGE_FILE "/etc/seco_nvm"

struct she_storage_context *she_storage_init(void)
{
    struct she_storage_context *ctx;
    uint8_t *data = NULL;
    uint32_t data_len = 0;
    uint32_t err = 1;
    int32_t fd = -1;
    struct stat sb;

    do {
        ctx = malloc(sizeof(struct she_storage_context));
        if (!ctx)
            break;
        ctx->storage_path = SECO_NVM_DEFAULT_STORAGE_FILE;
        fd = open(ctx->storage_path, O_RDONLY);
        if (fd >= 0) {
            if (fstat(fd, &sb) == 0) {
                data_len = sb.st_size;
            }
            if (data_len != 0) {
                data = malloc(data_len);
                if (data) {
                    if (read(fd, data, data_len) != data_len) {
                        /* File existing - but cannot be read.*/
                        free(data);
                        data = NULL;
                        data_len = 0;
                    }
                }
            }
            close(fd);
        }
        ctx->nvm_hdl = seco_nvm_open_session(1 /*SHE*/, data, data_len);
        free(data);
        if (!ctx->nvm_hdl) {
            break;
        }
        err = pthread_create(&ctx->tid, NULL, seco_nvm_manager_thread, ctx);
    } while (0);

    if (err) {
        free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int32_t she_storage_terminate(struct she_storage_context *nvm_ctx)
{
    int32_t err;
    err = pthread_cancel(nvm_ctx->tid);

    seco_nvm_close_session(nvm_ctx->nvm_hdl);

    return err;
}
