
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

#include "hsm_api.h"
#include "seco_ioctl.h"


#define SECO_HSM_PATH "/dev/seco_hsm"

struct hsm_session_hdl_s {
    int32_t fd;
    hsm_hdl_t session_hdl;
};

struct hsm_service_hdl_s {
    struct hsm_session_hdl_s *session;
    uint32_t service_hdl;
};

#define HSM_MAX_SESSIONS    (8u)
#define HSM_MAX_SERVICES    (32u)

static struct hsm_session_hdl_s hsm_sessions[HSM_MAX_SESSIONS] = {};
static struct hsm_service_hdl_s hsm_services[HSM_MAX_SERVICES] = {};


static struct hsm_session_hdl_s *session_hdl_to_ptr(hsm_hdl_t hdl)
{
    uint32_t i;
    struct hsm_session_hdl_s *ret;

    ret = NULL;
    for (i=0u; i<HSM_MAX_SESSIONS; i++) {
        if (hdl == hsm_sessions[i].session_hdl) {
            ret = &hsm_sessions[i];
            break;
        }
    }
    return ret;
}

static struct hsm_session_hdl_s *add_session(void)
{
    uint32_t i;
    struct hsm_session_hdl_s *s_ptr = NULL;

    for (i=0u; i<HSM_MAX_SESSIONS; i++) {
        if (hsm_sessions[i].session_hdl == 0u) {
            /* Found an empty slot. */
            s_ptr = &hsm_sessions[i];
            break;
        }
    }
    return s_ptr;
}

static void delete_session(struct hsm_session_hdl_s *s_ptr)
{
    if (s_ptr != NULL) {
        s_ptr->session_hdl = 0u;
    }
}

/* Open a HSM user session and return a pointer to the session handle. */
hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl)
{
    struct seco_ioctl_hsm_open_session ioctl_msg;
    struct hsm_session_hdl_s *s_ptr;
    hsm_err_t err = HSM_GENERAL_ERROR;

    do {
        s_ptr = add_session();
        if (s_ptr == NULL) {
            break;
        }

        s_ptr->fd = open(SECO_HSM_PATH, O_RDWR);
        if (s_ptr->fd < 0) {
            break;
        }

        ioctl_msg.session_priority = args->session_priority;
        ioctl_msg.operating_mode = args->operating_mode;
        if (ioctl(s_ptr->fd, SECO_MU_IOCTL_HSM_OPEN_SESSION, &ioctl_msg) == 0) {
            err = ioctl_msg.error;
            *session_hdl = ioctl_msg.session_hdl;
            s_ptr->session_hdl = ioctl_msg.session_hdl;
        }
    } while(0);

    if (err != HSM_NO_ERROR) {
        if (s_ptr != NULL) {
            close(s_ptr->fd);
            delete_session(s_ptr);
        }
    }

    return err;
};

/* Close a previously opened HSM session. */
hsm_err_t hsm_close_session(hsm_hdl_t session_hdl)
{
    struct seco_ioctl_hsm_close_session ioctl_msg;
    struct hsm_session_hdl_s *s_ptr;
    hsm_err_t err = HSM_GENERAL_ERROR;

    do {
        s_ptr = session_hdl_to_ptr(session_hdl);
        if (s_ptr == NULL) {
            break;
        }

        ioctl_msg.session_hdl = session_hdl;
        if (ioctl(s_ptr->fd, SECO_MU_IOCTL_HSM_CLOSE_SESSION, &ioctl_msg) == 0) {
            err = ioctl_msg.error;
        };

        close(s_ptr->fd);
        delete_session(s_ptr);
    } while(0);

    return err;
}
