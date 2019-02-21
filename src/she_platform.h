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
#include <stdint.h>

#include "she_api.h"

#ifndef SHE_PLATFORM_H
#define SHE_PLATFORM_H


typedef enum {
	SHE_NVM,
	SHE_USER
} she_session_type;

/* Platform specific implementations for SHE API.*/
she_hdl *she_platform_open_session(she_session_type type);

void she_platform_close_session(she_hdl *hdl);

int she_platform_send_mu_message(she_hdl *hdl, char *message, int size);

int she_platform_read_mu_message(she_hdl *hdl, char *message, int size);

void she_platform_configure_shared_buf(she_hdl *hdl, int shared_buf_off, int size);

int she_platform_copy_to_shared_buf(she_hdl *hdl, int dst_off, void *src, int size);

int she_platform_copy_from_shared_buf(she_hdl *hdl, int src_off, void *dst, int size);

int she_platform_shared_buf_offset(she_hdl *hdl);

void she_platform_create_thread(void * (*func)(void *), void * arg);

uint32_t seco_storage_write(she_hdl *hdl, uint32_t offset, uint32_t size);

uint32_t seco_storage_read(she_hdl *hdl, uint32_t offset, uint32_t max_size);

#endif