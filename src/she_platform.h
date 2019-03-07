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
#include <stdlib.h>

#include "she_api.h"

#ifndef SHE_PLATFORM_H
#define SHE_PLATFORM_H

#define SECURE_RAM_BASE_ADDRESS_SECURE	0x20800000

/* Platform specific implementations for SHE API.*/
struct she_platform_hdl *she_platform_open_she_session(void);

void she_platform_close_session(struct she_platform_hdl *phdl);

uint32_t she_platform_send_mu_message(struct she_platform_hdl *phdl, uint32_t *message, uint32_t size);

uint32_t she_platform_read_mu_message(struct she_platform_hdl *phdl, uint32_t *message, int32_t size);

int32_t she_platform_configure_shared_buf(struct she_platform_hdl *phdl, uint32_t shared_buf_off, uint32_t size);

uint32_t she_platform_copy_to_shared_buf(struct she_platform_hdl *phdl, uint32_t dst_off, void *src, uint32_t size);

uint32_t she_platform_copy_from_shared_buf(struct she_platform_hdl *phdl, uint32_t src_off, void *dst, uint32_t size);

uint32_t she_platform_shared_buf_offset(struct she_platform_hdl *phdl);

int32_t she_platform_create_thread(void * (*func)(void *), void * arg);


/* Functions specific to storage. */

struct she_platform_hdl *she_platform_open_storage_session(void);

uint32_t she_platform_storage_write(struct she_platform_hdl *phdl, uint32_t offset, uint32_t size);

uint32_t she_platform_storage_read(struct she_platform_hdl *phdl, uint32_t offset, uint32_t max_size);

#endif