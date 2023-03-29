/*
 * Copyright 2019-2023 NXP
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

/** 
 * \mainpage
 * \defgroup she_storage
 * \brief SHE NVM storage API
 * \{
 */

#ifndef NVM_H
#define NVM_H

#include <stdint.h>

uint32_t nvm_manager(uint8_t flags,
		     void **ctx,
		     uint8_t *fname,
		     uint8_t *dname);

void nvm_close_session(void *ctx);

uint32_t get_nvmd_status(void *ctx);

#define NVM_FLAGS_V2X    (0x02u)
#define NVM_FLAGS_SHE    (0x01u)
#define NVM_FLAGS_HSM    (0x00u)

#define NVM_STATUS_UNDEF    (0x00u)
#define NVM_STATUS_STARTING (0x01u)
#define NVM_STATUS_RUNNING  (0x02u)
#define NVM_STATUS_STOPPED  (0x03u)

/**
 * \}
 */

#endif
