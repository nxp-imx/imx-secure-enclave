/*
 * Copyright 2019-2020 NXP
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

#ifndef SECO_NVM_H
#define SECO_NVM_H

#include <stdint.h>

void seco_nvm_manager(uint8_t flags, uint32_t *status);
#define NVM_FLAGS_SHE    (0x01u)
#define NVM_FLAGS_HSM    (0x00u)

#define NVM_STATUS_UNDEF    (0x00u)
#define NVM_STATUS_STARTING (0x01u)
#define NVM_STATUS_RUNNING  (0x02u)
#define NVM_STATUS_STOPPED  (0x03u)

#endif
