// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
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

void set_nvmd_status_stop(void *ctx);

#define NVM_FLAGS_V2X		(0x02u)
#define NVM_FLAGS_SHE		(0x01u)
#define NVM_FLAGS_HSM		(0x00u)
#define NVM_FLAGS_V2X_SHE	(NVM_FLAGS_V2X | NVM_FLAGS_SHE)
#define NVM_FLAGS_V2X_HSM	(NVM_FLAGS_V2X | NVM_FLAGS_HSM)

#define NVM_STATUS_UNDEF    (0x00u)
#define NVM_STATUS_STARTING (0x01u)
#define NVM_STATUS_RUNNING  (0x02u)
#define NVM_STATUS_STOPPED  (0x03u)

/**
 * \}
 */

#endif
