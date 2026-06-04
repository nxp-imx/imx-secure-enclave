// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef NVM_BLOB_CONVERSION_H
#define NVM_BLOB_CONVERSION_H

#ifdef PSA_COMPLIANT
#include <stdint.h>
#include "sab_nvm.h"

/* NVM blob header size macros for the supported blob format versions */
#define NVM_HEADER_SZ_V1 16u
#define NVM_HEADER_SZ_V2 20u

/* Get the current/expected NVM blob header version */
uint8_t nvm_get_current_header_version(void);

/* Perform blob format conversion from current version to target version */
uint8_t nvm_blobs_format_conversion(struct nvm_ctx_st *nvm_ctx,
				    uint8_t current_version,
				    uint8_t target_version);
#endif
#endif
