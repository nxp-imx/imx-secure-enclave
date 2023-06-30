// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_KEY_STORE_H
#define SHE_KEY_STORE_H

#include "internal/hsm_key_store.h"
#include "internal/she_handle.h"

#define MIN_MAC_LEN_NOT_SET	BIT(0)
#define MIN_MAC_LEN_SET		BIT(1)

#define KEY_STORE_OPEN_FLAGS_DEFAULT                0x0u
#define KEY_STORE_OPEN_FLAGS_CREATE                 0x1u
#define KEY_STORE_OPEN_FLAGS_SHE                    0x2u
#define KEY_STORE_OPEN_FLAGS_SET_MAC_LEN            0x8u
#define KEY_STORE_OPEN_FLAGS_STRICT_OPERATION       0x80u

/**
 * New storage created successfully.
 */
#define SHE_STORAGE_CREATE_SUCCESS              0u
/**
 * New storage created but its usage is restricted to a limited security state of the chip.
 */
#define SHE_STORAGE_CREATE_WARNING              1u
/**
 * Creation of the storage is not authorized.
 */
#define SHE_STORAGE_CREATE_UNAUTHORIZED         2u
/**
 * Creation of the storage failed for any other reason.
 */
#define SHE_STORAGE_CREATE_FAIL                 3u
/**
 * default number of maximum number of updated for SHE storage.
 */
#define SHE_STORAGE_NUMBER_UPDATES_DEFAULT      300u
/**
 * default MAC verification length in bits
 */
#define SHE_STORAGE_MIN_MAC_BIT_LENGTH_DEFAULT  32u

she_err_t she_open_key_store(she_hdl_t session_hdl, open_svc_key_store_args_t *args);

#endif
