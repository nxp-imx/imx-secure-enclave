// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_KEY_STORE_H
#define SHE_KEY_STORE_H

#include "internal/she_handle.h"
#include "common/key_store.h"

/**
 * @defgroup group2 Key store
 * User must open a key store service flow in order to perform all operations on keys.
 *  - create a new key store
 *  - perform operations involving keys stored in the key store
 *  (ciphering, MAC generation/verification...)
 *  - perform a key store reprovisioning using a signed message.
 *  A key store re-provisioning results in erasing all the key stores handled
 *  by the SHE.
 *
 * To grant access to the key store, the caller is authenticated against the
 * domain ID (DID) and Messaging Unit used at the keystore creation,
 * additionally an authentication nonce can be provided.
 * @{
 */

#define KEY_STORE_OPEN_FLAGS_DEFAULT                0x0u
//!< default flags

#define KEY_STORE_OPEN_FLAGS_CREATE                 0x1u
//!< Create a key store

#define KEY_STORE_OPEN_FLAGS_SHE                    0x2u
//!< Target key store is a SHE key store

#define KEY_STORE_OPEN_FLAGS_SET_MAC_LEN            0x8u
//!< Check min mac length

#define KEY_STORE_OPEN_FLAGS_SHARED		    0x20u
//!< Target key store is a shared key store (applicable only for i.MX95)

#define KEY_STORE_OPEN_FLAGS_STRICT_OPERATION       0x80u
//!< The request is completed only when the key store has been written\n in the NVM and the monotonic counter has been updated. This flag is\n applicable for CREATE operation only

#define SHE_STORAGE_MIN_MAC_BIT_LENGTH_DEFAULT      32u
//!< default MAC verification length in bits

/**
 * Open a service flow on the specified key store.
 *
 * \param session_hdl SHE handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_open_key_store_service(she_hdl_t session_hdl,
				     open_svc_key_store_args_t *args);

/**
 * Terminate a previously opened key store service flow
 *
 * \param key_store_handle handle identifying the key store service.
 *
 * \return error code.
 */
she_err_t she_close_key_store_service(she_hdl_t key_store_handle);

/** @} end of key store service flow */

#endif
