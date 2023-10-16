// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_KEY_STORE_H
#define HSM_KEY_STORE_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "common/key_store.h"

/**
 *  @defgroup group2 Key store
 * User must open a key store service flow in order to perform the
 * following operations:
 *  - create a new key store
 *  - perform operations involving keys stored in the key store
 *  (ciphering, signature generation...)
 *  - perform a key store reprovisioning using a signed message.
 *  A key store re-provisioning results in erasing all the key stores handled
 *  by the HSM.
 *
 * To grant access to the key store, the caller is authenticated against the
 * domain ID (DID) and Messaging Unit used at the keystore creation,
 * additionally an authentication nonce can be provided.
 * @{
 */

/**
 * Bitmap specifying the open key store service supported attributes
 */
typedef uint8_t hsm_svc_key_store_flags_t;

#define HSM_SVC_KEY_STORE_FLAGS_LOAD \
			((hsm_svc_key_store_flags_t)(0u << 0))
//!< It must be specified to load a previously created key store.
#define HSM_SVC_KEY_STORE_FLAGS_CREATE \
			((hsm_svc_key_store_flags_t)(1u << 0))
//!< It must be specified to create a new key store. The key store will be
//!< stored in the NVM only if the STRICT OPERATION flag is set.
#define HSM_SVC_KEY_STORE_FLAGS_SET_MAC_LEN \
			((hsm_svc_key_store_flags_t)(1u << 3))
//!< If set, minimum mac length specified in min_mac_length field will be
//!< stored in the key store when creating the key store.
//!< Must only be set at key store creation.
#define HSM_SVC_KEY_STORE_FLAGS_MONOTONIC \
	((hsm_svc_key_store_flags_t)(1u << 5))
//!< When used in conjunction with STRICT flag, the request is completed only when
//!< the monotonic counter has been updated.
#define HSM_SVC_KEY_STORE_FLAGS_STRICT_OPERATION \
			((hsm_svc_key_store_flags_t)(1u << 7))
//!< The request is completed only when the new key store has been written
//!< in the NVM. This applicable for CREATE operations only.
//!< NOTE: In latest ELE FW API guide, STRICT has been replaced with SYNC.

/**
 * Open a service flow on the specified key store.
 * Only one key store service can be opened on a given key store.
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param key_store_hdl pointer to where the key store service flow handle must
 * be written.
 *
 * \return error code.
 */
hsm_err_t hsm_open_key_store_service(hsm_hdl_t session_hdl,
				     open_svc_key_store_args_t *args,
				     hsm_hdl_t *key_store_hdl);

/**
 * Close a previously opened key store service flow.
 * The key store is deleted from the HSM local memory,
 * any update not written in the NVM is lost \n
 *
 * \param key_store_hdl handle identifying the key store service flow to be closed.
 *
 * \return error code.
 */
hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl);

/**
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
hsm_err_t hsm_key_store_reprov_en(hsm_hdl_t session_hdl,
				  op_key_store_reprov_en_args_t *args);
/** @} end of key store service flow */

#endif
