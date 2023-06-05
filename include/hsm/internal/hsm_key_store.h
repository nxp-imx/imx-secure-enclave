// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_KEY_STORE_H
#define HSM_KEY_STORE_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

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
//!< stored in the key store when creating the key store.\n
//!< Must only be set at key store creation.
#define HSM_SVC_KEY_STORE_FLAGS_STRICT_OPERATION \
			((hsm_svc_key_store_flags_t)(1u << 7))
//!< The request is completed only when the new key store has been written in
//!< in the NVM. This applicable for CREATE operations only.

/**
 * Structure specifying the open key store service member arguments
 */
typedef struct {
	//!< handle identifying the key store service flow
	hsm_hdl_t key_store_hdl;
	//!< user defined id identifying the key store.
	//   Only one key store service can be opened on a given
	//   key_store_identifier.
	uint32_t key_store_identifier;
	//!< user defined nonce used as authentication proof for accessing the
	//   key store.
	uint32_t authentication_nonce;
	//!< bitmap specifying the services properties.
	hsm_svc_key_store_flags_t flags;
#ifndef PSA_COMPLIANT
	//!< maximum number of updates authorized for the key store.
	//   - Valid only for create operation.\n
	//   - This parameter has the goal to limit the occupation of the
	//   monotonic counter used as anti-rollback protection.\n
	//   -  If the maximum number of updates is reached, HSM still allows
	//   key store updates but without updating the monotonic counter giving
	//   the opportunity for rollback attacks.
	uint16_t max_updates_number;
	//!< it corresponds to the minimum mac length (in bits) accepted by
	//   the HSM to perform MAC verification operations.\n
	//   Only used upon key store creation when HSM_SVC_KEY_STORE_FLAGS_SET_MAC_LEN
	//   bit is set.\n
	//   It is effective only for MAC verification operations with the
	//   mac length expressed in bits.\n
	//   It can be used to replace the default value (32 bits).\n
	//   It impacts all MAC algorithms and all key lengths.\n
	//   It must be different from 0.\n
	//   When in FIPS approved mode values < 32 bits are not allowed.\n
	//   Only used on devices implementing SECO FW.
	uint8_t min_mac_length;
#endif
	//!< pointer to signed_message to be sent only in case of
	//   key store re-provisioning.
	uint8_t *signed_message;
	//!< size of the signed_message to be sent only in case of
	//   key store re-provisioning.
	uint16_t signed_msg_size;
} open_svc_key_store_args_t;

/**
 * Open a service flow on the specified key store.
 * Only one key store service can be opened on a given key store.
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param key_store_hdl pointer to where the key store service flow handle must
 * be written.
 *
 * \return error_code error code.
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
 * \return error_code error code.
 */
hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl);

/** @} end of key store service flow */

#endif
