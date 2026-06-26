// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#ifndef HSM_KEY_STORE_H
#define HSM_KEY_STORE_H

#include "hsm_handle.h"
#include "hsm_utils.h"
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
#define HSM_SVC_KEY_STORE_FLAGS_SHARED \
			((hsm_svc_key_store_flags_t)(1u << 2))
//!< It must be specified to create or load a shared key store.
#define HSM_SVC_KEY_STORE_FLAGS_SET_MAC_LEN \
			((hsm_svc_key_store_flags_t)(1u << 3))
//!< If set, minimum mac length specified in min_mac_length field will be
//!< stored in the key store when creating the key store.
//!< Must only be set at key store creation.
#ifdef PSA_COMPLIANT
#define HSM_SVC_KEY_STORE_FLAGS_KEY_STORE_STATUS \
	((hsm_svc_key_store_flags_t)(1u << 4))
//!<  Get Key store status. The status include following details:
//!<   - Key Store ID exist or does not exist.
//!<   - Key Store ID opened or not opened.
//!<   - Number of keys stored in Key store ID.
//!<   - Number of sessions stored in Key store ID.
#endif
#define HSM_SVC_KEY_STORE_FLAGS_MONOTONIC \
	((hsm_svc_key_store_flags_t)(1u << 5))
//!< When used in conjunction with STRICT flag, the request is completed only when
//!< the monotonic counter has been updated.
#define HSM_SVC_KEY_STORE_FLAGS_STRICT_OPERATION \
			((hsm_svc_key_store_flags_t)(1u << 7))
//!< The request is completed only when the new key store has been written
//!< in the NVM. This applicable for CREATE operations only.
//!< NOTE: In latest ELE FW API guide, STRICT has been replaced with SYNC.

#ifdef PSA_COMPLIANT
//!< Macros to decode Key store status information
#define HSM_KEY_STORE_STATUS_EXIST(status)     (((status) >> 0) & 0x01u)
#define HSM_KEY_STORE_STATUS_OPEN(status)      (((status) >> 1) & 0x01u)
#define HSM_KEY_STORE_STATUS_NUM_KEYS(status)  (((status) >> 8) & 0xFFu)
#define HSM_KEY_STORE_STATUS_NUM_SESS(status)  (((status) >> 16) & 0xFFFFu)
#endif

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
#ifdef PSA_COMPLIANT
/**
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param key_store_id key store identifier for getting the status.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
hsm_err_t hsm_get_key_store_status(hsm_hdl_t session_hdl,
				   uint32_t key_store_id,
				   op_key_store_status_args_t *args);

#ifdef PSA_COMPLIANT
typedef uint8_t hsm_storage_flags_t;

#define HSM_STORAGE_FLAGS_NVM_STATUS \
			((hsm_storage_flags_t)(1u << 7))
typedef enum {
	HSM_STORAGE_STATUS_NOT_OPENED,
	HSM_STORAGE_STATUS_OPENED,
	HSM_STORAGE_STATUS_FETCH_FAILED,
} hsm_storage_status_t;

#define HSM_STORAGE_GET_STATUS(status)  ((status) & 0x01u)

#define HSM_KEY_STORE_STATUS_STORAGE_OPEN HSM_STORAGE_GET_STATUS
//!< Going to be depricated. Use HSM_STORAGE_GET_STATUS instead.

/**
 * \param session_hdl: pointer to the handle identifying the current session
 *                     opened with mu_type. se_lib_service_hdl handle can be
 *		       used too, instead of session_hdl.
 * \param mu_type idenfier to the MU type on which storage status to be fetched.
 *
 * Any one of the above param, is required. If session_hdl is provided, other is
 * optional. If both are provided, session_hdl will be used; other will be ignored.
 *
 * \param storage_status pointer-reference of type hsm_storage_status_t:
 *      HSM_STORAGE_STATUS_NOT_OPENED,
 *      HSM_STORAGE_STATUS_OPENED,
 *      HSM_STORAGE_STATUS_FETCH_FAILED,
 *
 * \return error code.
 */
hsm_err_t hsm_get_storage_status(hsm_hdl_t session_hdl, uint32_t mu_type,
				 hsm_storage_status_t *storage_status);
#endif
#endif
/** @} end of key store service flow */

#endif
