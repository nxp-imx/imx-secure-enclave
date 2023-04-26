// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#ifndef HSM_API_H
#define HSM_API_H

#include <stdint.h>

#ifndef PSA_COMPLIANT
#include "hsm_api2.h"
#endif

#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key_store.h"

#include "internal/hsm_key_gen_ext.h"

#include "internal/hsm_gc_akey_gen.h"

#include "internal/hsm_gc_acrypto.h"

#include "internal/hsm_importkey.h"

#include "internal/hsm_delete_key.h"

#include "internal/hsm_get_key_attr.h"

#include "internal/hsm_managekey.h"

#include "internal/hsm_debug_dump.h"

#include "internal/hsm_key_recovery.h"

#include "internal/hsm_dev_getinfo.h"

#include "internal/hsm_lc_update.h"

#include "internal/hsm_dev_attest.h"

#include "internal/hsm_get_info.h"
/**
 *  @defgroup group1 Session
 * The API must be initialized by a potential requestor by opening a session.\n
 * Once a session is closed all the associated service flows are closed by the HSM.
 *  @{
 */
#include "internal/hsm_session.h"
/**
 *
 * \param args pointer to the structure containing the function arguments.

 * \param session_hdl pointer to where the session handle must be written.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl);

/**
 * Terminate a previously opened session. All the services opened under this session are closed as well \n
 *
 * \param session_hdl pointer to the handle identifying the session to be closed.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_close_session(hsm_hdl_t session_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group1
 *
 * i.MX8QXP HSM is implemented only on SECO core which doesn't offer priority management neither low latencies.
 * - \ref HSM_OPEN_SESSION_FIPS_MODE_MASK not supported and ignored
 * - \ref HSM_OPEN_SESSION_EXCLUSIVE_MASK not supported and ignored
 * - session_priority field of \ref open_session_args_t is ignored.
 * - \ref HSM_OPEN_SESSION_LOW_LATENCY_MASK not supported and ignored.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group1
 *
 * i.MX8DXL has 2 separate implementations of HSM on SECO and on V2X cores.
 * - \ref HSM_OPEN_SESSION_FIPS_MODE_MASK not supported and ignored
 * - \ref HSM_OPEN_SESSION_EXCLUSIVE_MASK not supported and ignored
 * - If \ref HSM_OPEN_SESSION_LOW_LATENCY_MASK is unset then SECO implementation will be used.
 * In this case session_priority field of \ref open_session_args_t is ignored.
 * - If \ref HSM_OPEN_SESSION_LOW_LATENCY_MASK is set then V2X implementation is used. session_priority field of \ref open_session_args_t and \ref HSM_OPEN_SESSION_NO_KEY_STORE_MASK are considered.
 *
 */
/** @} end of session group */

/**
 *  @defgroup group3 Key management
 * @{
 */

#include "internal/hsm_key_management.h"

#include "internal/hsm_key_generate.h"

/**
 *  @defgroup group4 Ciphering
 * @{
 */
#include "internal/hsm_cipher.h"
/**
 * Secondary API to perform ciphering operation\n
 *
 * This API does the following:
 * 1. Open an Cipher Service Flow\n
 * 2. Perform ciphering operation\n
 * 3. Terminate a previously opened cipher service flow\n
 *
 * User can call this function only after having opened a cipher service flow.\n
 *
 * \param key_store_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_cipher(hsm_hdl_t cipher_hdl,
			op_cipher_one_go_args_t *cipher_one_go);
/** @} end of cipher service flow */

/**
 *  @defgroup group5 Signature generation
 * @{
 */

#include "internal/hsm_sign_gen.h"

#include "internal/hsm_sign_prepare.h"

/**
 * Secondary API to generate signature on the given message.\n
 *
 * This API does the following:
 * 1. Open a service flow for signature generation.\n
 * 2. Based on the flag to identify the type of message: Digest or actual message,\n
 *    generate the signature using the key corresponding to the key id.
 * 3. Post performing the operation, terminate the previously opened\n
 *    signature-generation service flow.\n
 *
 * User can call this function only after having opened a key-store.\n
 *
 * \param key_store_hdl handle identifying the current key-store.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_sign(hsm_hdl_t key_store_hdl, op_generate_sign_args_t *args);
/** @} end of signature generation service flow */

/**
 *  @defgroup group6 Signature verification
 * @{
 */
#include "internal/hsm_verify_sign.h"
/**
 * Secondary API to verify a message signature.
 *
 * This API does the following:
 * 1. Open a flow for verification of the signature.\n
 * 2. Based on the flag to identify the type of message: Digest or actual message,\n
 *    verification of the signature is done using the public key.
 * 3. Post performing the operation, terminate the previously opened\n
 *    signature-verification service flow.\n
 *
 * User can call this function only after having opened a session.\n
 *
 * \param key_store_hdl handle identifying the current key-store.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_verify_sign(hsm_hdl_t session_hdl,
			  op_verify_sign_args_t *args,
			  hsm_verification_status_t *verification_status);

/**
 *\addtogroup qxp_specific
 * \ref group6
 *
 * - \ref HSM_OP_VERIFY_SIGN_FLAGS_KEY_INTERNAL is not supported
 * - \ref hsm_import_public_key: This API is not supported
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group6
 *
 * - \ref HSM_OP_VERIFY_SIGN_FLAGS_COMPRESSED_POINT is not supported, in case of HSM_SIGNATURE_SCHEME_DSA_SM2_FP_256_SM3.
 * - \ref HSM_OP_VERIFY_SIGN_FLAGS_KEY_INTERNAL is not supported
 * - \ref hsm_import_public_key: This API is a preliminary version
 *
 */
/** @} end of signature verification service flow */

/**
 *  @defgroup group7 Random number generation
 * @{
 */

#include "internal/hsm_rng.h"

/**
 * Secondary API to fetch the Random Number\n
 *
 * This API does the following:
 * 1. Opens Random Number Generation Service Flow\n
 * 2. Get a freshly generated random number\n
 * 3. Terminate a previously opened rng service flow\n
 *
 * User can call this function only after having opened a session.\n
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_rng(hsm_hdl_t session_hdl, op_get_random_args_t *args);
/** @} end of rng service flow */

/**
 *  @defgroup group8 Hashing
 * @{
 */
#include "internal/hsm_hash.h"
/**
 * Secondary API to digest a message.\n
 *
 * This API does the following:
 * 1. Open an Hash Service Flow\n
 * 2. Perform hash\n
 * 3. Terminate a previously opened hash service flow\n
 *
 * User can call this function only after having opened a session.\n
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_hash(hsm_hdl_t session_hdl, op_hash_one_go_args_t *args);
/** @} end of hash service flow */

/**
 *  @defgroup group13 Data storage
 * @{
 */
#include "internal/hsm_data_storage.h"
/**
 * Secondary API to store and restoare data from the linux\n
 * filesystem managed by EdgeLock Enclave Firmware.
 *
 * This API does the following:
 * 1. Open an data storage service Flow\n
 * 2. Based on the flag for operation attribute: Store or Re-store,\n
 *    - Store the data
 *    - Re-store the data, from the non-volatile storage.
 * 3. Post performing the operation, terminate the previously opened\n
 *    data-storage service flow.\n
 *
 * User can call this function only after having opened a key-store.\n
 *
 * \param key_store_hdl handle identifying the current key-store.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_data_ops(hsm_hdl_t key_store_hdl,
			 op_data_storage_args_t *args);
/** @} end of data storage service flow */

/**
 *  @defgroup group15 Authenticated Encryption
 * @{
 */
#include "internal/hsm_auth_enc.h"
/**
 * Secondary API to perform Authenticated Encryption\n
 *
 * This API does the following:
 * 1. Opens Cipher Service Flow\n
 * 2. Perform Authenticated Encryption operation\n
 * 3. Terminates the previously opened Cipher service flow\n
 *
 * User can call this function only after having opened a key store service
 * flow.\n
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_auth_enc(hsm_hdl_t key_store_hdl, op_auth_enc_args_t *auth_enc_args);
/** @} end of authenticated encryption service flow */

/**
 *  @defgroup group16 Mac
 * @{
 */
#include "internal/hsm_mac.h"
/**
 * Secondary API to perform mac operation\n
 *
 * This API does the following:
 * 1. Open an MAC Service Flow\n
 * 2. Perform mac operation\n
 * 3. Terminate a previously opened mac service flow\n
 *
 * User can call this function only after having opened a key store service flow.\n
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_do_mac(hsm_hdl_t key_store_hdl,
		     op_mac_one_go_args_t *mac_one_go);
/** @} end of mac service flow */

/** \}*/
#endif
