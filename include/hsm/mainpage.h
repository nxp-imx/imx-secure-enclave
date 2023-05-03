// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifdef PSA_COMPLIANT
/*! \mainpage ELE HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8ULP, i.MX93 HSM
 * solutions for ELE Platform.
 */
/*! \page  History Revision History
 *
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 | Apr 27 2023  | Preliminary draft
 */

/*! \page page1 General concepts related to the API
 * \tableofcontents
 * \image latex hsm_services_ele.png
 * \section sec1 Session
 * The API must be initialized by a potential requestor by opening a session.\n
 * The session establishes a route (MU, DomainID...) between the requester and the HSM.
 * When a session is opened, the HSM returns a handle identifying the session to the requester.
 * \section sec2 Service flow
 * For a given category of services which require service handle, the requestor is expected to open
 * a service flow by invoking the appropriate HSM API.\n
 * The session handle, as well as the control data needed for the service flow, are provided as
 * parameters of the call.\n
 * Upon reception of the open request, the HSM allocates a context in which the session handle,as
 * well as the provided control parameters are stored and return a handle identifying the service
 * flow.\n
 * The context is preserved until the service flow, or the session, are closed by the user and it is
 * used by the HSM to proceed with the sub-sequent operations requested by the user on the service
 * flow.
 * \section sec3 Example
 * \image latex code_example_ele.png
 * \section sec4 Key store
 * A key store can be created by specifying the CREATE flag in the hsm_open_key_store_service API.
 * Please note that the created key store will be not stored in the NVM till a key is generated or
 * imported specyfing the "STRICT OPERATION" flag.\n
 * Only symmetric and private keys are stored into the key store. Public keys can be exported during
 * the key pair generation operation or recalculated through the hsm_pub_key_recovery API.\n
 * Secret keys cannot be exported under any circumstances, while they can be imported in encrypted
 * form.\n
 * \subsection subsec2 Key management
 * Keys are divided in groups, keys belonging to the same group are written/read from the NVM as a
 * monolitic block.\n
 * Up to 3 key groups can be handled in the HSM local memory (those immediately available to perform
 * crypto operations), while up to 1000 key groups can be handled in the external NVM and imported
 * in the local memory as needed.\n
 * If the local memory is full (3 key groups already reside in the HSM local memory) and a new key
 * group is needed by an incoming user request, the HSM swaps one of the local key group with the
 * one needed by the user request.\n
 * The user can control which key group must be kept in the local memory (cached) through the
 * manage_key_group API lock/unlock mechanism.\n
 * As general concept, frequently used keys should be kept, when possible, in the same key group and
 * locked in the local memory for performance optimization.\n
 * \subsection subsec3 NVM writing
 * All the APIs creating a key store (open key store API) or modyfing its content (key generation,
 * key_management, key derivation functions) provide a "STRICT OPERATION" flag. If the flag is set,
 * the HSM exports the relevant key store blocks into the external NVM and increments (blows one
 * bit) the OTP monotonic counter used as roll back protection. In case of key generation/derivation
 * /update the "STRICT OPERATION" has effect only on the target key group.\n
 * Any update to the key store must be considered as effective only after an operation specifying
 * flag "STRICT OPERATION" is aknowledged by the HSM. All the operations not specifying the "STRICT
 * OPERATION" flags impact the HSM local memory only and will be lost in case of system reset\n
 * Due to the limited monotonic counter size, the user should, when possible, perform multiple udate
 * before setting the "STRICT OPERATION" flag(i.e. keys to be updated should be kept in the same key
 * group).\n
 * Once the monotonic counter is completely blown a warning is returned on each key store export to
 * the NVM to inform the user that the new updates are not roll-back protected.
 * \section sec5 Implementation specificities
 * HSM API with common features are supported on i.MX8ULP and i.MX93.The details of supported
 * features per chip will be listed in the platform specifities.
 */

#else
/*! \mainpage HSM API
 *
 * This document is a software referece description of the API provided by the i.MX8 HSM solutions.
 */

/*! \page  History Revision History
 *
 * Revision       | date           | description
 * :------------: | :-------------:| :------------
 * 0.1 | Mar 29 2019  | Preliminary draft
 * 0.8 | May 24 2019  | It adds the following API: \n-signature generation \n-signature verification \n-rng \n-hash \n-butterfly key expansion \n-ECIES enc/dec \n-public key reconstruction \n-public key decompression
 * 0.9 | May 28 2019  | Explicit addresses are replaced by pointers.
 * 1.0 | May 29 2019  | - bug/typos fix. \n- Change HSM_SVC_KEY_STORE_FLAGS definition
 * 1.1 | July 31 2019 | - hsm_butterfly_key_expansion argument definition: dest_key_identifier is now a pointer. \n- add error code definition. \n- improve argument comments clarity
 * 1.5 | Sept 13 2019 | - manage key argument: fix padding size\n - butterfly key expansion: change argument definition\n- introduce public key recovery API
 * 1.6 | Oct 14 2019  | - add Key store section in chapter 3\n- change key_info and flags definition, substitute key_type_ext with group_id\n- hsm_generate_key, hsm_manage_key, hsm_butterfly_key_expansion: change argument definition\n- hsm_manage_key: change argument definition\n- add hsm_manage_key_group API
 * 1.7 | Dec 20 2019  | - add generic data storage API \n- add GCM and CMAC support\n- add support for AES 192/256 key size for all cipher algorithms\n - add root KEK export API\n - add key import functionality\n- add get info API
 * 2.0 | Feb 21 2020  | - fix HSM_KEY_INFO_TRANSIENT definition: delete erroneous "not supported" comment \n- add Key Encryption Key (HSM_KEY_INFO_KEK) support \n- key store open service API: adding signed message support for key store reprovisionning \n- naming consistency: remove "hsm_" prefix from \n hsm_op_ecies_dec_args_t \n hsm_op_pub_key_rec_args_t \n hsm_op_pub_key_dec_args_t \n hsm_op_ecies_enc_args_t \n hsm_op_pub_key_recovery_args_t \n hsm_op_get_info_args_t
 * 2.1 | Apr 16 2020  | - Preliminary version: Add the support of the chinese algorithms and update for i.MX8DXL
 * 2.2 | Apr 30 2020  | - fix erroneous number of supported key groups (correct number is 1000 while 1024 was indicated)\n- add missing status code definition \n- remove hsm_open_key_store_service unused flags: HSM_SVC_KEY_STORE_FLAGS_UPDATE, HSM_SVC_KEY_STORE_FLAGS_DELETE
 * 2.3 | June 30 2020  | - hsm_get_info fips mode definition: now specifying "FIPS mode of operation" and "FIPS certified part" bits.\n- Update i.MX8QXP specificities section specifying operations disabled when in FIPS approved mode. \n- Update comments related to cipher_one_go and SM2 ECES APIs for i.MX8DXL
 * 2.4 | July 9 2020 | - clarify support of hsm_import_public key API.
 * 2.5 | July 28 2020 | - add section in "i.MX8QXP specificities" chapter indicating the maximum number of keys per group.
 * 2.6 | Jul 29 2020  | - Key Exchange: add the definition of ECDH_P384 and TLS KDFs\n- mac_one_go: add definition of HMAC SHA256/384.
 * 2.7 | Sep 25 2020  | - Key Exchange: additional TLS KDFs support, CMAC KDF replaced by SHA-256 KDF\n- mac_one_go: add support of HMAC SHA224/523.
 * 2.8 | Sep 30 2020  | - Key Exchange: add details related to the SM2 key exchange.
 * 2.9 | Oct 14 2020  | - key_store_open: add STRICT_OPERATION flag. This flag allows to export the key store in the external NVM at the key store creation.
 * 3.0 | Nov 16 2020  |  hsm_open_key_store_service: add min_mac_length argument.\n hsm_mac_one_go - verification: add HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS to represent mac_length in bit.\n hsm_key_exchange:\n - enforce new costraints on KEK and TLS key generations\n - add signed message arguments for KEK generation.\n - rename HSM_KDF_ALG_SHA_256 in HSM_KDF_ONE_STEP_SHA_256.\n - rename HSM_OP_KEY_EXCHANGE_FLAGS_USE_EPHEMERAL in HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL
 * 3.1 | Nov 20 2020  |  Enable support of key_exchange and HMAC on QXP
 * 3.2 | Dec 1  2020  | hsm_generate_key, hsm_manage_key: fix key_group argument wrong description. User must specify the key group for CREATE/UPDATE/DELETE operations.
 * 3.2 Amendement | Feb 3 2021 | Clarify Key_exchange and HMAC support on QXP - both are not supported.
 * 3.3 | Jan 11 2021  | Add hsm_tls_finish API.\n Update hsm_key_exchange description:\n - The TLS master_secret is now stored into the key store and accesible by the hsm_tls_finish API\n - TLS KDF: add support of extended master secret\n hsm_auth_enc API - GCM encryption (not backward compatible): the IV cannot be fully provided by the user anymore, it must be generated by the HSM instead.
 * 3.4 | Jan 13 2021  | Add support of per-key min mac length using extension commands for key create and key manage.
 * 3.5 | Feb 5 2021   | Clarify hsm_tls_finish support on QXP - not supported.
 * 3.6 | Feb 12 2021  | Key exchange for KEK negotiation supported on QXP, usage of IV flags for auth_enc clarified.
 * 3.7 | Mar 19 2021  | Add HSM_FATAL_FAILURE error code definition
 * 3.8 | April 30 2021| - hsm_open_key_store_service, hsm_generate_key_ext, hsm_manage_key_ext: min_mac_len cannot be set to values < 32 bits when in FIPS approved mode. \n - Update hsm_key_exchange kdf_input_size argument description in case of TLS Key generation.
 * 3.9 | May 12 2021  | - Butterfly key expansion: add the support of SM2 on DXL \n - Public key reconstruction: add the support of SM2 on DXL \n - Introduce standalone Butterfly key expansion API on DXL. \n - Butterfly key expansion, Public key reconstruction, ECIES enc/dec: remove the support of BR256T1 on DXL. \n- hsm_prepare_signature: specify max number of stored pre-calculated values. \n key exchange: add the support of BR256T1 on DXL.
 * 4.0 | Aug 05 2021  | - Authenticated encryption: add the support of SM4 CCM on DXL. \n - Add key generic cryptographic service API on DXL.
 * */

/*! \page page1 General concepts related to the API
  \tableofcontents
  \image latex hsm_services_seco.png
  \section sec1 Session
  The API must be initialized by a potential requestor by opening a session.\n
  The session establishes a route (MU, DomainID...) between the requester and the HSM.
  When a session is opened, the HSM returns a handle identifying the session to the requester.
  \section sec2 Service flow
  For a given category of services, the requestor is expected to open a service flow by invoking the appropriate HSM API.\n
  The session handle, as well as the control data needed for the service flow, are provided as parameters of the call.\n
  Upon reception of the open request, the HSM allocates a context in which the session handle, as well as the provided control parameters are stored and return a handle identifying the service flow.\n
  The context is preserved until the service flow, or the session, are closed by the user and it is used by the HSM to proceed with the sub-sequent operations requested by the user on the service flow.
  \section sec3 Example
\image latex code_example_seco.png
  \section sec4 Key store
  A key store can be created by specifying the CREATE flag in the hsm_open_key_store_service API. Please note that the created key store will be not stored in the NVM till a key is generated/imported specyfing the "STRICT OPERATION" flag.\n
  Only symmetric and private keys are stored into the key store. Public keys can be exported during the key pair generation operation or recalculated through the hsm_pub_key_recovery API.\n
  Secret keys cannot be exported under any circumstances, while they can be imported in encrypted form.\n
  \subsection subsec2 Key management
  Keys are divided in groups, keys belonging to the same group are written/read from the NVM as a monolitic block.\n
  Up to 3 key groups can be handled in the HSM local memory (those immediatly available to perform crypto operations), while up to 1000 key groups can be handled in the external NVM and imported in the local memory as needed.\n
  If the local memory is full (3 key groups already reside in the HSM local memory) and a new key group is needed by an incoming user request, the HSM swaps one of the local key group with the one needed by the user request.\n
  The user can control which key group must be kept in the local memory (cached) through the manage_key_group API lock/unlock mechanism.\n
  As general concept, frequently used keys should be kept, when possible, in the same key group and locked in the local memory for performance optimization.\n
  \subsection subsec3 NVM writing
  All the APIs creating a key store (open key store API) or modyfing its content (key generation, key_management, key derivation functions) provide a "STRICT OPERATION" flag. If the flag is set, the HSM exports the relevant key store blocks into the external NVM and increments (blows one bit) the OTP monotonic counter used as roll back protection. In case of key generation/derivation/update the "STRICT OPERATION" has effect only on the target key group.\n
  Any update to the key store must be considered as effective only after an operation specifing the flag "STRICT OPERATION" is aknowledged by the HSM. All the operations not specifying the "STRICT OPERATION" flags impact the HSM local memory only and will be lost in case of system reset\n
  Due to the limited monotonic counter size (QXPB0 up to 1620 update available by default), the user should, when possible, perform multiple udates before setting the "STRICT OPERATION" flag (i.e. keys to be updated should be kept in the same key group).\n
  Once the monotonic counter is completely blown a warning is returned on each key store export to the NVM to inform the user that the new updates are not roll-back protected.
  \section sec5 Implementation specificities
  HSM API is supported on different versions of the i.MX8 family. The API description below is the same for all of them but some features may not be available on some chips. The details of the supported features per chip can be found here:
  - for i.MX8QXP: \ref qxp_specific
  - for i.MX8DXL: \ref dxl_specific
 */

/**
 * \defgroup qxp_specific i.MX8QXP specificities
 *
 */

/**
 * \defgroup dxl_specific i.MX8DXL specificities
 *
 */

/**
 *\addtogroup qxp_specific
 * \ref sec4
 *
 * The table below summarizes the maximum number of keys per group in the QXP implementation:
 * Key size (bits)| Number of keys per group
 * :------------: | :-------------:
 * 128 | 169
 * 192 | 126
 * 224 | 101
 * 256 | 101
 * 384 | 72
 * 512 | 56
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref sec4
 *
 * The table below summarizes the maximum number of keys per group in the DXL implementation:
 *
 * sessions using V2X implementation (HSM_OPEN_SESSION_LOW_LATENCY_MASK) :
 * Key size (bits)| Number of keys per group
 * :------------: | :-------------:
 * 128 | 166
 * 192 | 125
 * 224 | 111
 * 256 | 100
 * 384 | 71
 * 512 | 52
 *
 * session using SECO implementation : same number as QXP applies
 */
#endif
