/*
 * Copyright 2019 NXP
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
 * \defgroup hsm_api
 * \brief i.MX8 HSM API header file
 * \{
 */

#include <stdint.h>


#ifndef HSM_API_H
#define HSM_API_H

/**
 * \brief Error codes returned by HSM functions.
 */
typedef enum {
    HSM_NO_ERROR                = 0x0,      /**< Success. */
    HSM_OUT_OF_MEM              = 0x1,      /**< There is not enough memory to open a new session or service flow. */
    HSM_UNKNOWN_HANDLE          = 0x2,      /**< The provided handle doens't exist */
    HSM_UNKNOWN_KEY_STORE       = 0x3,      /**< The provided key store identifier doesn't exist */
    HSM_KEY_STORE_AUTH_ERROR    = 0x4,      /**< Key store authentication fails */
    HSM_UNKNOWN_ID              = 0x5,      /**< The provided identifier doens't exist. */
    HSM_BUF_SIZE_ERROR          = 0x6,      /**< The size of the buffer provided by the requester is too small for the requested operation */
    HSM_KEY_ERROR               = 0x7,      /**< The key cannot be used for the requested opearation. */
    HSM_MEM_ACCESS_ERROR        = 0x8,      /**< The specified memory address cannot be accessed. */
    HSM_INVALID_PARAM           = 0x9,      /**< One or more parameters are not valid */
    HSM_GENERAL_ERROR           = 0xFF,     /**< Error not covered by other codes occured. */
} hsm_err_t;


/**
 * Initiate a HSM session granting the usage of the specified key store.\n
 * The returned handle pointer is typed with the transparent struct "hsm_hdl_s".
 * The user doesn't need to know or to access the fields of this struct.
 * They only need to store this pointer and pass it to every calls to other APIs within the same HSM session.
 * 
 * \param key_storage_identifier key store identifier
 * \param access_flags bitmap indicating the requested access to the key store. The create flag must be specified to create a new key storage.
 * \param password password for accesing the key storage
 * \param session_priority not supported in current release, any value accepted.
 * \param operating_mode not supported in current release, any value accepted. 
 *
 *
 * \return pointer to the HSM handle.
 */
struct hsm_hdl_s *hsm_open_session(uint32_t key_storage_identifier, uint8_t access_flags, uint32_t password, uint8_t session_priority, uint8_t operating_mode);

/**
 * It must be specified to create a new key storage
 */
#define HSM_KEY_STORAGE_ACCESS_FLAG_NEW (1 << 0)


/**
 * Terminate a previously opened HSM session
 *
 * \param hdl pointer to the HSM handle to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_session(struct hsm_hdl_s *hdl);


/**
 * Open a key management service flow\n
 * User must open this service in order to perform operation on the keys (generate, delete, update)
 *
 * \param hdl pointer to the HSM handle
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
 * 
 * \return error code
 */
hsm_err_t hsm_open_key_management_service(struct hsm_hdl_s *hdl, uint32_t input_address_ext, uint32_t output_address_ext);


/**
 * Generate a key or a key pair in the key store. The public key can optionally be exported\n
 * User can call this function only after having opened a key management service flow
 *
 * \param hdl pointer to the HSM handle
 * \param key_identifier pointer to the identifier of the key slot to be used for the operation - The value HSM_KEY_IDENTIFIER_NEW indicates to create a new key slot 
 * \param output pointer to the output area to store the public key - A NULL pointer indicates to not store the public key
 * \param key_type indicates which type of key must be generated
 * \param output_size lenght in bytes of the output area
 * \param flags bitmap specifying the properties of the key
 * 
 * \return error code
 */
hsm_err_t hsm_key_management_cmd_key_generation(struct hsm_hdl_s *hdl, uint8_t *key_identifier, uint8_t *output, uint16_t key_type, uint8_t output_size, uint8_t flags);

/**
 * It must be specified to create a new key slot
 */
#define HSM_KEY_IDENTIFIER_NEW                  0xFFFFFFFF
#define HSM_KEY_TYPE_ECDSA_NIST_P224            0x00
#define HSM_KEY_TYPE_ECDSA_NIST_P256            0x01
#define HSM_KEY_TYPE_ECDSA_NIST_P384            0x02
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224     0x10
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256     0x11
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384     0x12
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224     0x20        
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256     0x21
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384     0x22
#define HSM_KEY_TYPE_AES_128                    0x30
#define HSM_KEY_TYPE_AES_192                    0x31
#define HSM_KEY_TYPE_AES_256                    0x32

/**
 * When set, the key is transient. Transient keys are deleted when the corresponding key store service flow is closed.
 */
#define HSM_KEY_FLAGS_TRANSIENT                 (1 << 0)

/**
 * When set, the key is permanent. Once created, it will not be possible to update or delete the key anymore.
 */
#define HSM_KEY_FLAGS_PERMANENT                 (1 << 1)


/**
 * Terminate a previously opened key management service flow
 *
 * \param hdl pointer to the HSM handle.
 * 
 * \return error code
 */
hsm_err_t hsm_close_key_management_service(struct hsm_hdl_s *hdl);


/**
 * Open a cipher service flow\n
 * User must open this service in order to perform cipher operations.
 *
 * \param hdl pointer to the HSM handle
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param flags bitmap indicating the service flow properties - not supported in current release, any value accepted.
 * 
 * \return error code
 */
hsm_err_t hsm_open_cipher_service(struct hsm_hdl_s *hdl, uint32_t input_address_ext, uint32_t output_address_ext, uint8_t flags);


/**
 *
 * Prerform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param hdl pointer to the HSM handle
 * \param key_identifier identifier of the key to be used for the operation
 * \param input pointer to the input to be processed
 * \param output pointer to the output area
 * \param iv pointer to the initialization vector - it must be NULL for algorithms not using the initialization vector
 * \param input_size lenght in bytes of the input
 * \param iv_size lenght in bytes of the initialization vector - it must be 0 for algorithms not using the initialization vector
 * \param algorithm to be used for the operation
 * \param flags bitmap specifying the operation attributes
 *
 * \return error code
 */
hsm_err_t hsm_cipher_cmd_cipher_one_go(struct hsm_hdl_s *hdl, uint32_t key_identifier, uint8_t *input, uint8_t *output, uint8_t *iv, uint32_t *input_size, uint16_t iv_size, uint8_t algorithm, uint8_t flags);
#define HSM_CIPHER_ONE_GO_ALGO_AES_ECB 0x00
#define HSM_CIPHER_ONE_GO_ALGO_AES_CBC 0x01
#define HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT (1)
#define HSM_CIPHER_ONE_GO_FLAGS_DECRYPT (0)


/**
 * Terminate a previously opened cipher service flow
 *
 * \param hdl pointer to the HSM handle.
 * 
 * \return error code
 */
hsm_err_t hsm_close_cipher_service(struct hsm_hdl_s *hdl);


/** \}*/
#endif
