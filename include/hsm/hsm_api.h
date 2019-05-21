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
    HSM_NO_ERROR                        = 0x0,      /**<    Success. */
    HSM_INVALID_MESSAGE                 = 0x1,      /**< 	The received message is invalid or unknown. */
    HSM_INVALID_ADDRESS                 = 0x2,      /**<    The provided address is invalid or doesn’t respect the API requirements. */
    HSM_UNKNOWN_ID                      = 0x3,      /**< 	The provided identifier is not known. */
    HSM_INVALID_PARAM                   = 0x4,      /**< 	One of the parameter provided in the command is invalid. */
    HSM_NVM_ERROR                       = 0x5,      /**< 	NVM generic issue. */
    HSM_OUT_OF_MEMORY                   = 0x6,      /**< 	There is not enough memory to handle the requested operation. */
    HSM_UNKNOWN_HANDLE                  = 0x7,      /**< 	Unknown session/service handle. */
    HSM_UNKNOWN_KEY_STORE               = 0x8,      /**< 	The key store identified by the provided “key store Id” doesn’t exist and the “create” flag is not set. */
    HSM_KEY_STORE_AUTH                  = 0x9,      /**< 	Key storage authentication fails. */
    HSM_KEY_STORAGE_ERROR               = 0xA,      /**< 	An error occurred in the key storage internal processing. */
    HSM_ID_CONFLICT                     = 0xB,      /**< 	An element (key storage, key…) with the provided ID already exists. */
    HSM_RNG_NOT_STARTED                 = 0xC,      /**< 	The internal RNG is not started. */
    HSM_CMD_NOT_SUPPORTED               = 0xD,      /**< 	The functionality is not supported for the current session/service/key store configuration. */
    HSM_INVALID_LIFECYCLE               = 0xE,      /**< 	Invalid lifecycle for requested operation. */
    HSM_KEY_STORE_CONFLICT              = 0xF,      /**< 	An key store with the same attributes already exists. */
    HSM_GENERAL_ERROR                   = 0xFF,     /**<    Error not covered by other codes occured. */
} hsm_err_t;

typedef uint8_t hsm_svc_key_store_flags_t;
typedef uint8_t hsm_svc_key_management_flags_t;
typedef uint8_t hsm_svc_cipher_flags_t;
typedef uint8_t hsm_svc_signature_flags_t;
typedef uint8_t hsm_svc_fast_signature_verification_flags_t;
typedef uint8_t hsm_svc_fast_signature_generation_flags_t;
typedef uint8_t hsm_svc_rng_flags_t;
typedef uint8_t hsm_svc_hash_flags_t;

typedef uint8_t hsm_op_key_gen_flags_t;
typedef uint8_t hsm_op_manage_key_flags_t;
typedef uint8_t hsm_op_but_key_exp_flags_t;
typedef uint8_t hsm_op_cipher_one_go_algo_t;
typedef uint8_t hsm_op_cipher_one_go_flags_t;
typedef uint8_t hsm_op_signature_gen_flags_t;
typedef uint8_t hsm_op_signature_ver_flags_t;
typedef uint8_t hsm_op_fast_signature_gen_flags_t;
typedef uint8_t hsm_op_fast_signature_ver_flags_t;

typedef uint16_t hsm_key_type_t;
typedef uint16_t hsm_key_info_t;
typedef uint8_t hsm_signature_scheme_id_t;
typedef uint8_t hsm_hash_algo_t;
typedef uint32_t hsm_verification_status_t;

typedef uint32_t hsm_addr_msb_t;
typedef uint32_t hsm_addr_lsb_t;

/**
 * Initiate a HSM session.\n
 *
 * \param session_priority not supported in current release, any value accepted.
 * \param operating_mode not supported in current release, any value accepted.
 * \param error_code pointer to where the error code should be written.
 * 
 * \return Pointer to the handle identifying the session. NULL in case of error.\n
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_session(uint8_t session_priority, uint8_t operating_mode, hsm_err_t *error_code);

/**
 * Terminate a previously opened HSM session
 *
 * \param session_hdl pointer to the handle identifying the session to be closed.
 *
 * \return error_code error code.
 */
 hsm_err_t hsm_close_session(struct hsm_hdl_s *session_hdl);


/**
 * Open a service flow on the specified key store.\n
 * 
 * \param session_hdl pointer to the handle indentifing the current session.
 * \param key_store_identifier user defined id identifying the key store.
 * \param authentication_nonce user defined nonce used as authentication proof for accesing the key storage.
 * \param max_updates_number maximum number of updates authorized for the storage. Valid only for create operation.
 * \param access_flags bitmap indicating the requested access to the key store.
 * \param error_code pointer to where the error code should be written.
 *
 * \return Pointer to the handle indentifying the key store service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */

struct hsm_hdl_s *hsm_open_key_store_service(struct hsm_hdl_s *session_hdl, struct hsm_hdl_s **key_store_hdl, uint32_t key_store_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, hsm_svc_key_store_flags_t flags, hsm_err_t *error_code);

/**
 * It must be specified to create a new key storage
 */
#define HSM_SVC_KEY_STORE_FLAGS_CREATE ((hsm_svc_key_store_flags_t)(1 << 0))
#define HSM_SVC_KEY_STORE_FLAGS_UPDATE ((hsm_svc_key_store_flags_t)(1 << 1))
#define HSM_SVC_KEY_STORE_FLAGS_DELETE ((hsm_svc_key_store_flags_t)(1 << 3))

/**
 * Close a previously opened key store service flow.\n
 * 
 * \param pointer to the handle indentifing the key store service flow to be closed.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_close_key_store_service(struct hsm_hdl_s *key_store_hdl);


/**
 * Open a key management service flow\n
 * User must open this service in order to perform operation on the key store content: key generate, delete, update
 *
 * \param key_store_hdl pointer to the handle indentifing the key management service flow.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
 * \param error_code pointer to where the error code should be written.
 *
 * \param Pointer to the handle indentifing the key management service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_key_management_service(struct hsm_hdl_s *key_store_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_err_t *error_code);


/**
 * Generate a key or a key pair in the key store. In case of asymetic keys, the public key can optionally be exported. The generated key can be stored in a new or in an existing key slot
 * with the restriction that an existing key can be replaced only by a key of the same type.\n
 * User can call this function only after having opened a key management service flow
 *
 * \param key_management_hdl pointer to handle identifying the key management service flow.
 * \param key_identifier pointer to the identifier of the key to be used for the operation. In case of create operation the new key identifier will be stored in this location.
 * \param output LSB of the address in the requester space where to store the public key. This address is combined with the 32 bits UOA extension provided for the service flow
 * \param output_size lenght in bytes of the output area, if the size is 0, no key is copied in the output.
 * \param key_type indicates which type of key must be generated
 * \param key_info bitmap specifying the properties of the key
 * \param flags bitmap specifying the operation properties
 * 
 * \return error code
 */

hsm_err_t hsm_generate_key(struct hsm_hdl_s *key_management_hdl, uint32_t key_identifier, hsm_addr_lsb_t output, uint16_t output_size, hsm_key_type_t key_type, hsm_key_info_t key_info, hsm_op_key_gen_flags_t flags);

#define HSM_KEY_TYPE_ECDSA_NIST_P224            ((hsm_key_type_t)0x01)
#define HSM_KEY_TYPE_ECDSA_NIST_P256            ((hsm_key_type_t)0x02)
#define HSM_KEY_TYPE_ECDSA_NIST_P384            ((hsm_key_type_t)0x03)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224     ((hsm_key_type_t)0x12)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256     ((hsm_key_type_t)0x13)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384     ((hsm_key_type_t)0x15)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224     ((hsm_key_type_t)0x22)        
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256     ((hsm_key_type_t)0x23)
#define HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384     ((hsm_key_type_t)0x25)

#define HSM_KEY_TYPE_AES_128                    ((hsm_key_type_t)0x30)
#define HSM_KEY_TYPE_AES_192                    ((hsm_key_type_t)0x31)
#define HSM_KEY_TYPE_AES_256                    ((hsm_key_type_t)0x32)
/**
 * When set, the key is permanent. Once created, it will not be possible to update or delete the key anymore. This bit can never be reset.
 */
#define HSM_KEY_INFO_PERMANENT                              ((hsm_key_info_t)(1 << 0))
/**
 * User can replace an existing key only by generating a key with the same type of the original one.
 */
#define HSM_OP_KEY_GENERATION_FLAGS_UPDATE                  ((hsm_op_key_gen_flags_t)(1 << 0))
/**
 * Persistent keys are saved in the non volatile memory.
 */
#define HSM_OP_KEY_GENERATION_FLAGS_CREATE_PERSISTENT       ((hsm_op_key_gen_flags_t)(1 << 1))
/**
 * Transient keys are deleted when the corresponding key store service flow is closed.
 */
#define HSM_OP_KEY_GENERATION_FLAGS_CREATE_TRANSIENT        ((hsm_op_key_gen_flags_t)(1 << 2))
/**
 * The request is completed only when the new key has been written in the NVM. This applicable for persistent key only.
 */
#define HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION        ((hsm_op_key_gen_flags_t)(1 << 7))


/**
 * This command is designed to perform operation on an existing key.\n
 * User can call this function only after having opened a key management service flow
 *
 * \param key_management_hdl pointer to handle identifying the key management service flow.
 * \param key_identifier identifier of the key to be used for the operation.
 * \param key_address LSB of the address in the requester space where the new key value can be found. This address is combined with the 32 bits UIA extension provided for the service flow. Not checked in case of delete operation.
 * \param key_size lenght in bytes of the input key area. Not checked in case of delete operation.
 * \param key_type indicates the type of the key to be managed.
 * \param key_info bitmap specifying the properties of the key, it will replace the existing value. Not checked in case of delete operation..
 * \param flags bitmap specifying the operation properties
 * 
 * \return error code
 */
hsm_err_t hsm_manage_key(struct hsm_hdl_s *key_management_hdl, uint32_t key_identifier, hsm_addr_lsb_t key, uint16_t key_size, hsm_key_type_t key_type, hsm_key_info_t key_info, hsm_op_manage_key_flags_t flags);
#define HSM_OP_MANGE_KEY_FLAGS_UPDATE                   ((hsm_op_manage_key_flags_t)(1 << 0))
#define HSM_OP_MANGE_KEY_FLAGS_DELETE                   ((hsm_op_manage_key_flags_t)(1 << 1))
/**
 * The request is completed only when the modification has been written in the NVM. This applicable for persistent key only.
 */
#define HSM_OP_MANGE_KEY_FLAGS_STRICT_OPERATION         ((hsm_op_manage_key_flags_t)(1 << 7))

/**
 * 
 * 
 * This command is designed to perform the butterfly key expansion operation on an ECC private key in case of implicit certificate. Optionally the resulting public key is exported.\n
 * User can call this function only after having opened a key management service flow
 *
 * The following operation is performed:
 * ButKey = (Key + AddData1) * MultiplyData + AddData2 (mod n)
 * 
 * \param key_management_hdl pointer to handle identifying the key store management service flow.
 * \param key_identifier identifier of the key to be used for the operation.
 * \param add_data_1 LSB of the address in the requester space where the add_data_1 input can be found\n value 0 in case of explicit certificate\n expansion function f1(k, i, j) result value in case of implicit certificate.
 * \param add_data_2 LSB of the address in the requester space where the add_data_2 input can be found\n expansion function f1/f2(k, i, j) result value in case of explicit certificate\n the private reconstruction value used in the derivation of the pseudonym ECC key in case of implicit certificate 
 * \param multiply_data LSB of the address in the requester space where the multiply_data input can be found\n value 1 in case of explicit certificate\n the hash value used to in the derivation of the pseudonym ECC key 
 * \param data_1_size lenght in bytes of the add_data_1 input
 * \param data_2_size lenght in bytes of the add_data_2 input
 * \param multiply_date_size lenght in bytes of the multiply_data input
 * \param output LSB of the address in the requester space where to store the public key. This address is combined with the 32 bits UOA extension provided for the service flow
 * \param output_size lenght in bytes of the output area, if the size is 0, no key is copied in the output.
 * \param flags bitmap specifying the operation properties
 * 
 * \return error code
*/
hsm_err_t hsm_butterfly_key_expansion(struct hsm_hdl_s *key_management_hdl, uint32_t key_identifier, hsm_addr_lsb_t add_data_1, hsm_addr_lsb_t add_data_2, hsm_addr_lsb_t multiply_data, uint16_t data_1_size, uint16_t data_2_size, uint16_t multiply_data_size, uint32_t dest_key_identifier, hsm_addr_lsb_t output, uint32_t output_size, hsm_op_but_key_exp_flags_t flags);


/**
 * Terminate a previously opened key management service flow
 *
 * \param key_management_hdl pointer to handle identifying the key management service flow.
 * 
 * \return error code
 */
hsm_err_t hsm_close_key_management_service(struct hsm_hdl_s * key_management_hdl);


/**
 * Open a cipher service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform cipher operations.
 *
 * \param key_store_hdl pointer to the handle indentifing the key management service flow.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param flags bitmap indicating the service flow properties - not supported in current release, any value accepted.
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the cipher service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_cipher_service(struct hsm_hdl_s *key_store_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_svc_cipher_flags_t flags,  hsm_err_t *error_code);


/**
 * Perform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param chiper_hdl pointer to handle identifying the cipher service flow.
 * \param key_identifier identifier of the key to be used for the operation
 * \param input LSB of the address in the requester space where the input to be processed can be found\n plaintext for encryption\n ciphertext for decryption (tag is concatenated for CCM)
 * \param output LSB of the address in the requester space where the output must be stored\n ciphertext for encryption (tag is concatenated for CCM)\n plaintext for decryption
 * \param iv LSB of the address in the requester space where the initialization vector can be found
 * \param input_size lenght in bytes of the input
 * \param iv_size lenght in bytes of the initialization vector\n it must be 0 for algorithms not using the initialization vector.\n It must be 12 for AES in CCM mode 
 * \param cipher_algo algorithm to be used for the operation
 * \param flags bitmap specifying the operation attributes
 *
 * \return error code
 */
hsm_err_t hsm_cipher_one_go(struct hsm_hdl_s *chiper_hdl, uint32_t key_identifier, hsm_addr_lsb_t input, hsm_addr_lsb_t output, hsm_addr_lsb_t iv, uint32_t input_size, uint32_t output_size, uint32_t iv_size, hsm_op_cipher_one_go_algo_t cipher_algo, hsm_op_cipher_one_go_flags_t flags);
#define HSM_CIPHER_ONE_GO_ALGO_AES_ECB              ((hsm_op_cipher_one_go_algo_t)(0x00))
#define HSM_CIPHER_ONE_GO_ALGO_AES_CBC              ((hsm_op_cipher_one_go_algo_t)(0x01))
/**
 * Perform AES CCM with following prerequisites:\n
 * - Adata = 0 - There is no associated data\n
 * - Tlen = 16 bytes\n
 */
#define HSM_CIPHER_ONE_GO_ALGO_AES_CCM              ((hsm_op_cipher_one_go_algo_t)(0x02))
#define HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT             ((hsm_op_cipher_one_go_flags_t)(1 << 0))
#define HSM_CIPHER_ONE_GO_FLAGS_DECRYPT             ((hsm_op_cipher_one_go_flags_t)(1 << 1))

/**
 * Terminate a previously opened cipher service flow
 *
 * \param chiper_hdl pointer to handle identifying the cipher service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_cipher_service(struct hsm_hdl_s *chiper_hdl);

/**
 * Open a signature service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform signature generation/verification operations.
 *
 * \param key_store_hdl pointer to the handle indentifing the key management service flow.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param flags bitmap indicating the service flow properties - not supported in current release, any value accepted.
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the signature service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_signature_service(struct hsm_hdl_s *key_store_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_svc_signature_flags_t flags,  hsm_err_t *error_code);


/**
 * Generate a digital signature according to the signature scheme\n
 * User can call this function only after having opened a signature service flow
 *
 * \param signature_hdl pointer to handle identifying the signature service flow
 * \param key_identifier identifier of the key to be used for the operation
 * \param scheme_id identifier of the digital signature scheme to be used for the operation
 * \param message LSB of the address in the requester space where the input (message or message digest) to be processed can be found\n
 * \param signature LSB of the address in the requester space where the signature must be stored\n the signature S=(c,d) is stored as c||d||lsb_y in case of compressed point signature, c||d otherwhise.
 * \param message_size lenght in bytes of the input
 * \param signature_size lenght in bytes of the output - it must contains additional 32bits where to store the Ry last significant bit
 * \param flags bitmap specifying the operation attributes
 *
 * \return error code
 */
hsm_err_t hsm_signature_generation(struct hsm_hdl_s *signature_hdl, uint32_t key_identifier, hsm_signature_scheme_id_t scheme_id, hsm_addr_lsb_t message, hsm_addr_lsb_t signature, uint32_t message_size, uint32_t signature_size, hsm_op_signature_gen_flags_t flags);
#define HSM_OP_SIGNATURE_GENERATION_INPUT_DIGEST        ((hsm_op_signature_gen_flags_t)(0 << 0))
#define HSM_OP_SIGNATURE_GENERATION_INPUT_MESSAGE       ((hsm_op_signature_gen_flags_t)(1 << 1))
#define HSM_OP_SIGNATURE_GENERATION_COMPRESSED_POINT    ((hsm_op_signature_gen_flags_t)(2 << 1))

#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P224_SHA_256            ((hsm_signature_scheme_id_t)0x01)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256            ((hsm_signature_scheme_id_t)0x02)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384            ((hsm_signature_scheme_id_t)0x03)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_224_SHA_256     ((hsm_signature_scheme_id_t)0x12)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256     ((hsm_signature_scheme_id_t)0x13)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384     ((hsm_signature_scheme_id_t)0x15)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_224_SHA_256     ((hsm_signature_scheme_id_t)0x22)        
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256     ((hsm_signature_scheme_id_t)0x23)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384     ((hsm_signature_scheme_id_t)0x25)


/**
 * Verify a digital signature according to the signature scheme\n
 * User can call this function only after having opened a signature service flow
 *
 * \param signature_hdl pointer to handle identifying the signature service flow.
 * \param key_address pointer to the key to be used for the operation
 * \param key_identifier identifier of the key to be used for the operation
 * \param ecc_domain_id identifier of the supported ECC domains to be used for the operation
 * \param message LSB of the address in the requester space where the input (message or message digest) to be processed can be found
 * \param signature LSB of the address in the requester space where the signature can be found\n the signature S=(c,d) must be in the format c||d.
 * \param message_size lenght in bytes of the input
 * \param signature_size lenght in bytes of the output - it must contains additional 32bits where to store the Ry last significant bit
 * \param status pointer to where the verification status must be stored\n if the verification suceed the value HSM_OP_SIGNATURE_VERIFICATION_STATUS_SUCCESS is returned.
 * \param flags bitmap specifying the operation attributes
 *
 * \return error code
 */
hsm_err_t hsm_signature_verification(struct hsm_hdl_s *signature_hdl, hsm_addr_lsb_t key_address, hsm_signature_scheme_id_t scheme_id, hsm_addr_lsb_t message, hsm_addr_lsb_t signature, uint32_t message_size, uint32_t signature_size, hsm_verification_status_t *status, hsm_op_signature_ver_flags_t flags);
#define HSM_OP_SIGNATURE_VERIFICATION_INPUT_DIGEST    ((hsm_op_signature_ver_flags_t)(0 << 0))
#define HSM_OP_SIGNATURE_VERIFICATION_INPUT_MESSAGE   ((hsm_op_signature_ver_flags_t)(1 << 1))
#define HSM_VERIFICATION_STATUS_SUCCESS   ((hsm_verification_status_t)(0x5A3CC3A5))
#define HSM_VERIFICATION_STATUS_FAILURE   ((hsm_verification_status_t)(0xA5C33C5A))

/**
 * Terminate a previously opened signature service flow
 *
 * \param signature_hdl pointer to handle identifying the signature service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_signature_service(struct hsm_hdl_s *signature_hdl);


/**
 * Open a fast signature generation service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform several signature generation by using the same private key.
 *
 * \param key_store_hdl pointer to the handle indentifing the key management service flow.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param key_identifier identifier of the private key to be used for the subsequent operations
 * \param flags bitmap indicating the service flow properties - not supported in current release, any value accepted.
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the fast signature generation service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_fast_signature_generation_service(struct hsm_hdl_s *key_store_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, uint32_t key_identifier, hsm_signature_scheme_id_t scheme_id, hsm_svc_fast_signature_generation_flags_t flags,  hsm_err_t *error_code);


/**
 * Generate a digital signature according to the signature scheme\n
 * User can call this function only after having opened a fast signature generation service flow (key_identifier is omitted in the command)
 *
 * \param fast_signature_gen_hdl pointer to handle identifying the fast signature generation service flow
 * \param scheme_id identifier of the digital signature scheme to be used for the operation
 * \param message LSB of the address in the requester space where the input to be processed (message or message digest) can be found.
 * \param signature LSB of the address in the requester space where the signature must be stored\n the signature S=(c,d) is stored as c||d|lsb_y in case of compressed point signature, c||d otherwhise.
 * \param message_size lenght in bytes of the input
 * \param signature_size lenght in bytes of the output - In case of compressed point signature additional 32bit must be provided.
 * \param flags bitmap specifying the operation attributes
 *
 * \return error code
 */
hsm_err_t hsm_fast_signature_generation(struct hsm_hdl_s *fast_signature_gen_hdl, hsm_addr_lsb_t message, hsm_addr_lsb_t signature, uint32_t message_size, uint32_t signature_size, hsm_op_fast_signature_gen_flags_t flags);
#define HSM_OP_FAST_SIGNATURE_GENERATION_INPUT_DIGEST        ((hsm_op_fast_signature_gen_flags_t)(0 << 0))
#define HSM_OP_FAST_SIGNATURE_GENERATION_INPUT_MESSAGE       ((hsm_op_fast_signature_gen_flags_t)(1 << 1))
#define HSM_OP_FAST_SIGNATURE_GENERATION_COMPRESSED_POINT    ((hsm_op_fast_signature_gen_flags_t)(2 << 1))


/**
 * Terminate a previously opened fast signature generation service flow
 *
 * \param fast_signature_gen_hdl pointer to handle identifying the signature service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_fast_signature_generation_service(struct hsm_hdl_s *fast_signature_gen_hdl);

/**
 * Open a fast signature verification service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform several signature generation by using the same private key.
 *
 * \param key_store_hdl pointer to the handle indentifing the key management service flow.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param key_identifier identifier of the private key to be used for the subsequent operations
 * \param flags bitmap indicating the service flow properties - not supported in current release, any value accepted.
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the fast signature generation service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_fast_signature_verification_service(struct hsm_hdl_s *key_store_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_addr_msb_t key_address_ext, hsm_addr_lsb_t key_address, hsm_svc_fast_signature_verification_flags_t flags, hsm_signature_scheme_id_t scheme_id, hsm_err_t *error_code);

/**
 * Verify a digital signature according to the signature scheme\n
 * User can call this function only after having opened a signature service flow
 *
 * \param signature_hdl pointer to handle identifying the signature service flow.
 * \param key_address pointer to the key to be used for the operation
 * \param key_identifier identifier of the key to be used for the operation
 * \param ecc_domain_id identifier of the supported ECC domains to be used for the operation
 * \param message LSB of the address in the requester space where the input to be processed (message or message digest) can be found.
 * \param signature message LSB of the address in the requester space where the signature can be foundmust be stored\n the signature S=(c,d) must be in the c||d format.
 * \param message_size lenght in bytes of the input
 * \param signature_size lenght in bytes of the signature.
 * \param status pointer to where the verification status must be stored\n if the verification suceed the value HSM_OP_SIGNATURE_VERIFICATION_STATUS_SUCCESS is returned.
 * \param flags bitmap specifying the operation attributes.
 *
 * \return error code
 */
hsm_err_t hsm_fast_signature_verification(struct hsm_hdl_s *fast_signature_ver_hdl, hsm_addr_lsb_t message, hsm_addr_lsb_t signature, uint32_t message_size, uint32_t signature_size, hsm_verification_status_t *status, hsm_op_fast_signature_ver_flags_t flags);
#define HSM_OP_FAST_SIGNATURE_VERIFICATION_INPUT_DIGEST    ((hsm_op_fast_signature_ver_flags_t)(0 << 0))
#define HSM_OP_FAST_SIGNATURE_VERIFICATION_INPUT_MESSAGE   ((hsm_op_fast_signature_ver_flags_t)(1 << 1))

/**
 * Terminate a previously opened fast signature generation service flow
 *
 * \param fast_signature_ver_hdl pointer to handle identifying the fast signature verification service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_fast_signature_verification_service(struct hsm_hdl_s *fast_signature_ver_hdl);


/**
 * Open a random number generation service flow\n
 * User can call this function only after having opened a session. 
 * User must open this service in order to perform rng operations.
 *
 * \param session_hdl pointer to the handle indentifing the current session.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param flags bitmap indicating the service flow properties
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the rng service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s *hsm_open_rng_service(struct hsm_hdl_s * session_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_svc_rng_flags_t flags, hsm_err_t *error_code);

/**
 * Get a freshly generated random number\n
 * User can call this function only after having opened a rng service flow
 *
 * \param rng_hdl pointer to handle identifying the rng service flow.
 * \param output LSB of the address in the requester space where random number must be stored.
 * \param output_size length of the random number in bytes
 *
 * \return error code
 */
hsm_err_t hsm_rng_get_random(uint32_t rng_hdl, hsm_addr_lsb_t output, uint32_t output_size);

/**
 * Terminate a previously opened rng service flow
 *
 * \param rng_hdl pointer to handle identifying the rng service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_rng_service(struct hsm_hdl_s *rng_hdl);


/**
 * Open an hash service flow\n
 * User can call this function only after having opened a session. 
 * User must open this service in order to perform an hash operations.
 *
 * \param session_hdl pointer to the handle indentifing the current session.
 * \param input_address_ext most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the operations handled by the service flow.
 * \param output_address_ext most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the opeartion handled by the service flow.
 * \param flags bitmap indicating the service flow properties
 * \param error_code pointer to where the error code should be written.
 * 
 * \param pointer to the handle indentifing the hash service flow. NULL in case of error.
 * The returned pointer is typed with the struct "hsm_hdl_s". The user doesn't need
 * to know or to access the fields of this struct, but it needs to store and pass the pointer
 * to the subsequent services/operaton calls.
 */
struct hsm_hdl_s * hsm_open_hash_service(struct hsm_hdl_s *session_hdl, hsm_addr_msb_t input_address_ext, hsm_addr_msb_t output_address_ext, hsm_svc_hash_flags_t flags, hsm_err_t *error_code);

/**
 * Perform the hash operation on a given input\n
 * User can call this function only after having opened a hash service flow
 *
 * \param hash_hdl pointer to handle identifying the hash service flow.
 * \param input LSB of the address in the requester space where message to be hashed can be found.
 * \param output LSB of the address in the requester space where the resulting hash must be stored.
 * \param input_size lenght in bytes of the input
 * \param output_size lenght in bytes of the output.
 * \param algo algorithm to be used for the operation
 *
 * \return error code
 */
hsm_err_t hsm_hash_one_go(struct hsm_hdl_s *hash_hdl, hsm_addr_lsb_t input, hsm_addr_lsb_t output, uint32_t input_size, uint32_t output_size, hsm_hash_algo_t algo);
#define HSM_HASH_ALGO_SHA2_224      ((hsm_hash_algo_t)(0x0))
#define HSM_HASH_ALGO_SHA2_256      ((hsm_hash_algo_t)(0x1))
#define HSM_HASH_ALGO_SHA2_384      ((hsm_hash_algo_t)(0x2))

/**
 * Terminate a previously opened hash service flow
 *
 * \param hash_hdl pointer to handle identifying the hash service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_hash_service(struct hsm_hdl_s *hash_hdl);

/** \}*/
#endif
