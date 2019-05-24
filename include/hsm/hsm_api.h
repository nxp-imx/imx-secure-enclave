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
    HSM_KEY_STORE_CONFLICT              = 0xF,      /**< 	A key store with the same attributes already exists. */
    HSM_GENERAL_ERROR                   = 0xFF,     /**<    Error not covered by other codes occured. */
} hsm_err_t;

typedef uint32_t hsm_hdl_t;
typedef uint8_t hsm_svc_key_store_flags_t;
typedef uint8_t hsm_svc_key_management_flags_t;
typedef uint8_t hsm_svc_cipher_flags_t;
typedef uint8_t hsm_svc_signature_generation_flags_t;
typedef uint8_t hsm_svc_signature_verification_flags_t;
typedef uint8_t hsm_svc_fast_signature_verification_flags_t;
typedef uint8_t hsm_svc_rng_flags_t;
typedef uint8_t hsm_svc_hash_flags_t;

typedef uint8_t hsm_op_key_gen_flags_t;
typedef uint8_t hsm_op_manage_key_flags_t;
typedef uint8_t hsm_op_but_key_exp_flags_t;
typedef uint8_t hsm_op_cipher_one_go_algo_t;
typedef uint8_t hsm_op_cipher_one_go_flags_t;
typedef uint8_t hsm_op_generate_sign_flags_t;
typedef uint8_t hsm_op_prepare_signature_flags_t;
typedef uint8_t hsm_op_finalize_sign_flags_t;
typedef uint8_t hsm_op_verify_sign_flags_t;
typedef uint8_t hsm_op_fast_signature_gen_flags_t;
typedef uint8_t hsm_op_fast_signature_ver_flags_t;
typedef uint8_t hsm_op_hash_one_go_flags_t;
typedef uint8_t hsm_op_pub_key_rec_flags_t;
typedef uint8_t hsm_op_pub_key_dec_flags_t;
typedef uint8_t hsm_op_ecies_enc_flags_t;
typedef uint8_t hsm_op_ecies_dec_flags_t;

typedef uint8_t hsm_signature_scheme_id_t;
typedef uint8_t hsm_hash_algo_t;
typedef uint8_t hsm_key_type_t;
typedef uint8_t hsm_key_type_ext_t;
typedef uint16_t hsm_key_info_t;
typedef uint32_t hsm_addr_msb_t;
typedef uint32_t hsm_addr_lsb_t;
typedef uint32_t hsm_verification_status_t;

typedef struct {
    uint8_t session_priority;   //!< not supported in current release, any value accepted. */
    uint8_t operating_mode;     //!< not supported in current release, any value accepted. */
    uint16_t rsv;
} open_session_args_t;

/**
 * Initiate a HSM session.\n
 *
 * \param args pointer to the structure containing the function arugments.

 * \param session_hdl pointer to where the session handle must be written.
 * 
 * \return error_code error code.
 */
hsm_err_t hsm_open_session(open_session_args_t *args, hsm_hdl_t *session_hdl);


/**
 * Terminate a previously opened HSM session
 *
 * \param session_hdl pointer to the handle identifying the session to be closed.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_close_session(hsm_hdl_t session_hdl);


typedef struct {
    uint32_t key_store_identifier;      //!< user defined id identifying the key store.*/
    uint32_t authentication_nonce;      //!< user defined nonce used as authentication proof for accesing the key storage. */
    uint16_t max_updates_number;        //!< maximum number of updates authorized for the storage. Valid only for create operation. */
    hsm_svc_key_store_flags_t flags;    //!< bitmap specifying the services properties. */
    uint8_t rsv;
} open_svc_key_store_args_t;

/**
 * Open a service flow on the specified key store.\n
 * 
 * \param session_hdl pointer to the handle indentifing the current session.
 * \param args pointer to the structure containing the function arugments.

 * \param key_store_hdl pointer to where the key store service flow handle must be written.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_open_key_store_service(hsm_hdl_t session_hdl, open_svc_key_store_args_t *args, hsm_hdl_t *key_store_hdl);

/**
 * It must be specified to create a new key storage
 */
#define HSM_SVC_KEY_STORE_FLAGS_CREATE ((hsm_svc_key_store_flags_t)(1 << 0))
#define HSM_SVC_KEY_STORE_FLAGS_UPDATE ((hsm_svc_key_store_flags_t)(1 << 1))
#define HSM_SVC_KEY_STORE_FLAGS_DELETE ((hsm_svc_key_store_flags_t)(1 << 3))


/**
 * Close a previously opened key store service flow.\n
 * 
 * \param handle indentifing the key store service flow to be closed.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_close_key_store_service(hsm_hdl_t key_store_hdl);


typedef struct {
    hsm_addr_msb_t input_address_ext;       //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;      //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_key_management_flags_t flags;   //!< bitmap specifying the services properties.
    uint8_t rsv[3];
} open_svc_key_management_args_t;

/**
 * Open a key management service flow\n
 * User must open this service in order to perform operation on the key store content: key generate, delete, update
 *
 * \param key_store_hdl handle indentifing the key store service flow.
 * \param args pointer to the structure containing the function arugments.

 * \param key_management_hdl pointer to where the key management service flow handle must be written.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_open_key_management_service(hsm_hdl_t key_store_hdl, open_svc_key_management_args_t *args, hsm_hdl_t *key_management_hdl);


typedef struct {
    uint32_t *key_identifier;       //!< pointer to the identifier of the key to be used for the operation.\n In case of create operation the new key identifier will be stored in this location.
    uint16_t out_size;              //!< length in bytes of the output area, if the size is 0, no key is copied in the output.
    hsm_op_key_gen_flags_t flags;   //!< bitmap specifying the operation properties.
    uint8_t rsv;
    hsm_key_type_t key_type;        //!< indicates which type of key must be generated.
    hsm_key_type_ext_t key_type_ext;
    hsm_key_info_t key_info;        //!< bitmap specifying the properties of the key.
    hsm_addr_lsb_t out_key;         //!< LSB of the address in the requester space where to store the public key
} op_generate_key_args_t;

/**
 * Generate a key or a key pair in the key store. In case of asymetic keys, the public key can optionally be exported. The generated key can be stored in a new or in an existing key slot
 * with the restriction that an existing key can be replaced only by a key of the same type.\n
 * User can call this function only after having opened a key management service flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arugments.
 * 
 * \return error code
 */
hsm_err_t hsm_generate_key(hsm_hdl_t key_management_hdl, op_generate_key_args_t args);

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


typedef struct {
    uint32_t *key_identifier;           //!< pointer to the identifier of the key to be used for the operation.\n In case of create operation the new key identifier will be stored in this location.
    uint16_t input_size;                //!< length in bytes of the input key area. Not checked in case of delete operation.
    hsm_op_manage_key_flags_t flags;    //!< bitmap specifying the operation properties.
    uint16_t rsv;
    hsm_key_type_t key_type;            //!< indicates the type of the key to be managed.
    hsm_key_type_ext_t key_type_ext;
    hsm_key_info_t key_info;            //!< bitmap specifying the properties of the key, it will replace the existing value. Not checked in case of delete operation.
    hsm_addr_lsb_t input_key;           //!< LSB of the address in the requester space where the new key value can be found. Not checked in case of delete operation.
} op_manage_key_args_t;

/**
 * This command is designed to perform operation on an existing key.\n
 * User can call this function only after having opened a key management service flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arugments.
 * 
 * \return error code
 */
hsm_err_t hsm_manage_key(hsm_hdl_t key_management_hdl, op_manage_key_args_t *args);

/**
 * User can replace an existing key only by importing a key with the same type of the original one.
 */
#define HSM_OP_MANAGE_KEY_FLAGS_UPDATE                  ((hsm_op_manage_key_flags_t)(1 << 0))

/**
 * Persistent keys are saved in the non volatile memory.
 */
#define HSM_OP_MANAGE_KEY_FLAGS_CREATE_PERSISTENT       ((hsm_op_manage_key_flags_t)(1 << 1))

/**
 * Transient keys are deleted when the corresponding key store service flow is closed.
 */
#define HSM_OP_MANAGE_KEY_FLAGS_CREATE_TRANSIENT        ((hsm_op_manage_key_flags_t)(1 << 2))
/**
 * delete an existing key
 */
#define HSM_OP_MANAGE_KEY_FLAGS_DELETE                  ((hsm_op_manage_key_flags_t)(1 << 3))
/**
 * The request is completed only when the new key has been written in the NVM. This applicable for persistent key only.
 */
#define HSM_OP_MANAGE_KEY_FLAGS_STRICT_OPERATION        ((hsm_op_manage_key_flags_t)(1 << 7))



typedef struct {
    uint32_t key_identifier;            //!< identifier of the key to be expanded
    hsm_addr_lsb_t add_data_1;          //!< LSB of the address in the requester space where the add_data_1 input can be found
    hsm_addr_lsb_t add_data_2;          //!< LSB of the address in the requester space where the add_data_2 input can be found
    hsm_addr_lsb_t multiply_data;       //!< LSB of the address in the requester space where the multiply_data input can be found
    uint8_t data_1_size;                //!< length in bytes of the add_data_1 input
    uint8_t data_2_size;                //!< length in bytes of the add_data_2 input
    uint8_t multiply_data_size;         //!< length in bytes of the multiply_data input
    hsm_op_but_key_exp_flags_t flags;   //!< bitmap specifying the operation properties
    uint32_t dest_key_identifier;       //!< identifier of the derived key
    hsm_addr_lsb_t out_key;             //!< LSB of the address in the requester space where the public key must be written.
    uint16_t out_size;                  //!< length in bytes of the output area, if the size is 0, no key is copied in the output.
    hsm_key_type_t key_type;                   //!< indicates the type of the key to be managed.
    uint8_t rsv;
} op_butt_key_exp_args_t;

/**
 * This command is designed to perform the butterfly key expansion operation on an ECC private key in case of implicit certificate. Optionally the resulting public key is exported.\n
 * The result of the key expansion function is calculated outside the HSM and passed as input.\n
 * User can call this function only after having opened a key management service flow.\n\n
 * 
 * The following operation is performed:\n
 * out_key = (Key + add_data_1) * multiply_data + add_data_2 (mod n)\n\n
 *
 * Explicit certificates:
 *  add_data_1 = 0,
 *  add_data_2 = f1/f2(k, i, j),
 *  multiply_data = 1\n
 *
 * out_key = Key  + f1/f2(k, i, j) (mod n)\n\n
 *
 * Implicit certificates:
 *  add_data_1 = f1(k, i, j),
 *  add_data_2 = private reconstruction value pij,
 *  multiply_data = hash value used to in the derivation of the pseudonym ECC key\n
 * 
 * out_key = (Key  + f1(k, i, j))*Hash + pij\n\n
 * 
 * \param key_management_hdl handle identifying the key store management service flow.
 * \param args pointer to the structure containing the function arugments.
 * 
 * \return error code
*/
hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl, op_butt_key_exp_args_t *args);


/**
 * Terminate a previously opened key management service flow
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * 
 * \return error code
 */
hsm_err_t hsm_close_key_management_service(hsm_hdl_t key_management_hdl);


typedef struct {
    hsm_addr_msb_t input_address_ext;       //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;      //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_cipher_flags_t flags;           //!< bitmap specifying the services properties.
    uint8_t rsv[3];
} open_svc_cipher_args_t;

/**
 * Open a cipher service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform cipher operations.
 *
 * \param key_store_hdl handle indentifing the key store service flow.
 * \param args pointer to the structure containing the function arugments.
 * \param chiper_hdl pointer to where the cipher service flow handle must be written.
 * 
 * \return error code
 */
hsm_err_t hsm_open_cipher_service(hsm_hdl_t key_store_hdl, open_svc_cipher_args_t *args, hsm_hdl_t *chiper_hdl);

typedef struct {
    uint32_t key_identifier;                    //!< identifier of the key to be used for the operation
    hsm_addr_lsb_t iv;                          //!< LSB of the address in the requester space where the initialization vector can be found
    uint16_t iv_size;                           //!< length in bytes of the initialization vector\n it must be 0 for algorithms not using the initialization vector.\n It must be 12 for AES in CCM mode
    hsm_op_cipher_one_go_algo_t cipher_algo;    //!< algorithm to be used for the operation
    hsm_op_cipher_one_go_flags_t flags;         //!< bitmap specifying the operation attributes
    hsm_addr_lsb_t input;                       //!< LSB of the address in the requester space where the input to be processed can be found\n plaintext for encryption\n ciphertext for decryption (tag is concatenated for CCM)
    hsm_addr_lsb_t output;                      //!< LSB of the address in the requester space where the output must be stored\n ciphertext for encryption (tag is concatenated for CCM)\n plaintext for decryption
    uint32_t input_size;                        //!< length in bytes of the input
    uint32_t output_size;                       //!< length in bytes of the output
} op_cipher_one_go_args_t;

/**
 * Perform ciphering operation\n
 * User can call this function only after having opened a cipher service flow
 *
 * \param chiper_hdl handle identifying the cipher service flow.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_cipher_one_go(hsm_hdl_t chiper_hdl, op_cipher_one_go_args_t* args);
#define HSM_CIPHER_ONE_GO_ALGO_AES_ECB              ((hsm_op_cipher_one_go_algo_t)(0x00))
#define HSM_CIPHER_ONE_GO_ALGO_AES_CBC              ((hsm_op_cipher_one_go_algo_t)(0x01))
/**
 * Perform AES CCM with following constraints:
 * - Adata = 0 - There is no associated data
 * - Tlen = 16 bytes
 */
#define HSM_CIPHER_ONE_GO_ALGO_AES_CCM              ((hsm_op_cipher_one_go_algo_t)(0x04)) //!< AES CCM where Adata = 0, Tlen = 16 bytes
#define HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT             ((hsm_op_cipher_one_go_flags_t)(1 << 0))
#define HSM_CIPHER_ONE_GO_FLAGS_DECRYPT             ((hsm_op_cipher_one_go_flags_t)(1 << 1))

/**
 * Terminate a previously opened cipher service flow
 *
 * \param chiper_hdl pointer to handle identifying the cipher service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_cipher_service(hsm_hdl_t chiper_hdl);

typedef struct {
    hsm_addr_msb_t input_address_ext;       //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;      //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_signature_generation_flags_t flags;        //!< bitmap specifying the services properties.
    uint8_t rsv[3];
} open_svc_sign_gen_args_t;

/**
 * Open a signature generation service flow\n
 * User can call this function only after having opened a key store service flow. 
 * User must open this service in order to perform signature generation operations.
 *
 * \param key_store_hdl handle indentifing the key store service flow.
 * \param args pointer to the structure containing the function arugments.
 * \param signature_gen_hdl pointer to where the signature generation service flow handle must be written.
 * 
 * \return error code
 */
hsm_err_t hsm_open_signature_generation_service(hsm_hdl_t key_store_hdl, open_svc_sign_gen_args_t *args,  hsm_hdl_t *signature_gen_hdl);


/**
 * Terminate a previously opened signature generation service flow
 *
 * \param signature_gen_hdl handle identifying the signature generation service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_signature_generation_service(hsm_hdl_t signature_gen_hdl);

typedef struct {
    uint32_t key_identifier;                //!< identifier of the key to be used for the operation
    hsm_addr_lsb_t message;                 //!< LSB of the address in the requester space where the input (message or message digest) to be processed can be found
    hsm_addr_lsb_t signature;               //!< LSB of the address in the requester space where the signature must be stored. The signature S=(r,s) is always stored in format r||s||Ry where Ry is an additional byte containing the lsb of y. The Ry validity is based on the “compressed point” flag.
    uint32_t message_size;                  //!< length in bytes of the input
    uint16_t signature_size;                //!< length in bytes of the output 
    hsm_signature_scheme_id_t scheme_id;    //!< identifier of the digital signature scheme to be used for the operation
    hsm_op_generate_sign_flags_t flags;     //!< bitmap specifying the operation attributes
} op_generate_sign_args_t;


/**
 * Generate a digital signature according to the signature scheme\n
 * User can call this function only after having opened a signature generation service flow
 * The signature S=(r,s) is always stored in format r||s||Ry where Ry is an additional byte containing the lsb of y. The Ry validity is based on the “compressed point” flag.
 *
 * \param signature_gen_hdl handle identifying the signature generation service flow
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_generate_signature(hsm_hdl_t signature_gen_hdl, op_generate_sign_args_t *args);

#define HSM_OP_GENERATE_SIGN_INPUT_DIGEST           ((hsm_op_generate_sign_flags_t)(1 << 0))
#define HSM_OP_GENERATE_SIGN_INPUT_MESSAGE          ((hsm_op_generate_sign_flags_t)(1 << 1))
#define HSM_OP_GENERATE_SIGN_COMPRESSED_POINT       ((hsm_op_generate_sign_flags_t)(1 << 2))

#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P224_SHA_256            ((hsm_signature_scheme_id_t)0x01)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256            ((hsm_signature_scheme_id_t)0x02)
#define HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384            ((hsm_signature_scheme_id_t)0x03)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_224_SHA_256     ((hsm_signature_scheme_id_t)0x12)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_256_SHA_256     ((hsm_signature_scheme_id_t)0x13)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_R1_384_SHA_384     ((hsm_signature_scheme_id_t)0x15)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_224_SHA_256     ((hsm_signature_scheme_id_t)0x22)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_256_SHA_256     ((hsm_signature_scheme_id_t)0x23)
#define HSM_SIGNATURE_SCHEME_ECDSA_BRAINPOOL_T1_384_SHA_384     ((hsm_signature_scheme_id_t)0x25)


typedef struct {
    hsm_signature_scheme_id_t scheme_id;        //!< identifier of the digital signature scheme to be used for the operation
    hsm_op_prepare_signature_flags_t flags;     //!< bitmap specifying the operation attributes
    uint16_t rsv;
} op_prepare_sign_args_t;


/**
 * Prepare the creation of a signature by pre-calculating the operations having not dependencies on the input message.
 * The pre-calculated value will be stored internally and used to the next call of hsm_generate_signature_finalize \n
 * User can call this function only after having opened a signature generation service flow
 * The signature S=(r,s) is stored in format r||s||Ry where Ry is an additional byte containing the lsb of y, the validity of the Ry parameter is based on the “compressed point” flag.
 *
 * \param signature_gen_hdl handle identifying the signature generation service flow
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl, op_prepare_sign_args_t *args);

typedef struct {
    uint32_t key_identifier;                    //!< identifier of the key to be used for the operation
    hsm_addr_lsb_t message;                     //!< LSB of the address in the requester space where the input (message or message digest) to be processed can be found
    hsm_addr_lsb_t signature;                   //!< LSB of the address in the requester space where the signature must be stored. The signature S=(r,s) is stored in format r||s||Ry where Ry is an additional byte containing the lsb of y, the validity of the Ry parameter is based on the “compressed point” flag.
    uint32_t message_size;                      //!< length in bytes of the input
    uint16_t signature_size;                    //!< length in bytes of the output
    hsm_op_finalize_sign_flags_t flags;         //!< bitmap specifying the operation attributes
    uint8_t rsv;
} op_finalize_sign_args_t;


/**
 * Finalize the computation of a digital signature\n
 * User can call this function only after having called the hsm_prepare_signature API.
 *
 * \param signature_gen_hdl handle identifying the signature generation service flow
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_finalize_signature(hsm_hdl_t signature_gen_hdl, op_finalize_sign_args_t *args);

#define HSM_OP_FINALIZE_SIGN_INPUT_DIGEST           ((hsm_op_finalize_sign_flags_t)(1 << 0))
#define HSM_OP_FINALIZE_SIGN_INPUT_MESSAGE          ((hsm_op_finalize_sign_flags_t)(1 << 1))
#define HSM_OP_FINALIZE_SIGN_COMPRESSED_POINT       ((hsm_op_finalize_sign_flags_t)(1 << 2))


typedef struct {
    hsm_addr_msb_t input_address_ext;               //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;              //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_signature_verification_flags_t flags;   //!< bitmap indicating the service flow properties
    uint8_t rsv[3];
} open_svc_sign_ver_args_t;
/**
 * User must open this service in order to perform signature verification operations.\n
 * User can call this function only after having opened a session.
 *
 * \param session_hdl handle indentifing the current session.
 * \param args pointer to the structure containing the function arugments.
 * \param signature_ver_hdl pointer to where the signature verification service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_signature_verification_service(hsm_hdl_t session_hdl, open_svc_sign_ver_args_t *args, hsm_hdl_t *signature_ver_hdl);

typedef struct {
    hsm_addr_lsb_t key;                     //!< LSB of the address in the requester space where the public key to be used for the verification can be found.
    hsm_addr_lsb_t message;                 //!< LSB of the address in the requester space where the input (message or message digest) to be processed can be found
    hsm_addr_lsb_t signature;               //!< LSB of the address in the requester space where the signature can be found. The signature S=(r,s) is expected to be in format r||s||Ry where Ry is an additional byte containing the lsb of y, the validity of the Ry parameter is based on the “compressed point” flag.
    uint16_t key_size;                      //!< length in bytes of the input key
    uint16_t signature_size;                //!< length in bytes of the output - it must contains one additional byte where to store the Ry.
    uint32_t message_size;                  //!< length in bytes of the input message
    hsm_signature_scheme_id_t scheme_id;    //!< identifier of the digital signature scheme to be used for the operation
    hsm_op_verify_sign_flags_t flags;       //!< bitmap specifying the operation attributes
    uint16_t rsv;
} op_verify_sign_args_t;

/**
 * Verify a digital signature according to the signature scheme\n
 * User can call this function only after having opened a signature verification service flow
 * The signature S=(r,s) is expected to be in format r||s||Ry where Ry is an additional byte containing the lsb of y, the validity of the Ry parameters is based on the “compressed point” flag.
 * Only not-compressed keys (x,y) can be used by this command. Compressed keys can be decompressed by using the dedicated API.
 * 
 * \param signature_ver_hdl handle identifying the signature verification service flow.
 * \param args pointer to the structure containing the function arugments.
 * \param status pointer to where the verification status must be stored\n if the verification suceed the value HSM_VERIFICATION_STATUS_SUCCESS is returned.
 *
 * \return error code
 */
hsm_err_t hsm_verify_signature(hsm_hdl_t signature_ver_hdl, op_verify_sign_args_t *args, hsm_verification_status_t *status);

#define HSM_OP_VERIFY_SIGN_INPUT_DIGEST             ((hsm_op_verify_sign_flags_t)(1 << 0))
#define HSM_OP_VERIFY_SIGN_INPUT_MESSAGE            ((hsm_op_verify_sign_flags_t)(1 << 1))
#define HSM_OP_VERIFY_SIGN_COMPRESSED_POINT         ((hsm_op_verify_sign_flags_t)(1 << 2))
/**
 * when set the value passed by the key argument is considered as the internal reference of a key imported throught the hsm__import_pub_key API.
 */
#define HSM_OP_VERIFY_SIGN_KEY_INTERNAL             ((hsm_op_verify_sign_flags_t)(1 << 4))


#define HSM_VERIFICATION_STATUS_SUCCESS   ((hsm_verification_status_t)(0x5A3CC3A5))


typedef struct {
    hsm_addr_lsb_t key;                     //!< LSB of the address in the requester space where the public key to be imported can be found.
    uint16_t key_size;                      //!< length in bytes of the input key
    hsm_key_type_t key_type;                //!< indicates the type of the key to be imported.
    hsm_op_verify_sign_flags_t flags;       //!< bitmap specifying the operation attributes
} op_import_public_key_args_t;

/**
 * Import a public key to be used for several verification operations\n
 * User can call this function only after having opened a signature verification service flow.
 * Only not-compressed keys (x,y) can be imprted by this command. Compressed keys can be decompressed by using the dedicated API.
 * 
 * \param signature_ver_hdl handle identifying the signature verification service flow.
 * \param args pointer to the structure containing the function arugments.
 * \param int_key pointer to where the key reference to be used as key in the hsm_verify_signature will be stored\n
 *
 * \return error code
 */
hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl, op_import_public_key_args_t *args, hsm_addr_lsb_t *int_key);


/**
 * Terminate a previously opened signature verification service flow
 *
 * \param signature_ver_hdl handle identifying the signature verification service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_signature_verification_service(hsm_hdl_t signature_ver_hdl);


typedef struct {
    hsm_addr_msb_t input_address_ext;               //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;              //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_rng_flags_t flags;                      //!< bitmap indicating the service flow properties
    uint8_t rsv[3];
} open_svc_rng_args_t;

/**
 * Open a random number generation service flow\n
 * User can call this function only after having opened a session. 
 * User must open this service in order to perform rng operations.
 *
 * \param session_hdl handle indentifing the current session.
 * \param args pointer to the structure containing the function arugments.
 * \param rng_hdl pointer to where the rng service flow handle must be written.
 * 
 * \return error code
 */
hsm_err_t hsm_open_rng_service(hsm_hdl_t session_hdl, open_svc_rng_args_t *args, hsm_hdl_t *rng_hdl);


/**
 * Terminate a previously opened rng service flow
 *
 * \param rng_hdl handle identifying the rng service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_rng_service(hsm_hdl_t rng_hdl);


typedef struct {
    hsm_addr_lsb_t output;                  //!< LSB of the address in the requester space where the out random number must be written
    uint32_t random_size;                   //!< length in bytes of the random number to be provided.
} op_get_random_args_t;

/**
 * Get a freshly generated random number\n
 * User can call this function only after having opened a rng service flow
 *
 * \param rng_hdl handle identifying the rng service flow.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args);


typedef struct {
    hsm_addr_msb_t input_address_ext;               //!< most significant 32 bits address to be used by HSM for input memory transactions in the requester address space for the commands handled by the service flow.
    hsm_addr_msb_t output_address_ext;              //!< most significant 32 bits address to be used by HSM for output memory transactions in the requester address space for the commands handled by the service flow.
    hsm_svc_rng_flags_t flags;                      //!< bitmap indicating the service flow properties
    uint8_t rsv[3];
} open_svc_hash_args_t;

/**
 * Open an hash service flow\n
 * User can call this function only after having opened a session. 
 * User must open this service in order to perform an hash operations.
 *
 * \param session_hdl handle indentifing the current session.
 * \param args pointer to the structure containing the function arugments.
 * \param hash_hdl pointer to where the hash service flow handle must be written.
 * 
 * \return error code
 */
hsm_err_t hsm_open_hash_service(hsm_hdl_t session_hdl, open_svc_hash_args_t *args, hsm_hdl_t *hash_hdl);


/**
 * Terminate a previously opened hash service flow
 *
 * \param hash_hdl handle identifying the hash service flow to be closed.
 * 
 * \return error code
 */
hsm_err_t hsm_close_hash_service(hsm_hdl_t hash_hdl);


typedef struct {
    hsm_addr_lsb_t input;               //!< LSB of the address in the requester space where the input payload can be found
    hsm_addr_lsb_t output;              //!< LSB of the address in the requester space where the output digest must be written 
    uint32_t input_size;                //!< length in bytes of the input
    uint32_t output_size;               //!< length in bytes of the output
    hsm_hash_algo_t algo;               //!< hash algorithm to be used for the operation
    hsm_op_hash_one_go_flags_t flags;       //!< flags bitmap specifying the operation attributes.
    uint16_t rsv;
} op_hash_one_go_args_t;

/**
 * Perform the hash operation on a given input\n
 * User can call this function only after having opened a hash service flow
 *
 * \param hash_hdl handle identifying the hash service flow.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_hash_one_go(hsm_hdl_t hash_hdl, op_hash_one_go_args_t *args);
#define HSM_HASH_ALGO_SHA_224      ((hsm_hash_algo_t)(0x0))
#define HSM_HASH_ALGO_SHA_256      ((hsm_hash_algo_t)(0x1))
#define HSM_HASH_ALGO_SHA_384      ((hsm_hash_algo_t)(0x2))

typedef struct {
    hsm_addr_msb_t pub_rec_ext;             //!< MSB of the address in the requester space where the public reconstruction value extracted from the implicit certificate can be found.
    hsm_addr_msb_t pub_rec;                 //!< LSB of the address in the requester space where the public reconstruction value extracted from the implicit certificate can be found.
    hsm_addr_msb_t hash_ext;                //!< MSB of the address in the requester space where the hash value can be found. In the butterfly scheme it corresponds to the hash value calculated over PCA certificate and, concatenated, the implicit certificat.
    hsm_addr_lsb_t hash;                    //!< LSB of the address in the requester space where the hash value can be found. In the butterfly scheme it corresponds to the hash value calculated over PCA certificate and, concatenated, the implicit certificat.
    hsm_addr_msb_t ca_key_ext;              //!< MSB of the address in the requester space where the CA public key can be found.
    hsm_addr_lsb_t ca_key;                  //!< LSB of the address in the requester space where the CA public key can be found.
    hsm_addr_msb_t out_key_ext;             //!< MSB of the address in the requester space where the output resulting key must be written.
    hsm_addr_lsb_t out_key;                 //!< LSB of the address in the requester space where the output resulting key must be written.
    uint16_t pub_rec_size;                  //!< length in bytes of the public reconstruction value
    uint16_t hash_size;                     //!< length in bytes of the input hash
    uint16_t ca_key_size;                   //!< length in bytes of the input  CA public key
    uint16_t out_key_size;                  //!< length in bytes of the output key
    hsm_key_type_t key_type;                //!< indicates the type of the manged keys.
    hsm_op_pub_key_rec_flags_t flags;       //!< flags bitmap specifying the operation attributes.
    uint16_t rsv;
} hsm_op_pub_key_rec_args_t;


/**
 * Reconstruct an ECC public key provided by an implicit certificate\n
 * User can call this function only after having opened a session\n
 * This API implements the followign formula: 
 * out_key = (pub_rec * hash) + ca_key
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_reconstruction(hsm_hdl_t session_hdl,  hsm_op_pub_key_rec_args_t *args);


/**
 * Decompress an ECC public key \n
 * User can call this function only after having opened a session 
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
typedef struct {
    hsm_addr_msb_t pub_key_ext;             //!< MSB of the address in the requester space where the compressed ECC public key can be found. The expected key format is x||lsb_y where lsb_y is 1 byte having value 1 if the least-significant bit of the original (uncompressed) y coordinate is set, and 0 otherwise.
    hsm_addr_lsb_t pub_key;                 //!< MSB of the address in the requester space where the compressed ECC public key can be found. The expected key format is x||lsb_y where lsb_y is 1 byte having value 1 if the least-significant bit of the original (uncompressed) y coordinate is set, and 0 otherwise.
    hsm_addr_msb_t out_key_ext;             //!< MSB of the address in the requester space where the output resulting key must be written.
    hsm_addr_lsb_t out_key;                 //!< LSB of the address in the requester space where the output resulting key must be written.
    hsm_key_type_t key_type;                //!< indicates the type of the manged keys.
    hsm_op_pub_key_dec_flags_t flags;       //!< bitmap specifying the operation attributes.
    uint16_t rsv;
} hsm_op_pub_key_dec_args_t;
hsm_err_t hsm_pub_key_decompression(hsm_hdl_t session_hdl,  hsm_op_pub_key_dec_args_t *args);

typedef struct {
    hsm_addr_msb_t pub_key_ext;             //!< MSB of the address in the requester space where the recipient public key can be found.
    hsm_addr_lsb_t pub_key;                 //!< LSB of the address in the requester space where the recipient public key can be found.
    hsm_addr_msb_t input_ext;               //!< MSB of the address in the requester space where the plaintext can be found.
    hsm_addr_lsb_t input;                   //!< LSB of the address in the requester space where the plaintext can be found.
    hsm_addr_msb_t p1_ext;                  //!< MSB of the address in the requester space where the KDF P1 parameter can be found
    hsm_addr_lsb_t p1;                      //!< LSB of the address in the requester space where the KDF P1 parameter can be found
    hsm_addr_msb_t p2_ext;                  //!< MSB of the address in the requester space where the MAC P2 parameter can be found
    hsm_addr_lsb_t p2;                      //!< LSB of the address in the requester space where the MAC P2 parameter can be found
    uint16_t p1_size;                       //!< length in bytes of the KDF P1 parameter
    uint16_t p2_size;                       //!< length in bytes of the MAC P2 parameter
    uint16_t pub_key_size;                  //!< length in bytes of the recipient public key
    uint16_t mac_size;                      //!< length in bytes of the requested message authentication code
    uint32_t input_size;                    //!< length in bytes of the input plaintext
    hsm_addr_msb_t output_ext;              //!< MSB of the address in the requester space where the output VCT must be written 
    hsm_addr_lsb_t output;                  //!< LSB of the address in the requester space where the output VCT must be written 
    uint32_t out_size;                      //!< length in bytes of the output VCT
    hsm_key_type_t key_type;                //!< indicates the type of the recipient public key
    hsm_op_ecies_enc_flags_t flags;         //!< bitmap specifying the operation attributes.
    uint16_t rsv;
} hsm_op_ecies_enc_args_t;

/**
 * Encrypt data usign ECIES \n
 * User can call this function only after having opened a session 
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_encryption(hsm_hdl_t session_hdl, hsm_op_ecies_enc_args_t *args);


typedef struct {
    uint32_t key_identifier;                //!< identifier of the private key to be used for the operation
    hsm_addr_msb_t input_ext;               //!< MSB of the address in the requester space where the input VCT can be found 
    hsm_addr_lsb_t input;                   //!< LSB of the address in the requester space where the input VCT can be found
    hsm_addr_msb_t p1_ext;                  //!< MSB of the address in the requester space where the KDF P1 parameter can be found
    hsm_addr_lsb_t p1;                      //!< LSB of the address in the requester space where the KDF P1 parameter can be found
    hsm_addr_msb_t p2_ext;                  //!< MSB of the address in the requester space where the MAC P2 parameter can be found
    hsm_addr_lsb_t p2;                      //!< LSB of the address in the requester space where the MAC P2 parameter can be found
    uint16_t p1_size;                       //!< length in bytes of the KDF P1 parameter
    uint16_t p2_size;                       //!< length in bytes of the MAC P2 parameter
    uint32_t input_size;                    //!< length in bytes of the input VCT
    hsm_addr_msb_t output_ext;              //!< MSB of the address in the requester space where the output plaintext must be written
    hsm_addr_lsb_t output;                  //!< LSB of the address in the requester space where the output plaintext must be written 
    uint32_t out_size;                      //!< length in bytes of the ouptu plaintext
    uint16_t mac_size;                      //!< length in bytes of the requested message authentication code
    hsm_key_type_t key_type;                //!< indicates the type of the used key
    hsm_op_ecies_dec_flags_t flags;         //!< bitmap specifying the operation attributes.
} hsm_op_ecies_dec_args_t;

/**
 * Decrypt data usign ECIES \n
 * User can call this function only after having opened a key store service flow 
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arugments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_decryption(hsm_hdl_t key_store_hdl, hsm_op_ecies_dec_args_t *args);


/** \}*/
#endif
