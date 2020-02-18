
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

#ifndef SHE_API_H
#define SHE_API_H

#include <stdint.h>

/**
 *  @defgroup group100 Error codes
 * Error codes returned by SHE functions.
 *  @{
 */
typedef enum {
    ERC_NO_ERROR            = 0x0,      /**< Success. */
    ERC_SEQUENCE_ERROR      = 0x1,      /**< Invalid sequence of commands. */
    ERC_KEY_NOT_AVAILABLE   = 0x2,      /**< Key is locked. */
    ERC_KEY_INVALID         = 0x3,      /**< Key not allowed for the given operation. */
    ERC_KEY_EMPTY           = 0x4,      /**< Key has not beed initialized yet. */
    ERC_NO_SECURE_BOOT      = 0x5,      /**< Conditions for a secure boot process are not met. */
    ERC_KEY_WRITE_PROTECTED = 0x6,      /**< Memory slot for this key has been write-protected. */
    ERC_KEY_UPDATE_ERROR    = 0x7,      /**< Key update did not succeed due to errors in verification of the messages. */
    ERC_RNG_SEED            = 0x8,      /**< The seed has not been initialized. */
    ERC_NO_DEBUGGING        = 0x9,      /**< Internal debugging is not possible. */
    ERC_BUSY                = 0xA,      /**< A function of SHE is called while another function is still processing. */
    ERC_MEMORY_FAILURE      = 0xB,      /**< Memory error (e.g. flipped bits) */
    ERC_GENERAL_ERROR       = 0xC,      /**< Error not covered by other codes occured. */
} she_err_t;
/** @} end of error code group */


/**
 *  @defgroup group200 SHE keys
 * Identifiers for SHE keys.
 *  @{
 */
#define SHE_KEY_1    (0x04)
#define SHE_KEY_2    (0x05)
#define SHE_KEY_3    (0x06)
#define SHE_KEY_4    (0x07)
#define SHE_KEY_5    (0x08)
#define SHE_KEY_6    (0x09)
#define SHE_KEY_7    (0x0a)
#define SHE_KEY_8    (0x0b)
#define SHE_KEY_9    (0x0c)
#define SHE_KEY_10   (0x0d)
#define SHE_RAM_KEY  (0x0e)
/** @} end of keys group */


/**
 *  @defgroup group300 SHE+ key extension
 *  \ingroup group1
 * Identifiers for the SHE key extension.
 *  @{
 */
#define SHE_KEY_DEFAULT (0x00)      //!< no key extension: keys from 0 to 10 as defined in SHE specification.
#define SHE_KEY_N_EXT_1 (0x10)      //!< keys 11 to 20.
#define SHE_KEY_N_EXT_2 (0x20)      //!< keys 21 to 30.
#define SHE_KEY_N_EXT_3 (0x30)      //!< keys 31 to 40.
#define SHE_KEY_N_EXT_4 (0x40)      //!< keys 41 to 50.
/** @} end of keys ext group */


/**
 *  @defgroup group400 Key store provisioning
 *  @{
 */
/**
 * Creates an empty SHE storage.
 *
 * Must be called at least once on every device before using any other SHE API.\n
 * A signed message must be provided to replace an existing key store. This message is not necessary under some conditions related to chip's lifecycle.
 * 
 * \param key_storage_identifier key store identifier
 * \param authentication_nonce user defined nonce to be used as authentication proof for accesing the key store.
 * \param max_updates_number Not supported: maximum number of updates authorized on this new storage.\n
 * This parameter has the goal to limit the occupation of the monotonic counter used as anti-rollback protection.\n
 * If the maximum number of updates is reached, SHE still allows key store updates but without updating the monotonic counter giving the opportunity for rollback attacks.\n
 * Always forced to the SHE available monotonic counter bits in the current release.
 * \param signed_message pointer to a signed message authorizing the operation (NULL if no signed message to be used)
 * \param msg_len length in bytes of the signed message
 *
 * \return error code
 */
uint32_t she_storage_create(uint32_t key_storage_identifier, uint32_t authentication_nonce, uint16_t max_updates_number, uint8_t *signed_message, uint32_t msg_len);
#define SHE_STORAGE_CREATE_SUCCESS          0u     //!< New storage created succesfully.
#define SHE_STORAGE_CREATE_WARNING          1u     //!< New storage created but its usage is restricted to a limited security state of the chip.
#define SHE_STORAGE_CREATE_UNAUTHORIZED     2u     //!< Creation of the storage is not authorized.
#define SHE_STORAGE_CREATE_FAIL             3u     //!< Creation of the storage failed for any other reason.
#define SHE_STORAGE_NUMBER_UPDATES_DEFAULT  300u   //!< default number of maximum number of updated for SHE storage.
/** @} end of provisioning group */


/**
 *  @defgroup group500 Session
 *  @{
 */
/**
 * Initiate a SHE session.
 * The returned session handle pointer is typed with the struct "she_hdl_s".\n
 * The user doesn't need to know or to access the fields of this struct.\n
 * It only needs to store this pointer and pass it to every calls to other APIs within the same SHE session.
 *
 * Note that asynchronous API is currently not supported. async_cb and priv pointers must be set to NULL.
 *
 * \param key_storage_identifier key store identifier
 * \param authentication_nonce user defined nonce used as authentication proof for accesing the key store..
 * \param async_cb user callback to be called on completion of a SHE operation
 * \param priv user pointer to be passed to the callback
 *
 * \return pointer to the session handle.
 */
struct she_hdl_s *she_open_session(uint32_t key_storage_identifier, uint32_t authentication_nonce, void (*async_cb)(void *priv, she_err_t err), void *priv);

/**
 * Terminate a previously opened SHE session
 *
 * \param hdl pointer to the session handler to be closed.
 */
void she_close_session(struct she_hdl_s *hdl);
/** @} end of session group */

/**
 *  @defgroup group600 SHE commands
 *  @{
 */
/**
 *  @defgroup group601 CMD_GENERATE_MAC
 *  \ingroup group600
 *  @{
 */
/**
 *
 * Generates a MAC of a given message with the help of a key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param message_length lenght in bytes of the input message. The message is padded to be a multiple of 128 bits by SHE.
 * \param message pointer to the message to be processed
 * \param mac pointer to where the output MAC should be written (128bits should be allocated there)
 *
 * \return error code
 */
she_err_t she_cmd_generate_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac);
#define SHE_MAC_SIZE 16u //!< size of the MAC generated is 128bits.
/** @} end of CMD_GENERATE_MAC group */

/**
 *  @defgroup group602 CMD_VERIFY_MAC
 *  \ingroup group600
 *  @{
 */
/**
 *
 * Verifies the MAC of a given message with the help of a key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param message_length lenght in bytes of the input message.  The message is padded to be a multiple of 128 bits by SHE.
 * \param message pointer to the message to be processed
 * \param mac pointer to the MAC to be compared (implicitely 128 bits)
 * \param mac_length number of bytes to compare (must be at least 4)
 * \param verification_status pointer to where write the result of the MAC comparison
 *
 * \return error code
 */
she_err_t she_cmd_verify_mac(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint16_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status);
#define SHE_MAC_VERIFICATION_SUCCESS 0u //!< indication of mac verification success
#define SHE_MAC_VERIFICATION_FAILED  1u //!< indication of mac verification failure
/** @} end of CMD_VERIFY_MAC group */


/**
 *  @defgroup group603 CMD_ENC_CBC
 *  \ingroup group600
 *  @{
 */
/**
 * CBC encryption of a given plaintext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param data_length lenght in bytes of the plaintext and the cyphertext. Must be a multiple of 128bits.
 * \param iv pointer to the 128bits IV to use for the encryption.
 * \param plaintext pointer to the message to be encrypted.
 * \param ciphertext pointer to ciphertext output area.
 *
 * \return error code
 */
she_err_t she_cmd_enc_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext);
#define SHE_AES_BLOCK_SIZE_128       16u //!< size in bytes of a 128bits CBC block
/** @} end of CMD_ENC_CBC group */

/**
 *  @defgroup group604 CMD_DEC_CBC
 *  \ingroup group600
 *  @{
 */
/**
 * CBC decryption of a given ciphertext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param data_length lenght in bytes of the plaintext and the cyphertext. Must be a multiple of 128bits.
 * \param iv pointer to the 128bits IV to use for the decryption.
 * \param ciphertext pointer to ciphertext to be decrypted.
 * \param plaintext pointer to the plaintext output area.
 *
 * \return error code
 */
she_err_t she_cmd_dec_cbc(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext);
/** @} end of CMD_DEC_CBC group */


/**
 *  @defgroup group605 CMD_ENC_ECB
 *  \ingroup group600
 *  @{
 */
/**
 * ECB encryption of a given plaintext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param plaintext pointer to the 128bits message to be encrypted.
 * \param ciphertext pointer to ciphertext output area (128bits).
 *
 * \return error code
 */
she_err_t she_cmd_enc_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext);
/** @} end of CMD_ENC_ECB group */

/**
 *  @defgroup group606 CMD_DEC_ECB
 *  \ingroup group600
 *  @{
 */
/**
 * ECB decryption of a given ciphertext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param ciphertext pointer to 128bits ciphertext to be decrypted.
 * \param plaintext pointer to the plaintext output area (128bits).
 *
 * \return error code
 */
she_err_t she_cmd_dec_ecb(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *ciphertext, uint8_t *plaintext);
/** @} end of CMD_DEC_ECB group */


/**
 *  @defgroup group607 CMD_LOAD_KEY
 *  \ingroup group600
 *  @{
 */
/**
 * Update an internal key of SHE with the protocol specified by SHE. The request is completed only when the new key has been written in the NVM. The monotonic counter is incremented for aach successful update.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param m1 pointer to M1 message - 128 bits
 * \param m2 pointer to M2 message - 256 bits
 * \param m3 pointer to M3 message - 128 bits
 * \param m4 pointer to the output address for M4 message - 256 bits
 * \param m5 pointer to the output address for M5 message - 128 bits
 *
 * \return error code
 */
she_err_t she_cmd_load_key(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5);
typedef uint8_t she_cmd_load_key_ext_flags_t;
/**
 * This is an extension of the she_cmd_load_key API.
 * The functionality of the she_cmd_load_key API is extended by adding a flag argument.
 *  - STRICT OPERATION flag: User can use this flag to perform multiple updates before writing the key store into the NVM and incrementing the monotonic counter. The updates to the key store must be considered as effective only after an operation specifying the flag "STRICT OPERATION" is aknowledged by SHE.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_ext identifier of the key extension to be used for the operation
 * \param key_id identifier of the key to be used for the operation
 * \param m1 pointer to M1 message - 128 bits
 * \param m2 pointer to M2 message - 256 bits
 * \param m3 pointer to M3 message - 128 bits
 * \param m4 pointer to the output address for M4 message - 256 bits
 * \param m5 pointer to the output address for M5 message - 128 bits
 * \param flags bitmap specifying the operation properties.
 *
 * \return error code
 */
she_err_t she_cmd_load_key_ext(struct she_hdl_s *hdl, uint8_t key_ext, uint8_t key_id, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5, she_cmd_load_key_ext_flags_t flags);
#define SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION        ((she_cmd_load_key_ext_flags_t)(1 << 7))  //!< The request is completed only when the key store is written in the NVM and the monotonic counter is incremented.
#define SHE_KEY_SIZE 16u //!< SHE keys are 128 bits (16 bytes) long.
/** @} end of CMD_LOAD_KEY group */

/**
 *  @defgroup group608 CMD_LOAD_PLAIN_KEY
 *  \ingroup group600
 *  @{
 */
/**
 * Load a key as plaintext to the RAM_KEY slot without encryption and verification.
 *
 * \param hdl pointer to the SHE session handler
 * \param key pointer to the plaintext key to be loaded - 128bits
 *
 * \return error code
 */
she_err_t she_cmd_load_plain_key(struct she_hdl_s *hdl, uint8_t *key);
/** @} end of CMD_LOAD_PLAIN_KEY group */


/**
 *  @defgroup group609 CMD_EXPORT_RAM_KEY
 *  \ingroup group600
 *  @{
 */
/**
 * exports the RAM_KEY into a format protected by SECRET_KEY.
 *
 * \param hdl pointer to the SHE session handler
 * \param m1 pointer to the output address for M1 message - 128 bits
 * \param m2 pointer to the output address for M2 message - 256 bits
 * \param m3 pointer to the output address for M3 message - 128 bits
 * \param m4 pointer to the output address for M4 message - 256 bits
 * \param m5 pointer to the output address for M5 message - 128 bits
 *
 * \return error code
 */
she_err_t she_cmd_export_ram_key(struct she_hdl_s *hdl, uint8_t *m1, uint8_t *m2, uint8_t *m3, uint8_t *m4, uint8_t *m5);
/** @} end of CMD_EXPORT_RAM_KEY group */


/**
 *  @defgroup group610 CMD_INIT_RNG
 *  \ingroup group600
 *  @{
 */
/**
 * initializes the seed and derives a key for the PRNG.
 * The function must be called before CMD_RND after every power cycle/reset.
 *
 * \param hdl pointer to the SHE session handler
 *
 * \return error code
 */
she_err_t she_cmd_init_rng(struct she_hdl_s *hdl);
/** @} end of CMD_INIT_RNG group */

/**
 *  @defgroup group611 CMD_EXTEND_SEED
 *  \ingroup group600
 *  @{
 */
/**
 * extends the seed of the PRNG by compressing the former seed value and the
 * supplied entropy into a new seed which will be used to generate the following random numbers.
 * The random number generator has to be initialized by CMD_INIT_RNG before the seed can
 * be extended.
 *
 * \param hdl pointer to the SHE session handler
 * \param entropy pointer to the entropy vector (128bits) to use for the operation
 *
 * \return error code
 */
she_err_t she_cmd_extend_seed(struct she_hdl_s *hdl, uint8_t *entropy);
#define SHE_ENTROPY_SIZE 16u
/** @} end of CMD_EXTEND_SEED group */

/**
 *  @defgroup group612 CMD_RND
 *  \ingroup group600
 *  @{
 */
/**
 * returns a vector of 128 random bits.
 * The random number generator has to be initialized by CMD_INIT_RNG before random
 * numbers can be supplied.
 *
 * \param hdl pointer to the SHE session handler
 * \param rnd pointer to the output address for the generated 128bits random vector
 *
 * \return error code
 */
she_err_t she_cmd_rnd(struct she_hdl_s *hdl, uint8_t *rnd);
#define SHE_RND_SIZE 16u
/** @} end of CMD_RND group */


/**
 *  @defgroup group613 CMD_GET_STATUS
 *  \ingroup group600
 *  @{
 */
/**
 * returns the content of the status register
 *
 * \param hdl pointer to the SHE session handler
 * \param sreg pointer to the output address for status register(8bits)
 *
 * \return error code
 */
she_err_t she_cmd_get_status(struct she_hdl_s *hdl, uint8_t *sreg);
/** @} end of CMD_GET_STATUS group */

/**
 *  @defgroup group614 CMD_GET_ID
 *  \ingroup group600
 *  @{
 */
/**
 * returns the identity (UID) and the value of the status register protected by a
 * MAC over a challenge and the data.
 *
 * \param hdl pointer to the SHE session handler
 * \param challenge pointer to the challenge vector (128bits)
 * \param id pointer to the output address for the identity (120bits)
 * \param sreg pointer to the output address for status register(8bits)
 * \param mac pointer to the output address for the computed MAC (128bits)
 *
 * \return error code
 */
she_err_t she_cmd_get_id(struct she_hdl_s *hdl, uint8_t *challenge, uint8_t *id, uint8_t *sreg, uint8_t *mac);
#define SHE_CHALLENGE_SIZE 16u /* 128 bits */
#define SHE_ID_SIZE 15u /* 120 bits */
/** @} end of CMD_GET_ID group */


/**
 *  @defgroup group615 CMD_CANCEL
 *  \ingroup group600
 *  @{
 */
/**
 * interrupt any given function and discard all calculations and results.
 *
 * \param hdl pointer to the SHE session handler
 *
 * \return error code
 */
she_err_t she_cmd_cancel(struct she_hdl_s *hdl);
/** @} end of CANCEL group */

/**
 *  @defgroup group616 last rating code
 *  \ingroup group600
 *  @{
 */
/**
 * Report rating code from last command
 * 
 * SHE API defines standard errors that should be returned by API calls.
 * Error code reported by SECO are "translated" to these SHE error codes.
 * This API allow user to get the error code reported by SECO for the last
 * command before its translation to SHE error codes. This shoudl be used
 * for debug purpose only.
 *
 * \param hdl pointer to the SHE session handler
 *
 * \return rating code reported by last command
 */
uint32_t she_get_last_rating_code(struct she_hdl_s *hdl);
/** @} end of last rating code group */

/** @} end of Commands group */

/**
 *  @defgroup group700 Get info
 *  Get miscellaneous information. This function return, among others, all the information needed to build a valid signed message.
 *  @{
 */
/**
 *
 * \param hdl pointer to the SHE session handler
 * \param user_sab_id pointer to the output address for the user identity (32bits)
 * \param chip_unique_id pointer to the output address for the chip unique identifier (64bits)
 * \param chip_monotonic_counter pointer to the output address for the chip monotonic counter value (16bits)
 * \param chip_life_cycle pointer to the output address for the chip current life cycle (16bits)
 * \param she_version pointer to the output address for the SHE module version (32bits)
 *
 * \return error code
 */
she_err_t she_get_info(struct she_hdl_s *hdl, uint32_t *user_sab_id, uint8_t *chip_unique_id, uint16_t *chip_monotonic_counter, uint16_t *chip_life_cycle, uint32_t *she_version);
/** @} end of get info group */

#endif
