
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
 * \mainpage
 * \defgroup she_api
 * \brief SHE feature API
 * \{
 */

#include <stdint.h>


#ifndef SHE_API_H
#define SHE_API_H

/**
 * \brief Error codes returned by SHE functions.
 */
typedef enum {
	ERC_NO_ERROR,			/**< Success. */
	ERC_SEQUENCE_ERROR,		/**< Invalid sequence of commands. */
	ERC_KEY_NOT_AVAILABLE,	/**< Key is locked. */
	ERC_KEY_INVALID,		/**< Key not allowed for the given operation. */
	ERC_KEY_EMPTY,			/**< Key has not beed initialized yet. */
	ERC_NO_SECURE_BOOT,		/**< Conditions for a secure boot process are not met. */
	ERC_KEY_WRITE_PROTECTED,/**< Memory slot for this key has been write-protected. */
	ERC_KEY_UPDATE_ERROR,	/**< Key update did not succeed due to errors in verification of the messages. */
	ERC_RNG_SEED,			/**< The seed has not been initialized. */
	ERC_NO_DEBUGGING,		/**< Internal debugging is not possible. */
	ERC_BUSY,				/**< A function of SHE is called while another function is still processing. */
	ERC_MEMORY_FAILURE,		/**< Memory error (e.g. flipped bits) */
	ERC_GENERAL_ERROR,		/**< Error not covered by other codes occured. */
} she_err;

/**
 * Initiate a SHE session.
 *
 * \return pointer to the session handle.
 */
struct she_hdl *she_open_session(void);


/**
 * Terminate a previously opened SHE session
 *
 * \param hdl pointer to the session handler to be closed.
 */
void she_close_session(struct she_hdl *hdl);


/**
 *
 * Generates a MAC of a given message with the help of a key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_id identifier of the key to be used for the operation
 * \param message_length lenght in bytes of the input message
 * \param message pointer to the message to be processed
 * \param mac pointer to where the output MAC should be written
 *
 * \return error code
 */
she_err she_cmd_generate_mac(struct she_hdl *hdl, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac);
#define SHE_MAC_SIZE 16 /**< size of the MAC generated is 128bits. */

/**
 *
 * Verifies the MAC of a given message with the help of a key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_id identifier of the key to be used for the operation
 * \param message_length lenght in bytes of the input message
 * \param message pointer to the message to be processed
 * \param mac pointer to the MAC to be compared
 * \param mac_length number of bytes to compare (must be at least 4)
 * \param verification_status pointer to where write the result of the MAC comparison
 *
 * \return error code
 */
she_err she_cmd_verify_mac(struct she_hdl *hdl, uint8_t key_id, uint32_t message_length, uint8_t *message, uint8_t *mac, uint8_t mac_length, uint8_t *verification_status);
#define SHE_MAC_VERIFICATION_SUCCESS 0 /**< indication of mac verification success  */
#define SHE_MAC_VERIFICATION_FAILED  1 /**< indication of mac verification failure */


/**
 * Encrypt a given plaintext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_id identifier of the key to be used for the operation
 * \param data_length lenght in bytes of the plaintext and the cyphertext. Must be a multiple of 128bits.
 * \param iv pointer to the 128bits IV to use for the encryption.
 * \param plaintext pointer to the message to be encrypted.
 * \param ciphertext pointer to ciphertext output area.
 *
 * \return error code
 */
she_err she_cmd_enc_cbc(struct she_hdl *hdl, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *plaintext, uint8_t *ciphertext);
#define SHE_CBC_BLOCK_SIZE_128       16 /**< size in bytes of a 128bits CBC bloc */


/**
 * Decrypt a given ciphertext with the key identified by key_id.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_id identifier of the key to be used for the operation
 * \param data_length lenght in bytes of the plaintext and the cyphertext. Must be a multiple of 128bits.
 * \param iv pointer to the 128bits IV to use for the decryption.
 * \param ciphertext pointer to ciphertext to be decrypted.
 * \param plaintext pointer to the plaintext output area.
 *
 * \return error code
 */
she_err she_cmd_dec_cbc(struct she_hdl *hdl, uint8_t key_id, uint32_t data_length, uint8_t *iv, uint8_t *ciphertext, uint8_t *plaintext);


/**
 * Temporary: Entry point to test NVM storage
 */
she_err she_cmd_load_key(struct she_hdl *hdl);

/** \}*/
#endif
