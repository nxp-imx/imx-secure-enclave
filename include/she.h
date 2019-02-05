
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
 * \file she.h
 * \brief API for SHE feature on i.MX8
 */
#include <stdint.h>

/**
 * \brief Error codes returned by SHE functions.
 */
typedef enum {
	ERC_NO_ERROR,			/**< No error */
	ERC_SEQUENCE_ERROR,		/**< invalid sequence of commands */
	ERC_KEY_NOT_AVAILABLE,	/**< */
	ERC_KEY_INVALID,		/**< */
	ERC_KEY_EMPTY,			/**< */
	ERC_NO_SECURE_BOOT,		/**< */
	ERC_KEY_WRITE_PROTECTED,/**< */
	ERC_KEY_UPDATE_ERROR,	/**< */
	ERC_RNG_SEED,			/**< */
	ERC_NO_DEBUGGING,		/**< */
	ERC_BUSY,				/**< */
	ERC_MEMORY_FAILURE,		/**< */
	ERC_GENERAL_ERROR,		/**< */
} she_err;

typedef void she_hdl;

/**
 * Initiate a SHE session.
 *
 * \return pointer to the session handle.
 */
she_hdl *she_open_session(void);


/**
 * Terminate a previously opened SHE session
 *
 * \param hdl pointer to the session handler to be closed.
 */
void she_close_session(she_hdl *hdl);


/**
 * The function encrypts a given PLAINTEXT with the key identified by KEY_ID
 * and returns the CIPHERTEXT. Both input and output are 128 bits long.
 *
 * \param hdl pointer to the SHE session handler
 * \param key_id identifier of the key to be used for the operation
 * \param plaintext pointer to the plaintext to be encrypted. Length of the plaintext is assumed to be 128 bits
 * \param ciphertext pointer to the area where the output of the encryption should be stored. User must ensure that the available size is at least 128 bits.
 */
she_err she_cmd_enc_cbc(she_hdl *hdl, uint8_t key_id, uint8_t *plaintext, uint8_t *ciphertext);




/*

CMD_ENC_ECB
CMD_ENC_CBC
CMD DEC_ECV
CMD_DEC_CBC
CMG_GENERATE_MAC
CMD_VERIFY_MAC
CMD_LOAD_KEY
CMD_LOAD_PLAIN_KEY
CMD_EXPORT_RAM_KEY
CMD_INIT_RNG
CMD_EXTEND_SEED
CMD_RND
CMD_GET_STATUS
CMD_GET_ID
CMD_DEBUG
*/