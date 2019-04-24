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

#ifndef SHE_PLATFORM_H
#define SHE_PLATFORM_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "she_api.h"

/**
 * Opens a SHE session
 * Purpose of this function is to setup a communication channel dedicated to SHE
 * using a messaging unit (MU) between the caller of this function and SECO.
 * This session is uniquely identified by a platform handle.
 * The pointer to this handle is returned here and has to be provided by the user
 * on each call to platform dependent functions.
 * The details of the she_platform_hdl structure are not described in this API so
 * it can be custmized for each OS/platform porting.
 *
 * One physical MU can be shared between several sessions but concurrent access
 * should be protected. Seco can only process one command at a time. Once a command
 * has been sent to SECO no other command should be sent on the physical MU (even by
 * other sessions sharing same physical MU) until the response has been received.
 * (but a response to a command from Seco should not be blocked - e.g. in storage case)
 *
 * The mapping between physical MUs and sessions is considered as platform dependent.
 * So no assumption are made about this by the caller.
 *
 * \return pointer to the SHE session handle.
 */
struct she_platform_hdl *she_platform_open_she_session(void);

/**
 * Opens a storage session
 * Purpose of this function is to setup a communication channel dedicated to storage
 * using a messaging unit (MU) between the caller of this function and SECO.
 * (see description of she_platform_open_she_session for more details about the session).
 *
 * Note that during a storage session Seco will send commands to the storage manager in an
 * asynchronous way and even when a command has been sent to SECO by another session.
 * The response to these commands should be sent to Seco even in another command is being
 * be processed.
 *
 * \return pointer to the storage session handle.
 */
struct she_platform_hdl *she_platform_open_storage_session(void);

/**
 * Close a previously opened session.
 *
 *\param phdl pointer to the session handle to be closed.
 */
void she_platform_close_session(struct she_platform_hdl *phdl);

/**
 * Send a message to Seco over a messaging unit.
 *
 * A message is made of 1 or more 32bits words.
 * The 1st word is an header containing the length of the message and its type (command or response)
 * The following protocol has to be respected when sending a message to SECO:
 * - write the header in TR0 of the MU
 * - send and interrupt to SECO thanks to GI0 bit in CR register of the MU
 * - Write other words of the message. word at index n in the message has to be written in TR[n%4] register of the MU.
 * Write to a TRx register has to be performed only when the corresponding TEx bit in SR register is equal to 1 (indicating that the TRx register is empty).
 *
 * Note that a physical MU can be shared between several sessions.
 * Concurent access to the physical MU should be prevented (SECO process commands one by one).
 * So this API should block until the physical MU is available for this session.
 *
 * \param phdl pointer to handle identifying the session to be used to carry the message.
 * \param message pointer to the message itself. It has to be aligned on 32bits.
 * \param size size in bytes of the message. It has to be multiple of 4 bytes.
 *
 * \return length in bytes written to the MU or negative value in case of error
 */
int32_t she_platform_send_mu_message(struct she_platform_hdl *phdl, uint32_t *message, uint32_t size);

/**
 * Read a message from Seco over a messaging unit.
 *
 * This API is blocking until a message is sent by SECO
 *
 * A message is made of 1 or more 32bits words.
 * The 1st word is an header containing the length of the message and its type (command or response)
 *
 * When receiving MU's GI0 interrupt from SECO this API should:
 * - read the header in RR0 of the MU and extract its length
 * - send and interrupt to SECO thanks to GI0 bit in CR register of the MU
 * - Write other words of the message. word at index n in the message has to be written in TR[n%4] register of the MU.
 * Write to a TRx register has to be performed only when the corresponding TEx bit in SR register is equal to 1 (indicating that the TRx register is empty).
 *
 * Typically for SHE this API will be called right after having sent a command to SECO in
 * order to get the response. And for Storage an infinite loop will wait on this blocking
 * API for a command from SECO.
 *
 * \param phdl pointer to handle identifying the session to be used to carry the message.
 * \param message pointer to the message itself. It has to be aligned on 32bits.
 * \param size size in bytes of the message. It has to be multiple of 4 bytes.
 *
 * \return length in bytes read from the MU or negative value in case of error
 */
int32_t she_platform_read_mu_message(struct she_platform_hdl *phdl, uint32_t *message, uint32_t size);

/**
 * Configure the use of shared buffer in secure memory
 *
 * Seco allocates a shared buffer in secure memory to exchange data. Offset in secure memory and size are
 * provided by Seco in a message decoded by caller. These information are provided to the platform dependent
 * layer through this API to avoid parsing incoming messages here.
 *
 * \param phdl pointer to the session handle associated to this shared buffer.
 * \param shared_buf_offset offset of the shared buffer in secure memory.
 * \param size size in bytes of the allocated shared buffer.
 *
 * \return 0 in case of success. Any other value means error.
 */
int32_t she_platform_configure_shared_buf(struct she_platform_hdl *phdl, uint32_t shared_buf_off, uint32_t size);

/**
 * Setup data buffer for command processing
 *
 * The command messages sent to Seco do not carry the data to be processed. It uses pointers instead.
 * This API is used to make sure the data are available to Seco when it receive a command and also that
 * the result can be accessed by the caller when seco sends the response.
 * It also provides the address to be inserted into the message to be sent to Seco. It represent either the
 * physical address or the offset in the shared buffer (see options below) yo be used by Seco.
 *
 * Several options are available to describe the buffers.
 * DATA_BUF_IS_INPUT: the buffer described here is input to the next command. Otherwise this is an output.
 * DATA_BUF_USE_SEC_MEM: the data should be copied to the shared buffer in secure memory or the output will
 * be stored by Seco in it. It is up to this API to manage how the data are stored in the shared memory.
 * If not set Seco will access directly the pointer provided in this API. In this case this API should take
 * care of cache coherency before Seco access the physical memory.
 * DATA_BUF_SHORT_ADDR: (only possible when using secure memory) returns the offset in secure memory (16bits)
 * instead of full 64bits address (used to reduce the size of some Seco messages).
 *
 * Once this API has been called the buffers should no more be accessed by the caller until the command has
 * been sent to Seco and its response has been received.
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 * \param src pointer to the data if input or to the area where the output should be written.
 * \param size size in bytes of the input data or max size of the output.
 * \param flags data buffer options as described above. Interpreted as a bit-field.
 *
 * \return the address to be inserted in the message to Seco to indicate him this buffer.
 */
uint64_t she_platform_data_buf(struct she_platform_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags);
#define DATA_BUF_IS_INPUT         0x01u
#define DATA_BUF_USE_SEC_MEM      0x02u
#define DATA_BUF_SHORT_ADDR       0x04u
#define SEC_MEM_SHORT_ADDR_MASK   0xFFFFu

/**
 * Create a thread
 *
 * the created thread is associated to a given session handle.
 * 2 simultaneous threads per session handle must not be created.
 * caller must cancel a previous thread before creating a new one. 
 * Used by storage manager to have a background task waiting for commands from Seco.
 *
 * \param phdl pointer to the session handle associated to this thread.
 * \param func pointer to the thread function
 * \param arg argument to be provided to the thread function.
 *
 * \return 0 on success. Any other value means error.
 */
int32_t she_platform_create_thread(struct she_platform_hdl *phdl, void * (*func)(void *arg), void * arg);


/**
 *  Terminate a previously created thread.
 *
 * \param phdl pointer to the session handle aowning the thread to be canceled.
 *
 * \return 0 on success. Any other value means error.
 */
int32_t she_platform_cancel_thread(struct she_platform_hdl *phdl);

/**
 * Compute the CRC of a buffer.
 *
 * Used for basic check of integrity on the storage to avoid sending a corrupted blob to Seco.
 * No strong security requirement here since Seco will perform more robust integrity check on the blob.
 *
 * CRC computation is abstracted here in order to let the possibility to use some platform optimized
 * library instead of re-implementing.
 *
 * \param data pointer to the data on which the CRC must be computed.
 * \size size in bytes of the data
 *
 * \return 32bits value of the CRC.
 */
uint32_t she_platform_crc(uint8_t *data, uint32_t size);

/**
 * Write data to NVM storage
 *
 * \param phdl session handle associated to this storage
 * \param src pointer to the data to be written in NVM
 * \param size size in bytes of the data to be writen in NVM
 *
 * return size in bytes of the data written to NVM or negative value in case of error
 */
int32_t she_platform_storage_write(struct she_platform_hdl *phdl, uint8_t *src, uint32_t size);

/**
 * Read data stored in NVM
 *
 * \param phdl session handle associated to this storage
 * \param src pointer to the data where data should be written
 * \param size maximum number of bytes to be read from NVM
 *
 * return size in bytes of the data read from NVM or negative value in case of error
 */
int32_t she_platform_storage_read(struct she_platform_hdl *phdl, uint8_t *dst, uint32_t size);

/**
 * Force all bytes of a buffer to a given value.
 *
 */
void she_platform_memset(uint8_t *dst, uint8_t val, uint32_t len);

/**
 * Copy the content of a buffer to another location.
 */
void she_platform_memcpy(uint8_t *dst, uint8_t *src, uint32_t len);


uint8_t *she_platform_malloc(uint32_t size);

void she_platform_free(void *ptr);

#endif
