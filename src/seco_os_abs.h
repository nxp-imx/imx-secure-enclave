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


#ifndef SECO_OS_ABS_H
#define SECO_OS_ABS_H

/* standard types definitions. */
#if defined(__KERNEL__)
/* Linux kernel */
#include <linux/types.h>
#elif defined(__linux__)
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#endif

/**
 *  @defgroup group800 Abstraction layer
 * seco_libs code itself is independent from any OS or platform.
 * This abstraction layer defines the functions that should be implemented on
 * a specific OS or platform when porting seco_libs on it.
 *  @{
 */

/**
 * Opens a MU channel
 * Purpose of this function is to setup a communication channel using a messaging unit (MU)
 * between the caller of this function and SECO.
 * This session is uniquely identified by a platform handle.
 * The pointer to this handle is returned here and has to be provided by the user
 * on each call to platform dependent functions.
 * The details of the seco_os_abs_hdl structure are not described in this API so
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
 * \param type constant indicating for which purpose will be used this channel (see defines below)
 * \param mu_params pointer where the MU params for this channel should be written. It is up to this
 *                  abstraction layer to provide a mapping between channel types and associated MU
 *                  params. Caller need to know these information to fill some SECO messages.
 *
 * \return pointer to the MU channel handle.
 */

struct seco_mu_params {
    uint8_t mu_id;				/**< index of the MU as per SECO point of view. */
    uint8_t interrupt_idx;		/**< Interrupt number of the MU used to indicate data availability. */
    uint8_t tz;					/**< indicate if current partition has TZ enabled. */
    uint8_t did;				/**< DID of the calling partition. */
    uint8_t priority;			/**< SECO priority associated to this MU. */
    uint8_t operating_mode;		/**< SECO operating mode associated to this MU. */
};

#define MU_CHANNEL_UNDEF     (0x00u)
#define MU_CHANNEL_SHE       (0x01u)
#define MU_CHANNEL_SHE_NVM   (0x02u)
#define MU_CHANNEL_HSM       (0x03u)
#define MU_CHANNEL_HSM_NVM   (0x04u)

struct seco_os_abs_hdl *seco_os_abs_open_mu_channel(uint32_t type, struct seco_mu_params *mu_params);

/**
 * Close a previously opened session.
 *
 *\param phdl pointer to the session handle to be closed.
 */
void seco_os_abs_close_session(struct seco_os_abs_hdl *phdl);


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
int32_t seco_os_abs_send_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size);

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
int32_t seco_os_abs_read_mu_message(struct seco_os_abs_hdl *phdl, uint32_t *message, uint32_t size);

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
int32_t seco_os_abs_configure_shared_buf(struct seco_os_abs_hdl *phdl, uint32_t shared_buf_off, uint32_t size);

/**
 * Setup data buffer for command processing
 *
 * The command messages sent to Seco most of the time do not carry the data to be processed. It uses pointers instead.
 * This API is used to make sure the data are available to Seco when it receive a command and also that
 * the result can be accessed by the caller after seco sent the response by either:
 *  - copy to/from dedicated shared buffer in secure memory
 *  - or perform appropriate cache management when using buffers in DDR
 * It also provides the address to be inserted into the message to be sent to Seco: either the
 * physical address or the offset in the shared buffer (see options below) yo be used by Seco.
 *
 * Several options are available to describe the buffers.
 * DATA_BUF_IS_INPUT: the buffer described here is input to the next command. Otherwise this is an output.
 * DATA_BUF_USE_SEC_MEM: the data should be copied to the shared buffer in secure memory or the output will
 * be stored by Seco in it. It is expected that the buffers will be allocated in a contiguous manner in this
 * shared memory since some optimizations depend on this (fast MAC).
 * If not set any other memory can be used (e.g. DDR). In this case this API should take care of cache coherency
 * and access rights before Seco tries access the physical memory.
 * when using secure mem.
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
uint64_t seco_os_abs_data_buf(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint32_t flags);
#define DATA_BUF_IS_INPUT         0x01u
#define DATA_BUF_USE_SEC_MEM      0x02u
#define DATA_BUF_SHORT_ADDR       0x04u
#define SEC_MEM_SHORT_ADDR_MASK   0xFFFFu

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
uint32_t seco_os_abs_crc(uint8_t *data, uint32_t size);

/**
 * Force all bytes of a buffer to a given value.
 *
 * \param dst address of the buffer to be overwriten
 * \param val value to be written in every bytes of the buffer
 * \param len number of bytes to be written
 *
 */
void seco_os_abs_memset(uint8_t *dst, uint8_t val, uint32_t len);

/**
 * Copy the content of a buffer to another location.
 *
 * \param dst pointer to the destination buffer where data should be copied
 * \param src pointer to the source buffer from where data should be copied
 * \param len number of bytes to be copied
 */
void seco_os_abs_memcpy(uint8_t *dst, uint8_t *src, uint32_t len);

/**
 * Dynamically allocate memory.
 *
 * \param size number of bytes to be allocated
 *
 * \return pointer to the allocated buffer or NULL in case of error.
 */
uint8_t *seco_os_abs_malloc(uint32_t size);

/**
 * Free a previously allocated buffer.
 *
 * \param ptr pointer to the buffer to free
 *
 */
void seco_os_abs_free(void *ptr);

/**
 * Write data to the non volatile storage.
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 * \param src pointer to the data to be written to storage.
 * \param size number of bytes to be written.
 *
 * \return number of bytes written.
 */
int32_t seco_os_abs_storage_write(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size);

/**
 * Read data from the non volatile storage.
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 * \param dst pointer to the data where data read from the storage should be copied.
 * \param size number of bytes to be read.
 *
 * \return number of bytes read.
 */
int32_t seco_os_abs_storage_read(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size);

/**
 * Write a subset of data to the non volatile storage.
 *
 * In case of large storage SECO will split it in "chunks" that will be encrypted in blobs.
 * A unique identifier within the system allow the storage manager to store and read it without
 * ambiguity.
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 * \param src pointer to the data to be written to storage.
 * \param size number of bytes to be written.
 * \patam blob_id unique identifier of the blob corresponding to the storage chunk to be written
 *
 * \return number of bytes written.
 */
int32_t seco_os_abs_storage_write_chunk(struct seco_os_abs_hdl *phdl, uint8_t *src, uint32_t size, uint64_t blob_id);

/**
 * Read a subset of data from the non volatile storage.
 *
 * In case of large storage SECO will split it in "chunks" that will be encrypted in blobs.
 * A unique identifier within the system allow the storage manager to store and read it without
 * ambiguity.
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 * \param dst pointer to the data where data read from the storage should be copied.
 * \param size number of bytes to be read.
 * \patam blob_id unique identifier of the blob corresponding to the storage chunk to be read
 *
 * \return number of bytes read.
 */
int32_t seco_os_abs_storage_read_chunk(struct seco_os_abs_hdl *phdl, uint8_t *dst, uint32_t size, uint64_t blob_id);

/**
 * Start the RNG from a system point of view.
 *
 * Start the RNG HW through a SCU RPC: sc_seco_start_rng()
 *
 * \param phdl pointer to the session handle for which this data buffer is used.
 */
void seco_os_abs_start_system_rng(struct seco_os_abs_hdl *phdl);

/**
 * Send a signed message to SECO through dedicated SCU RPC
 *
 * Purpose is to unlock the creation of a storage in some specific cases.
 *
 * \param signed_message pointer to the signed message.
 * \param msg_len length of the signed message
 */
int32_t seco_os_abs_send_signed_message(struct seco_os_abs_hdl *phdl, uint8_t *signed_message, uint32_t msg_len);

/** @} end of porting guide */
#endif
