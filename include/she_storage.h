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
 * \defgroup she_storage
 * \brief SHE NVM storage API
 * \{
 */

/**
 * Initialize SHE storage manager.
 *
 * \return pointer to the storage context 
 */
struct she_storage_context *she_storage_init(void);


/**
 * terminates the SHE storage manager.
 *
 * \param ctx pointer to the context of the storage manager  to be closed.
 *
 * \return 0 on success. other value on failure.
 */
int32_t she_storage_terminate(struct she_storage_context *nvm_ctx);
