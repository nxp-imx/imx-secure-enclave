/*
 * Copyright 2023 NXP
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


#include <stdint.h>

void HEXDUMP(unsigned char *buf, size_t sz);
int32_t compare_data(uint8_t *ori_data, uint8_t *dec_data, int32_t datalen);
void BUFF_DUMP(char *, unsigned char *, size_t);

uint32_t openSSL_Encryption(void *pldataB, uint32_t pldataB_length,
			    void *plKey, uint32_t plKey_length,
			    void *enc_dataB, uint32_t *enc_dataB_length,
			    uint32_t aes_mode, void *iv, uint32_t iv_length);
