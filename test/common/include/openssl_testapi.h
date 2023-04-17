// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */


#include <stdint.h>

void HEXDUMP(unsigned char *buf, size_t sz);
int32_t compare_data(uint8_t *ori_data, uint8_t *dec_data, int32_t datalen);
void BUFF_DUMP(char *, unsigned char *, size_t);

uint32_t openSSL_Encryption(void *pldataB, uint32_t pldataB_length,
			    void *plKey, uint32_t plKey_length,
			    void *enc_dataB, uint32_t *enc_dataB_length,
			    uint32_t aes_mode, void *iv, uint32_t iv_length);
