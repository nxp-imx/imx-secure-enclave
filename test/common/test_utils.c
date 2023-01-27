/*
 * Copyright 2022-2023 NXP
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
#include <stdio.h>

void hexdump(uint32_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%08x ", buf[i]);
	}
	printf("\n\n");
}

/* hexdump which dumps byte-by-byte.
 * correctly reflecting the content
 * at the specific byte location.
 */
void hexdump_bb(uint8_t buf[], uint32_t size)
{
	int i = 0;

	for (i = 0; i < size; i++) {
		if ((i != 0) && (i % 16 == 0))
			printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");

}

void word_byteswap(uint32_t *buf, uint32_t buf_len)
{
	int i = 0;
	uint32_t word;

	for (; i < buf_len; i++) {
		word = buf[i];
		buf[i] = ((uint8_t *) &word)[3];
		buf[i] |= ((uint8_t *) &word)[2] << 8;
		buf[i] |= ((uint8_t *) &word)[1] << 16;
		buf[i] |= ((uint8_t *) &word)[0] << 24;
	}
}

