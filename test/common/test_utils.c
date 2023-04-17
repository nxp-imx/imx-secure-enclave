// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
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

