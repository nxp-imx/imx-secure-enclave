/*
 * Copyright 2019 NXP
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "she_api.h"

static char mac_input_message[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
									0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
									0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 };

static char mac_output[SHE_MAC_SIZE]; /*128bits*/

#define MAC_TEST1_INPUT_SIZE 16
static char mac_output_ref1[] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};

#define MAC_TEST2_INPUT_SIZE 40
static char mac_output_ref2[] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};


int main(int argc, char *argv[])
{
	int i;
	int test_len;
	struct timespec ts1, ts2;
	long time_us;

	she_hdl *hdl = she_open_session();

	printf("------------ MAC generation test 1 ----------------\n");
	she_cmd_generate_mac(hdl, 1, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output);

	if (memcmp(mac_output, mac_output_ref1, SHE_MAC_SIZE))
		printf("\n--> ERROR\n");
	else
		printf("\n-->PASS\n");

	printf("------------ MAC generation test 2 ----------------\n");
	she_cmd_generate_mac(hdl, 1, MAC_TEST2_INPUT_SIZE, mac_input_message, mac_output);

	if (memcmp(mac_output, mac_output_ref2, SHE_MAC_SIZE))
		printf("\n--> ERROR\n");
	else
		printf("\n-->PASS\n");

	/* Speed test. */
	printf("------------ MAC generation speed test ------------\n");
	test_len = 100000; /* default length. */
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

	for (i=0; i<test_len; i++)
		she_cmd_generate_mac(hdl, 1, MAC_TEST1_INPUT_SIZE, mac_input_message , mac_output);

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);
    time_us = (long)(ts2.tv_sec - ts1.tv_sec)*1000000 + (ts2.tv_nsec - ts1.tv_nsec)/1000;

	printf("%d MAC generated in %ld microseconds (about %ld microseconds per MAC)\n", test_len, time_us, time_us/test_len);

	she_close_session(hdl);
}
