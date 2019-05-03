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
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIE
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef __SHE_TEST_MACROS_H__
#define __SHE_TEST_MACROS_H__


/*----------------------------------------------*/
/* allocate buffers and define pointers to them */
/*----------------------------------------------*/
#define dump_buffer(BUF, SIZE) \
    if (BUF == NULL) { \
        printf("NULL\n"); \
    } \
    else { \
        for (uint32_t i=0; i<SIZE; i++) { \
            printf("0x%x ", BUF[i]); \
            if (i%4 == 3) { \
                printf("\n"); \
            } \
        } \
    }


/*----------------------------------------------*/
/* allocate buffers and define pointers to them */
/*----------------------------------------------*/

#define INPUT_BUFFER(NAME, SIZE) \
    uint8_t i_buff_##NAME[SIZE]; \
    uint8_t *NAME = i_buff_##NAME;

#define OUTPUT_BUFFER(NAME, SIZE) INPUT_BUFFER(NAME, SIZE)


/*----------------------------------------------*/
/* Read data from the test file                 */
/*----------------------------------------------*/

#define READ_VALUE(FP, TYPE) \
    (TYPE)read_single_data(fp);

#ifdef DEBUG
#define READ_INPUT_BUFFER(FP, NAME, SIZE) \
    INPUT_BUFFER(NAME, SIZE) \
    read_buffer_ptr(FP, &NAME, SIZE); \
    printf("%s @  %p\n", #NAME, NAME); \
    dump_buffer(NAME, SIZE);
#else 
#define READ_INPUT_BUFFER(FP, NAME, SIZE) \
    INPUT_BUFFER(NAME, SIZE) \
    read_buffer_ptr(FP, &NAME, SIZE);
#endif

#define READ_OUTPUT_BUFFER(FP, NAME, SIZE) READ_INPUT_BUFFER(FP, NAME, SIZE)


/*----------------------------------------------*/
/* Check values                                 */
/*----------------------------------------------*/

#define CHECK_VALUE(VAL, EXP) \
    if (VAL != EXP) { \
        printf("--> FAIL unexpected error: 0x%x\n", VAL); \
        fails++; \
    } \
    else { \
        printf("--> PASS\n"); \
    }

#define CHECK_RANGE(VAL, EXP_MIN, EXP_MAX) \
    if ((VAL < EXP_MIN) || (VAL > EXP_MAX)) { \
        printf("--> FAIL value out of range: %d\n", VAL); \
        fails++; \
    } \
    else { \
        printf("--> PASS\n"); \
    }

#define CHECK_BUFFER(BUF, EXP, SIZE) \
    if (NULL != EXP) { \
        if (NULL == BUF) { \
            printf("--> FAIL output is NULL\n"); \
            fails++; \
        } \
        else if (0 != memcmp(BUF, EXP, SIZE)) { \
            printf("--> FAIL wrong output\n"); \
            fails++; \
            printf("Received buffer:\n"); \
            dump_buffer(BUF, SIZE); \
            printf("Expected buffer:\n"); \
            dump_buffer(EXP, SIZE); \
        } \
        else { \
            printf("--> PASS\n"); \
        } \
    }

/*----------------------------------------------*/
/* Read values from the test file, check them   */
/*----------------------------------------------*/

#define READ_CHECK_VALUE(FP, NAME) \
    typeof(NAME) EXP_##NAME = READ_VALUE(FP, typeof(NAME)) \
    CHECK_VALUE(NAME, EXP_##NAME);

#define READ_CHECK_BUFFER(FP, NAME, SIZE) \
    READ_INPUT_BUFFER(FP, EXP_##NAME, SIZE) \
    CHECK_BUFFER(NAME, EXP_##NAME, SIZE)

#define READ_CHECK_RANGE(FP, NAME) \
    uint32_t EXP_MIN_##NAME = READ_VALUE(FP, uint32_t) \
    uint32_t EXP_MAX_##NAME = READ_VALUE(FP, uint32_t) \
    printf("RANGE_CHECK(%d, %d) ", EXP_MIN_##NAME, EXP_MAX_##NAME); \
    if (EXP_MAX_##NAME > EXP_MIN_##NAME) { \
        CHECK_RANGE(NAME, EXP_MIN_##NAME, EXP_MAX_##NAME); \
    } \
    else { \
        printf(" --> Disabled\n");\
    }

#endif // __SHE_TEST_MACROS_H__

