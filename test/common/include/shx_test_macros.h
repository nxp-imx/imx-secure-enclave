// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __SHX_TEST_MACROS_H__
#define __SHX_TEST_MACROS_H__

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "shx_reader.h"
#include "slt_log.h"

/* get timestamp in us */
static inline unsigned long get_timestamp(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (1000000 * ts.tv_sec) + (ts.tv_nsec / 1000);
}

#define TS get_timestamp()
#define COMBINE1(X, Y) X##Y
#define COMBINE(X, Y) COMBINE1(X, Y)

/*----------------------------------------------*/
/* dump a buffer's contents to stdout           */
/*----------------------------------------------*/

static inline void dump_buffer(uint8_t *BUF, uint32_t SIZE)
{
	if (!(BUF)) {
		slt_print(SLT_INFO, "NULL\n");
	} else if ((SIZE)  == 0) {
		slt_print(SLT_INFO, "SIZE = 0\n");
	} else {
		for (uint32_t i = 0; i < (SIZE); i++) {
			slt_print(SLT_INFO, "0x%x ", BUF[i]);
			if (i % 4 == 3)
				slt_print(SLT_INFO, "\n");
		}
	}
	if ((SIZE) % 4)
		slt_print(SLT_INFO, "\n");
}

/*----------------------------------------------*/
/* Read data from the test file                 */
/*----------------------------------------------*/

#define READ_VALUE(FP, TYPE) \
	({ \
		(TYPE)shx_read_single_data(FP); \
	})

#define READ_INPUT_BUFFER(FP, SIZE) \
	({ \
	 uint8_t *COMBINE(B_, __LINE__) = malloc(SIZE); \
	 uint8_t *COMBINE(P_, __LINE__) = COMBINE(B_, __LINE__); \
	 uint32_t COMBINE(SZ_, __LINE__) = SIZE; \
	 shx_read_buffer_ptr(FP, &COMBINE(P_, __LINE__), &COMBINE(SZ_, __LINE__)); \
	 slt_print(SLT_DEBUG, "BUFFER @  %p (%d):\n", \
		   COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	if (SLT_LOGLEVEL >= SLT_DEBUG) \
		dump_buffer(COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	 COMBINE(P_, __LINE__); \
	 })

#define READ_INPUT_ARRAY(FP, DST, SIZE) \
	({ \
	 uint8_t *COMBINE(P_, __LINE__) = DST; \
	 uint32_t COMBINE(SZ_, __LINE__) = SIZE; \
	 shx_read_buffer_ptr(FP, &COMBINE(P_, __LINE__), &COMBINE(SZ_, __LINE__)); \
	 slt_print(SLT_DEBUG, "BUFFER @  %p (%d):\n", \
		   COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	if (SLT_LOGLEVEL >= SLT_DEBUG) \
		dump_buffer(COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	 COMBINE(P_, __LINE__); \
	 })

#define READ_OUTPUT_BUFFER(FP, SIZE) READ_INPUT_BUFFER(FP, SIZE)

#define FREE_BUFFER(BUFPTR) \
	({ \
	if (BUFPTR) { \
		free(BUFPTR);\
		BUFPTR = NULL; \
	} \
	 })

/*----------------------------------------------*/
/* Check values                                 */
/*----------------------------------------------*/
#define CHECK_RANGE(VAL, EXP_MIN, EXP_MAX) \
{ \
	do { \
		if ((VAL) < (EXP_MIN) || (VAL) > (EXP_MAX)) { \
			slt_print(SLT_ERROR, "[0x%x, 0x%x] --> [FAIL] received: %d\n", \
				  (EXP_MIN), (EXP_MAX), (VAL)); \
			fails++; \
		} \
		else { \
			slt_print(SLT_NOTICE, "[0x%x, 0x%x] --> [PASS]\n",\
				  (EXP_MIN), (EXP_MAX)); \
		} \
	} while (false); \
}

#ifdef EXTENTED_TRACE
#define CHECK_VALUE(CTX, VAL, EXP) \
{ \
	do { \
		if ((VAL) != (EXP)) { \
			slt_print(SLT_ERROR, "%lu %d (%d) %s [%d]: 0x%x " \
				  "--> [FAIL] received: 0x%x\n", \
				  TS, getpid(), (CTX)->cmd_prio, \
				  (CTX)->cmd_name, (CTX)->inst, (EXP), (VAL)); \
			fails++; \
		} \
		else { \
			slt_print(SLT_NOTICE, "%lu %d (%d) %s [%d]: 0x%x --> [PASS]\n", \
				  TS, getpid(), (CTX)->cmd_prio, \
				  (CTX)->cmd_name, (CTX)->inst, EXP); \
		} \
	} while (false); \
}

#define CHECK_BUFFER(CTX, BUF, EXP, SIZE) \
{ \
	do { \
		if (EXP) { \
			if (!(BUF)) { \
				slt_print(SLT_ERROR, "%lu %d (%d) %s [%d]: " \
					  "--> [FAIL] output is NULL\n", \
					  TS, getpid(), (CTX)->cmd_prio, \
					  (CTX)->cmd_name, (CTX)->inst); \
				fails++; \
			} \
			else if (memcmp((BUF), (EXP), SIZE) != 0) { \
				slt_print(SLT_ERROR, "%lu %d (%d) %s [%d]: " \
					  "--> [FAIL] wrong output\n", \
					  TS, getpid(), (CTX)->cmd_prio, \
					  (CTX)->cmd_name, (CTX)->inst); \
				fails++; \
				slt_print(SLT_DEBUG, "%lu %d (%d) %s [%d]: " \
					  "Received buffer (%s):\n", \
					  TS, getpid(), (CTX)->cmd_prio, \
					  (CTX)->cmd_name, (CTX)->inst, #BUF); \
				if (SLT_LOGLEVEL >= SLT_DEBUG) \
					dump_buffer((BUF), SIZE); \
				slt_print(SLT_DEBUG, "%lu %d (%d) %s [%d]: " \
					  "Expected buffer:\n", \
					  TS, getpid(), (CTX)->cmd_prio, \
					  (CTX)->cmd_name, (CTX)->inst); \
				if (SLT_LOGLEVEL >= SLT_DEBUG) \
					dump_buffer((EXP), SIZE); \
			} \
			else { \
				slt_print(SLT_NOTICE, "%lu %d (%d) %s [%d]:" \
					  "--> [PASS]\n", \
					  TS, getpid(), (CTX)->cmd_prio, \
					  (CTX)->cmd_name, (CTX)->inst); \
			} \
		} \
		else { \
			slt_print(SLT_INFO, "%lu %d (%d) %s [%d]: " \
				  "Received buffer (%s):\n", \
				  TS, getpid(), (CTX)->cmd_prio, \
				  (CTX)->cmd_name, (CTX)->inst, #BUF); \
			if (SLT_LOGLEVEL >= SLT_DEBUG) \
				dump_buffer(((BUF), SIZE); \
		} \
	} while (false); \
}

#define NOCHECK_BUFFER(CTX, BUF, EXP, SIZE) \
{ \
	slt_print(SLT_INFO, "%lu %d (%d) %s [%d]: Received buffer (%s):\n", \
		  TS, getpid(), (CTX)->cmd_prio, (CTX)->cmd_name, (CTX)->inst, #BUF); \
	if (SLT_LOGLEVEL >= SLT_DEBUG) \
		dump_buffer(BUF, SIZE); \
}

#else // !EXTENTED_TRACE
#define CHECK_VALUE(CTX, VAL, EXP) \
{ \
	if ((VAL) != (EXP)) { \
		slt_print(SLT_ERROR, "0x%x --> [FAIL] received: 0x%x\n", EXP, VAL); \
		fails++; \
	} else { \
		slt_print(SLT_INFO, "0x%x --> [PASS]\n", EXP); \
	} \
}

#define CHECK_BUFFER(CTX, BUF, EXP, SIZE) \
{ \
	if (EXP) { \
		if (!(BUF)) { \
			slt_print(SLT_ERROR, "--> [FAIL] output is NULL\n"); \
			fails++; \
		} else if (memcmp(BUF, EXP, SIZE) != 0) { \
			slt_print(SLT_ERROR, "--> [FAIL] wrong output\n"); \
			fails++; \
			slt_print(SLT_DEBUG, "    Received buffer (%s):\n", #BUF); \
			if (SLT_LOGLEVEL >= SLT_DEBUG) \
				dump_buffer(BUF, (SIZE)); \
			slt_print(SLT_DEBUG, "    Expected buffer:\n"); \
			if (SLT_LOGLEVEL >= SLT_DEBUG) \
				dump_buffer(EXP, (SIZE)); \
		} else { \
			slt_print(SLT_INFO, "--> [PASS]\n"); \
		} \
	} else { \
		slt_print(SLT_INFO, "    Received buffer (%s):\n", #BUF); \
		if (SLT_LOGLEVEL >= SLT_DEBUG) \
			dump_buffer(BUF, (SIZE)); \
	} \
}

#define NOCHECK_BUFFER(CTX, BUF, EXP, SIZE) \
	(slt_print(SLT_INFO, "    Received buffer (%s):\n", #BUF); \
	if (SLT_LOGLEVEL >= SLT_DEBUG) \
		dump_buffer(BUF, SIZE);)

#endif // EXTENTED_TRACE

#define PRINT_INPUT_BUFFER(FP, SIZE) \
{ \
	uint8_t *COMBINE(B_, __LINE__) = malloc(SIZE); \
	uint8_t *COMBINE(P_, __LINE__) = COMBINE(B_, __LINE__); \
	uint32_t COMBINE(SZ_, __LINE__) = SIZE; \
	shx_read_buffer_ptr(FP, &COMBINE(P_, __LINE__), &COMBINE(SZ_, __LINE__)); \
	slt_print(SLT_INFO, "<INPUT_DATA>\n"); \
	slt_print(SLT_INFO, "BUFFER @  %p (%d):\n", \
		  COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	if (SLT_LOGLEVEL >= SLT_DEBUG) \
		dump_buffer(COMBINE(B_, __LINE__), COMBINE(SZ_, __LINE__)); \
	COMBINE(P_, __LINE__); \
	slt_print(SLT_INFO, "</INPUT_DATA>"); \
}

#define PRINT_BUFFER(BUF, EXP, SIZE) \
{ \
	slt_print(SLT_INFO, "<OUTPUT_DATA>\n"); \
	dump_buffer(BUF, SIZE); \
	slt_print(SLT_INFO, "</OUTPUT_DATA>"); \
}

/*----------------------------------------------*/
/* Read values from the test file, check them   */
/*----------------------------------------------*/

#define READ_CHECK_VALUE(CTX, FP, NAME) \
{ \
	typeof(NAME) EXP_##NAME = READ_VALUE(FP, typeof(NAME)); \
	CHECK_VALUE(CTX, NAME, EXP_##NAME); \
}

#define READ_CHECK_BUFFER(CTX, FP, NAME, SIZE) \
	uint8_t *COMBINE(EXP_, __LINE__) = READ_INPUT_BUFFER(FP, SIZE); \
	if (COMBINE(EXP_, __LINE__)) { \
		CHECK_BUFFER(CTX, NAME, COMBINE(EXP_, __LINE__), SIZE); \
		FREE_BUFFER(COMBINE(EXP_, __LINE__)); \
	}

#define WRITE_NOCHECK_BUFFER(CTX, NAME, SIZE) \
{ \
	uint8_t *COMBINE(EXP_, __LINE__); \
	NOCHECK_BUFFER(CTX, NAME, COMBINE(EXP_, __LINE__), SIZE); \
	slt_print(SLT_INFO, "\n"); \
}

#define DISPLAY_BUFFER(NAME, SIZE) \
{ \
	uint8_t *COMBINE(EXP_, __LINE__); \
	PRINT_BUFFER(NAME, COMBINE(EXP_, __LINE__), SIZE); \
	slt_print(SLT_INFO, "\n"); \
}

#define READ_CHECK_RANGE(FP, NAME) \
	uint32_t EXP_MIN_##NAME = READ_VALUE(FP, uint32_t); \
	uint32_t EXP_MAX_##NAME = READ_VALUE(FP, uint32_t); \
	slt_print(SLT_NOTICE, "RANGE_CHECK(%d, %d) ", EXP_MIN_##NAME, EXP_MAX_##NAME); \
	if (EXP_MAX_##NAME > EXP_MIN_##NAME) { \
		CHECK_RANGE(NAME, EXP_MIN_##NAME, EXP_MAX_##NAME); \
	} \
	else { \
		slt_print(SLT_NOTICE, " --> Disabled\n");\
	}

#define READ_CHECK_POINTER(CTX, FP, NAME) \
{ \
	uint32_t ptrOk; \
	if ((NAME) != 0) { \
		ptrOk = 1; \
	} \
	else { \
		ptrOk = 0; \
	} \
	READ_CHECK_VALUE(CTX, FP, ptrOk); \
}

#ifdef SLT_PERF_MODE /* Disable some checks and prints */
#undef CHECK_BUFFER
#define CHECK_BUFFER(CTX, BUF, EXP, SIZE) NOCHECK_BUFFER(CTX, BUF, EXP, SIZE)
#undef PRINT_BUFFER
#define PRINT_BUFFER(BUF, EXP, SIZE) {}
#undef PRINT_INPUT_BUFFER
#define PRINT_INPUT_BUFFER(FP, SIZE) {}
#undef dump_buffer
#define dump_buffer(BUF, SIZE) {}

#endif /* PERF_MODE */

#endif // __SHX_TEST_MACROS_H__
