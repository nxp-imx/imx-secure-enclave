// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef ELE_PERF_H
#define ELE_PERF_H

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <hsm/internal/hsm_common_def.h>

#include "common.h"
#include "test_common_tv.h"
#include "plat_utils.h"

#define DEFAULT_TIME_PER_OP 1u
#define PERF_SUPPORTED_OP_N 3u

#define PERF_CIPHER_FNAME "test_vectors_set1_cipher_p.tv"
#define PERF_MAC_FNAME "test_vectors_set2_mac_p.tv"
#define PERF_SIGN_VERIFY_FNAME "test_vectors_set3_sign_verify_p.tv"
#define PERF_CIPHER_FPATH (DEFAULT_TV_DIR PERF_CIPHER_FNAME)
#define PERF_MAC_FPATH (DEFAULT_TV_DIR PERF_MAC_FNAME)
#define PERF_SIGN_VERIFY_FPATH (DEFAULT_TV_DIR PERF_SIGN_VERIFY_FNAME)

typedef struct statistics {
	//!< total operations occurred in the given time
	int no_of_ops;
	//!< mean time for a single operation
	float  mean_time;
	//!< total time for the operations
	float total_time;
} statistics;

uint64_t diff_microsec(struct timespec *t1, struct timespec *t2);

void update_stats(statistics *s, struct timespec *t1, struct timespec *t2);

float kb_per_sec(size_t size, float usec);

void print_perf_data(statistics *s, uint32_t size, const char *algo,
		     uint32_t ciphertext_size);

const char *cipher_algo_to_string(uint32_t val);

const char *scheme_algo_to_string(uint32_t val);

const char *mac_algo_to_string(uint32_t val);

#endif
