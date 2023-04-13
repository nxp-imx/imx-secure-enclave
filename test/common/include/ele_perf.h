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
#include "plat_utils.h"

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
