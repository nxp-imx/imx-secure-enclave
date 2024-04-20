// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __she_test_h__
#define __she_test_h__

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include "she_api.h"

typedef enum {
	KEY_STORE = 0,
	UTILS,
	CIPHER
} service_type;

typedef struct {
	she_hdl_t she_hdl;
	she_hdl_t rng_hdl;
	she_hdl_t service_hdl[5][3];
	int cmd_prio;
	int inst;
	char cmd_name[32];
} she_test_struct_t;

struct she_test_entry_t {
	const char *name;
	uint32_t (*func)(she_test_struct_t *testCtx, FILE *fp);
};

#endif  // __she_test_h__
