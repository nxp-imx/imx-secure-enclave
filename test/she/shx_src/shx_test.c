// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shx_reader.h"
#include "she_api.h"
#include "shx_exec.h"
#include "shx_test.h"
#include "slt_log.h"

she_test_struct_t testCtx[20] = { 0 };

void execute_test_vectors(FILE *fp)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	uint16_t i;
	uint32_t fails = 0;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (line[0] == '<') {
			slt_print(SLT_DEBUG, "%s", line);
		} else {
			uint32_t these_fails = 0;

			for (i = 0;
			     i < (sizeof(tests) / sizeof(struct she_test_entry_t));
			     i++) {
				if (memcmp(line,
					   tests[i].name,
					   strlen(tests[i].name)) == 0) {
					slt_print(SLT_INFO, "test: %s", line);
					these_fails += she_exec_function(i, fp, testCtx);
					slt_print(SLT_INFO, "\n");
					break;
				}
			}
			fails += these_fails;
			if (these_fails != 0) {
				slt_print(SLT_ERROR,
					  "--- Test reported fails: %d", these_fails);
				break;
			}
		}
	}

	if (line) {
		free(line);
		line = NULL;
	}
}

/* Test entry function. */
int shx_she_tests(int argc, char *argv[])
{
	FILE *fp;

	uint32_t idx = 1;

	while (idx < argc) {
		do {
			fp = fopen(argv[idx], "r");
			if (!fp) {
				slt_print(SLT_ERROR,
					  "Can't open file: %s  --> FAIL\n", argv[idx]);
				break;
			}

			/* Indicate the start of a test */
			slt_print(SLT_NOTICE, "\n<test>\n");

			slt_print(SLT_NOTICE, "<filename>%s</filename>\n", argv[idx]);

			execute_test_vectors(fp);

		} while (false);

		idx++;

		if (!fp) {
			(void)fclose(fp);

			/* Indicate the end of a test */
			slt_print(SLT_NOTICE, "\n</test>\n");
		}
	}

	return 0;
}
