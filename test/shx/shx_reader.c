// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shx_reader.h"
#include "shx_test_macros.h"
#include "slt_log.h"

uint32_t shx_read_single_data(FILE *fp)
{
	uint32_t value = 0;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	read = getline(&line, &len, fp);
	if (read > 0)
		value = (uint32_t)strtoul(line, NULL, 0);

	slt_print(SLT_DEBUG, "VALUE: 0x%x\n", value);

	FREE_BUFFER(line);

	return value;
}

void shx_read_buffer(FILE *fp, uint8_t *dst, uint32_t size)
{
	char *line = NULL;
	char *startptr = NULL;
	char *endptr = NULL;
	size_t len = 0;
	ssize_t read;
	uint32_t idx = 0;
	uint32_t data;

	while (idx < size) {
		read = getline(&line, &len, fp);
		if (read < 0)
			break;

		startptr = line;

		data = strtoul(startptr, &endptr, 0);
		while (endptr != startptr) {
			dst[idx++] = (uint8_t)(data & 0xFFu);
			startptr = endptr + 1; /* skip separator */
			data = strtoul(startptr, &endptr, 0);
		}
	}

	FREE_BUFFER(line);
}

void shx_read_buffer_ptr(FILE *fp, uint8_t **dst, uint32_t *sz)
{
	char *line = NULL;
	char *startptr = NULL;
	char *endptr = NULL;
	size_t len = 0;
	size_t read;
	uint32_t idx = 0;
	uint32_t data;

	uint32_t size = *sz;

	if (size == 0) // Always read one byte ... we have to support NULL for zero-length
		size = 1;

	while (idx < size) {
		read = getline(&line, &len, fp);
		if (read < 0)
			break;

		if (read >= 4 && (memcmp("NULL", line, 4) == 0)) {
			*dst = NULL;
			*sz = 0;
			break;
		}

		uint8_t *d = *dst;

		startptr = line;

		data = strtoul(startptr, &endptr, 0);
		while (endptr != startptr) {
			d[idx++] = (uint8_t)(data & 0xFFu);
			startptr = endptr + 1; /* skip separator */
			data = strtoul(startptr, &endptr, 0);
		}
	}

	FREE_BUFFER(line);
}
