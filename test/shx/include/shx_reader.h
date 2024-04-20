// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __SHX_READER_H__
#define __SHX_READER_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t shx_read_single_data(FILE *fp);

void shx_read_buffer(FILE *fp, uint8_t *dst, uint32_t size);

void shx_read_buffer_ptr(FILE *fp, uint8_t **dst, uint32_t *size);

#endif
