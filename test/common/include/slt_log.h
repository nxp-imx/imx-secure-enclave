// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef __SLT_LOG_H__
#define __SLT_LOG_H__

#include <stdio.h>
#include <pthread.h>

/* Debug levels */
#define SLT_EMERG      0
#define SLT_ALERT      1
#define SLT_CRIT       2
#define SLT_ERROR      3
#define SLT_WARNING    4
#define SLT_NOTICE     5
#define SLT_INFO       6
#define SLT_DEBUG      7
#define SLT_VERBOSE    8

#if !defined(SLT_LOGLEVEL)
#define SLT_LOGLEVEL SLT_INFO
#endif

#ifdef SLT_LOG_TO_FILE
#ifndef SLT_LOG_PATH
#define SLT_LOG_PATH "/var/volatile/slt_log.txt" /* tmpfs for fast access */
#endif
#define SLT_MUTEX "/mutex_slt_lock"
/* Global variables used in slt_print, to be init in main */
FILE *fd_;
pthread_mutex_t *slt_log_mutex_;
/* Seco Lib Test print to file macro */
#define slt_print(level, x...) do { if ((level) <= SLT_LOGLEVEL) { \
	pthread_mutex_lock(slt_log_mutex_); \
	fprintf(fd_, x);  \
	fflush(fd_); \
	pthread_mutex_unlock(slt_log_mutex_);\
} } while (0)
#else /* !SLT_LOG_TO_FILE */
/* Seco Lib Test print to UART macro */
#define slt_print(level, x...) do { if ((level) <= SLT_LOGLEVEL) printf(x); } while (0)
#endif /* SLT_LOG_TO_FILE */
#endif  /* __SLT_LOG_H__ */
