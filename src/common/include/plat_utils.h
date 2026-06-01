// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2026 NXP
 */


#ifndef PLAT_UTILS_H
#define PLAT_UTILS_H

#include "sab_msg_def.h"
#include "plat_os_abs.h"

#include "internal/hsm_utils.h"

#define no_printf(...)						\
{}
/* Legacy logging macros - preserved for backward compatibility */
#define se_print(a,...) printf("%s(): " a,__func__,##__VA_ARGS__)

#ifdef ELE_DEBUG
#define se_err(a,...) printf("%s(): " a, __func__, ## __VA_ARGS__)
#define se_info(a,...) printf("%s(): "  a,__func__, ##__VA_ARGS__)
#define se_warn(a, ...) printf("%s(): "  a, __func__, ##__VA_ARGS__)
#else
#define se_err(...) no_printf(__VA_ARGS__) /* not debugging */
#define se_info(...) no_printf(__VA_ARGS__) /* not debugging */
#define se_warn(...) no_printf(__VA_ARGS__) /* not debugging */
#endif

/* ========================================================================
 * New Standard Log Level System
 * ========================================================================
 */

/* Standard log levels */
#define SE_LOG_LEVEL_NONE     0
#define SE_LOG_LEVEL_FATAL    1
#define SE_LOG_LEVEL_ERROR    2
#define SE_LOG_LEVEL_WARN     3
#define SE_LOG_LEVEL_INFO     4
#define SE_LOG_LEVEL_DEBUG    5
#define SE_LOG_LEVEL_VERBOSE  6

/* Set default log level to ERROR if not defined */
#ifndef SE_LOG_LEVEL
#define SE_LOG_LEVEL SE_LOG_LEVEL_ERROR
#endif

/* Core logging macro with level check */
#define se_log(level, tag, fmt, ...) \
	do { \
		if (level <= SE_LOG_LEVEL) { \
			printf("[" tag "] %s(): " fmt, __func__, ##__VA_ARGS__); \
		} \
	} while (0)

/* New standard log level functions */
#define se_log_fatal(fmt, ...) \
		se_log(SE_LOG_LEVEL_FATAL,   "FATAL",   fmt, ##__VA_ARGS__)
#define se_log_error(fmt, ...) \
		se_log(SE_LOG_LEVEL_ERROR,   "ERROR",   fmt, ##__VA_ARGS__)
#define se_log_warn(fmt, ...) \
		se_log(SE_LOG_LEVEL_WARN,    "WARN",    fmt, ##__VA_ARGS__)
#define se_log_info(fmt, ...) \
		se_log(SE_LOG_LEVEL_INFO,    "INFO",    fmt, ##__VA_ARGS__)
#define se_log_debug(fmt, ...) \
		se_log(SE_LOG_LEVEL_DEBUG,   "DEBUG",   fmt, ##__VA_ARGS__)
#define se_log_verbose(fmt, ...) \
		se_log(SE_LOG_LEVEL_VERBOSE, "VERBOSE", fmt, ##__VA_ARGS__)

/* Shorter aliases for convenience */
#define SE_FATAL(fmt, ...)   se_log_fatal(fmt, ##__VA_ARGS__)
#define SE_ERROR(fmt, ...)   se_log_error(fmt, ##__VA_ARGS__)
#define SE_WARN(fmt, ...)    se_log_warn(fmt, ##__VA_ARGS__)
#define SE_INFO(fmt, ...)    se_log_info(fmt, ##__VA_ARGS__)
#define SE_DEBUG(fmt, ...)   se_log_debug(fmt, ##__VA_ARGS__)
#define SE_VERBOSE(fmt, ...) se_log_verbose(fmt, ##__VA_ARGS__)

/* ======================================================================== */

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define UINT32_ADD(value_a, value_b) \
	({ \
		typeof(value_a) _a = (value_a); \
		typeof(value_b) _b = (value_b); \
		long _c = _a + _b; \
		(_c < UINT32_MAX) ? (uint32_t)_c : 0; \
	 })

#define PLAT_SUCCESS        (0x0u)
#define PLAT_FAILURE        (0x1u)
#define PLAT_READ_FAILURE   (0x0u)
#define PLAT_WRITE_FAILURE  (0x0u)
#define PLAT_OPEN_FAILURE   (0xFFFFFFFFu)

/**
 * Library platform error codes
 */
#define PLAT_MEMCPY_FAIL               0x02u
#define PLAT_ERR_OUT_OF_MEMORY         0x03u
#define PLAT_DATA_BUF_SETUP_FAIL       0x04u
#define PLAT_DATA_BUF_SETUP_FAIL_OUT_OF_MEM \
	(IO_BUF_OUT_OF_MEM >> 8)
#define PLAT_SIGNED_MESSAGE_SETUP_FAIL 0x05u
#define PLAT_ERR_NO_SUCH_FILE_DIR      0x06u
#define PLAT_CONF_SHARED_BUF_FAIL      0x08u

typedef enum {
	NOT_SUPPORTED,
	ROM_MSG,
	SAB_MSG,
	MAX_MSG_TYPE,
} msg_type_t;

/* Count the number of bits set in x */
static inline uint32_t bf_popcount(uint32_t x)
{
	return (uint32_t)(__builtin_popcount(x));
}

void plat_build_cmd_msg_hdr(struct sab_mu_hdr *hdr, msg_type_t msg_type,
			uint8_t cmd, uint32_t len, uint32_t mu_type,
			struct plat_os_abs_hdl *phdl);
void plat_build_rsp_msg_hdr(struct sab_mu_hdr *hdr, msg_type_t msg_type,
			uint8_t cmd, uint32_t len, uint32_t mu_type,
			struct plat_os_abs_hdl *phdl);

int32_t plat_send_msg_and_get_resp(struct plat_os_abs_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len);

uint32_t plat_send_msg_and_rcv_resp(struct plat_os_abs_hdl *phdl,
				    uint32_t *cmd,
				    uint32_t cmd_len,
				    uint32_t *rsp,
				    uint32_t *rsp_len);

uint32_t plat_compute_msg_crc(uint32_t *msg, uint32_t msg_len);
uint32_t plat_fetch_msg_crc(uint32_t *msg, uint32_t msg_len);
uint32_t plat_add_msg_crc(uint32_t *msg, uint32_t msg_len);
uint8_t plat_validate_msg_crc(uint32_t *msg, uint32_t msg_len);

uint32_t plat_rcvmsg_cmd(struct plat_os_abs_hdl *phdl,
			 uint32_t *cmd,
			 uint32_t *cmd_len,
			 uint32_t *rcv_msg_cmd_id);
uint32_t plat_sndmsg_rsp(struct plat_os_abs_hdl *phdl,
			 uint32_t *rsp,
			 uint32_t rsp_len);
#endif
