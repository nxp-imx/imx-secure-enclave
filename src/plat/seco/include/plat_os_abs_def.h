// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#ifndef PLAT_OS_ABS_DEF_H
#define PLAT_OS_ABS_DEF_H

#include <stdint.h>

#define NO_LENGTH                   0x0u
#define MAX_FNAME_DNAME_SZ          256u

struct mu_info {
	uint8_t cmd_tag;
	uint8_t rsp_tag;
	uint8_t success_tag;
	uint8_t base_api_ver;
	uint8_t fw_api_ver;
};

struct plat_os_abs_hdl {
	int32_t fd;
	uint32_t type;
	struct mu_info mu_info;
};


struct plat_mu_params {
    uint8_t mu_id;		/**< index of the MU as per PLAT point of view. */
    uint8_t interrupt_idx;	/**< Interrupt number of the MU used to indicate data availability. */
    uint8_t tz;			/**< indicate if current partition has TZ enabled. */
    uint8_t did;		/**< DID of the calling partition. */
};

#define MU_CHANNEL_UNDEF          (0x00u)
#define MU_CHANNEL_PLAT_SHE       (0x01u)
#define MU_CHANNEL_PLAT_SHE_NVM   (0x02u)
#define MU_CHANNEL_PLAT_HSM       (0x03u)
#define MU_CHANNEL_PLAT_HSM_2ND   (0x04u)
#define MU_CHANNEL_PLAT_HSM_NVM   (0x05u)
#define MU_CHANNEL_V2X_SV0        (0x10u)
#define MU_CHANNEL_V2X_SV1        (0x11u)
#define MU_CHANNEL_V2X_SHE        (0x12u)
#define MU_CHANNEL_V2X_SG0        (0x13u)
#define MU_CHANNEL_V2X_SG1        (0x14u)
#define MU_CHANNEL_V2X_SHE_NVM    (0x15u)
#define MU_CHANNEL_V2X_HSM_NVM    (0x16u)

uint32_t plat_sab_success_tag(void *phdl);

#define SAB_BLOB_ID_STRUCT_SIZE (8u)
struct sab_blob_id {
	uint32_t id;
	uint32_t ext;
};

#endif /* PLAT_OS_ABS_DEF_H */
