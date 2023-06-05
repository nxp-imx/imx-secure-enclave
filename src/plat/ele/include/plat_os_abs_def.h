// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#ifndef PLAT_OS_ABS_DEF_H
#define PLAT_OS_ABS_DEF_H

#include <stdint.h>

#define NO_LENGTH                   0x0u
#define MAX_FNAME_DNAME_SZ          256u

struct plat_os_abs_hdl {
    int32_t fd;
    uint32_t type;
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

#define MAX_KEY_STORE             (0x02u)

struct key_db_fd {
	uint32_t key_store_id;
	int persistent_tmp_fd;
	int volatile_fd;
};

uint32_t get_chunk_file_path(char **path,
			     uint8_t *nvm_storage_dname,
			     uint64_t blob_id);

#endif /* PLAT_OS_ABS_DEF_H */
