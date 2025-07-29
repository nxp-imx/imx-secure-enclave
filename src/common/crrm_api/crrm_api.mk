# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025 NXP
#

CRRM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_utils.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_session.o \
		$(PLAT_COMMON_PATH)/se_global_info.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_handle.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_dev_getinfo.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_get_info.o \

ifneq (${MT_SAB_BOOT_MODE},0x0)
DEFINES		+=	-DBOOT_MODE
CRRM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/crrm_api/crrm_boot_mode.o
endif

ifneq (${MT_SAB_GET_AWDT_STATUS},0x0)
DEFINES		+=	-DGET_AWDT_STATUS
CRRM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/crrm_api/crrm_get_AWDT_status.o
endif

ifneq (${MT_SAB_GET_NONCE},0x0)
DEFINES		+=	-DGET_NONCE
CRRM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/crrm_api/crrm_get_nonce.o
endif

ifneq (${MT_SAB_REFRESH_AWDT},0x0)
DEFINES		+=	-DREFRESH_AWDT
CRRM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/crrm_api/crrm_refresh_AWDT.o
endif

OBJECTS		+= $(CRRM_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/crrm
