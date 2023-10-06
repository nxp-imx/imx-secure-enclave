# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2023 NXP
#

SHE_API_SRC	+= $(PLAT_COMMON_PATH)/she_api/she_handle.o \
		$(PLAT_COMMON_PATH)/she_api/she_utils.o \

ifneq (${MT_SAB_SESSION},0x0)
DEFINES		+=	-DSHE_SESSION
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_session.o
endif

ifneq (${MT_SAB_UTILS},0x0)
DEFINES		+=	-DSHE_OPEN_UTILS
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_utils_service.o
endif

ifneq (${MT_SAB_KEY_STORE},0x0)
DEFINES		+=	-DSHE_KEY_STORE
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_key_store.o
endif

ifneq (${MT_SAB_KEY_STORE},0x0)
DEFINES		+=	-DSHE_CIPHER
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_cipher.o
endif

ifneq (${MT_SAB_GET_STATUS},0x0)
DEFINES		+=	-DSHE_GET_STATUS
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_get_status.o
endif

ifneq (${MT_SAB_RNG},0x0)
DEFINES		+=	-DSHE_RNG
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_rng.o
endif

ifneq (${MT_SAB_GET_INFO},0x0)
DEFINES		+=	-DSHE_GET_INFO
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_get_info.o
endif

ifneq (${MT_SAB_KEY_UPDATE},0x0)
DEFINES		+=	-DSHE_KEY_UPDATE
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_key_update.o
endif

ifneq (${MT_SAB_CANCEL},0x0)
DEFINES		+=	-DSHE_CANCEL
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_cancel.o
endif

ifneq (${MT_SAB_PLAIN_KEY},0x0)
DEFINES		+=	-DSHE_PLAIN_KEY
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_load_plain_key.o \
		$(PLAT_COMMON_PATH)/she_api/she_export_plain_key.o
endif

ifneq (${MT_SAB_FAST_MAC},0x0)
DEFINES		+=	-DSHE_FAST_MAC
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_fast_mac.o
endif

ifneq (${MT_SAB_GET_ID},0x0)
DEFINES		+=	-DSHE_GET_ID
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_get_id.o
endif

OBJECTS		+= $(SHE_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/she \
		   -I${PLAT_COMMON_PATH}/she_api/include
