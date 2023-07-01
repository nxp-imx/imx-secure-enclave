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

ifneq (${MT_SAB_OPEN_UTILS},0x0)
DEFINES		+=	-DSHE_OPEN_UTILS
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_open_utils.o
endif

ifneq (${MT_SAB_KEY_STORE},0x0)
DEFINES		+=	-DSHE_KEY_STORE
SHE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/she_api/she_open_key_store.o
endif

OBJECTS		+= $(SHE_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/she \
		   -I${PLAT_COMMON_PATH}/she_api/include
