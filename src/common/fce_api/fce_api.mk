# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025 NXP
#

FCE_API_SRC	+= \
		$(PLAT_COMMON_PATH)/fce_api/fce_service.o \
		$(PLAT_COMMON_PATH)/fce_api/fce_hmac.o \
		$(PLAT_COMMON_PATH)/fce_api/fce_aes.o \
		$(PLAT_COMMON_PATH)/fce_api/fce_mem.o

OBJECTS		+= $(FCE_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/fce \
		   -I${PLAT_COMMON_PATH}/sab_msg/include \
