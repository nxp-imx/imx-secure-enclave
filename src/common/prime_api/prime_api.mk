# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2025-2026 NXP
#

PRIME_API_SRC	+= \
		$(PLAT_COMMON_PATH)/prime_api/service.o \
		$(PLAT_COMMON_PATH)/prime_api/service_utils.o \
		$(PLAT_COMMON_PATH)/prime_api/hmac.o \
		$(PLAT_COMMON_PATH)/prime_api/aes.o \
		$(PLAT_COMMON_PATH)/prime_api/v2x_version.o \
		$(PLAT_COMMON_PATH)/prime_api/info.o

OBJECTS		+= $(PRIME_API_SRC)

INCLUDE_PATHS	+= \
		   -Iinclude/prime \
		   -I${PLAT_COMMON_PATH}/sab_msg/include \
