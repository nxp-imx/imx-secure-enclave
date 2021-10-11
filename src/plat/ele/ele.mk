#
# Copyright 2021 NXP
#
# NXP Confidential.
# This software is owned or controlled by NXP and may only be used strictly
# in accordance with the applicable license terms.  By expressly accepting
# such terms or by downloading, installing, activating and/or otherwise using
# the software, you are agreeing that you have read, and that you agree to
# comply with and are bound by, such license terms.  If you do not agree to be
# bound by the applicable license terms, then you may not retain, install,
# activate or otherwise use the software.
#

HSM_TEST := $(PLAT)_hsm_test
SHE_TEST := $(PLAT)_she_test
V2X_TEST := $(PLAT)_v2x_test
SHE_LIB := lib$(PLAT)_she.a
HSM_LIB := lib$(PLAT)_hsm.a
NVM_LIB := lib$(PLAT)_nvm.a

DEFINES		+=	-DCONFIG_PLAT_ELE

PLAT_OBJECTS	:=	$(PLAT_PATH)/ele_os_abs_linux.o \
			$(PLAT_PATH)/ele_utils.o

OBJECTS	+= $(PLAT_OBJECTS)
