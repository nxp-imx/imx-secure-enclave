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

CFLAGS := -O1 -Werror -fPIC
DESTDIR ?= export
BINDIR ?= /usr/bin
base_libdir ?= /lib
LIBDIR ?= /usr/$(base_libdir)
INCLUDEDIR ?= /usr/include
PLAT ?= seco

ifdef COVERAGE
GCOV_FLAGS :=-fprofile-arcs -ftest-coverage
endif

PLAT_PATH := src/plat/$(PLAT)
PLAT_COMMON_PATH := src/common

INCLUDE_PATHS := -I${PLAT_PATH}/include -I${PLAT_COMMON_PATH}/include -Iinclude -Iinclude/hsm

OBJECTS	:= \
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(PLAT_COMMON_PATH)/hsm_lib.o \
	$(PLAT_COMMON_PATH)/nvm_manager.o

include $(PLAT_PATH)/$(PLAT).mk

PROJECT	:= $(SHE_TEST) $(HSM_TEST) $(V2X_TEST) $(SHE_LIB) $(NVM_LIB) $(HSM_LIB)

all: ${PROJECT}

.PHONY: all clean

%.o: %.c
	@echo "  HOSTCC  $<"
	${CC} -c ${CFLAGS} ${GCOV_FLAGS} ${INCLUDE_PATHS} $< -o $@

# SHE lib
$(SHE_LIB): \
	$(PLAT_PATH)/$(PLAT)_utils.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o \
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(PLAT_COMMON_PATH)/sab_messaging.o
	$(AR) rcs $@ $^

# HSM lib
$(HSM_LIB): \
	$(PLAT_COMMON_PATH)/hsm_lib.o \
	$(PLAT_PATH)/$(PLAT)_utils.o \
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o
	$(AR) rcs $@ $^

# NVM manager lib
$(NVM_LIB): $(PLAT_COMMON_PATH)/nvm_manager.o
	$(AR) rcs $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
endif

COMMON_TEST_OBJ=$(wildcard test/common/*.c)
COMMON_TEST_INC=-Itest/common/include/

HSM_TEST_OBJ=$(wildcard test/hsm/*.c) $(COMMON_TEST_OBJ)
$(HSM_TEST): $(HSM_TEST_OBJ) $(HSM_LIB) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} ${COMMON_TEST_INC} $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

SHE_TEST_OBJ=$(wildcard test/she/src/*.c)
#SHE test app
$(SHE_TEST): $(SHE_TEST_OBJ) $(SHE_LIB) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

V2X_TEST_OBJ=$(wildcard test/v2x/*.c)
$(V2X_TEST): $(V2X_TEST_OBJ) $(HSM_LIB) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf $(OBJECTS) *.gcno *.a *_test $(TEST_OBJ) $(DESTDIR)

she_doc: include/she_api.h include/nvm.h
	rm -rf doc/latex/
	doxygen doc/she/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/she_api_manual.pdf
	rm -rf doc/latex/

hsm_doc: include/hsm/hsm_api.h
	rm -rf doc/latex/
	doxygen doc/hsm/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/hsm_api_document.pdf
	rm -rf doc/latex/

install: $(HSM_TEST) $(SHE_TEST) $(SHE_LIB) $(NVM_LIB) $(HSM_LIB)
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp $(NVM_LIB) $(HSM_LIB) $(SHE_LIB) $(DESTDIR)$(LIBDIR)
	cp $(HSM_TEST) $(SHE_TEST) $(DESTDIR)$(BINDIR)
	cp -a include/* $(DESTDIR)$(INCLUDEDIR)
