
all: she_test hsm_test she_lib.a seco_nvm_manager.a hsm_lib.a

CFLAGS = -O1 -Werror
DESTDIR ?= export
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

ifdef COVERAGE
GCOV_FLAGS=-fprofile-arcs -ftest-coverage
endif

%.o: src/%.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

# SHE lib
she_lib.a: she_lib.o seco_utils.o seco_sab_messaging.o seco_os_abs_linux.o
	$(AR) rcs $@ $^

# HSM lib
hsm_lib.a: hsm_lib.o seco_utils.o seco_sab_messaging.o seco_os_abs_linux.o
	$(AR) rcs $@ $^

# NVM manager lib
seco_nvm_manager.a: seco_nvm_manager.o
	$(AR) rcs $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
endif
HSM_TEST_OBJ=$(wildcard test/hsm/*.c)
hsm_test: $(HSM_TEST_OBJ) hsm_lib.a seco_nvm_manager.a
	$(CC) $^  -o $@ -I include -I include/hsm $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

SHE_TEST_OBJ=$(wildcard test/she/src/*.c)
#SHE test app
she_test: $(SHE_TEST_OBJ) she_lib.a seco_nvm_manager.a
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf she_test *.o *.gcno *.a hsm_test $(TEST_OBJ) $(DESTDIR)

she_doc: include/she_api.h include/seco_nvm.h
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

install: hsm_test she_test she_lib.a seco_nvm_manager.a hsm_lib.a
	mkdir -p $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp -a seco_nvm_manager.a hsm_lib.a she_lib.a $(DESTDIR)$(LIBDIR)
	cp hsm_test she_test $(DESTDIR)$(BINDIR)
	cp -a include/* $(DESTDIR)$(INCLUDEDIR)

