
all: she_test she_start_storage_manager hsm_test she_lib.a seco_nvm_manager.a hsm_lib.a

CFLAGS = -Werror

ifdef COVERAGE
GCOV_FLAGS=-fprofile-arcs -ftest-coverage
endif

# SHE implementation
she_lib.o: src/she_lib.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

# HSM
hsm_lib.o: src/hsm_lib.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

# SHE storage implementation
seco_nvm_manager.o: src/seco_nvm_manager.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

# HSM storage implementation
hsm_storage.o: src/hsm_storage.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

seco_sab_messaging.o: src/seco_sab_messaging.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

seco_utils.o: src/seco_utils.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

seco_os_abs_linux.o: src/seco_os_abs_linux.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

# SHE lib
she_lib.a: she_lib.o seco_utils.o seco_sab_messaging.o seco_os_abs_linux.o
	$(AR) rcs $@ $^

# HSM lib
hsm_lib.a: hsm_lib.o
	$(AR) rcs $@ $^

# NVM manager lib
seco_nvm_manager.a: seco_nvm_manager.o
	$(AR) rcs $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
endif

hsm_test: hsm_lib.o seco_utils.o seco_sab_messaging.o seco_nvm_manager.o seco_os_abs_linux.o test/hsm/hsm_test.c
	$(CC) $^  -o $@ -I include -I include/hsm $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

TEST_OBJ=$(patsubst %.c,%.o,$(wildcard test/src/*.c))

test/src/%.o: test/src/%.c 
	$(CC) $^  -c -o $@ -I include -I test/src $(CFLAGS) $(DEFINES)

test/she_start_storage_manager/%.o: test/she_start_storage_manager/%.c
	$(CC) $^  -c -o $@ -I include -I test/src $(CFLAGS) $(DEFINES)

#SHE test app
she_test: she_lib.o seco_utils.o seco_sab_messaging.o seco_nvm_manager.o seco_os_abs_linux.o $(TEST_OBJ) include/she_api.h
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

she_start_storage_manager: seco_utils.o seco_sab_messaging.o seco_nvm_manager.o seco_os_abs_linux.o test/she_start_storage_manager/she_start_storage_manager.o include/she_api.h
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf she_test *.o *.gcno *.a she_start_storage_manager hsm_test $(TEST_OBJ)

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
