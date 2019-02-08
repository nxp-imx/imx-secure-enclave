
# Placeholder for platform specific implementation
she_platform_lib.o: src/she_linux.c
	$(CC) $^  -c -o $@ -I include

she_lib.o: src/she_generic.c
	$(CC) $^  -c -o $@ -I include

she_test: test/she_test.c she_lib.o she_platform_lib.o include/she_api.h
	$(CC) $^  -o $@ -I include

clean:
	rm -rf she_test she_lib.o she_platform_lib.o

doc: include/she_api.h
	rm -rf doc/html/
	doxygen doc/Doxyfile

