#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>

void main(int argc, char ** argv){
	printf("Starting our loader\n");
	char filename[256];
	if(argc != 2){
		printf("WARNING defaulting to `test.bin` shellcode\n");
		strncpy(filename, "test.bin", 256);
	} else {
		strncpy(filename, argv[1], 256);
	}

	FILE * f;
	size_t fsize = 0;
	f = fopen(filename, "r");
	if(f == NULL){
		printf("Could not open `%s`\n",filename);
		exit(1);
	}

	// Getting file size, and going back to beginnning
	fseek(f, 0, SEEK_END);
	fsize =  (size_t)ftell(f);
	fseek(f, 0, SEEK_SET);
	
	// declaring function pointer: shellcode
	void (*shellcode)();
	shellcode = malloc(fsize);

	if(shellcode == NULL){
		printf("Allocation %ld bytes failed\n", fsize);
		exit(1);
	}

	// This performs page alignment
	// mprotect doesnot handled non page align addresses
	// a page align address is one in which the last 12 bits are 0
	void * ptr;
	ptr = (void (*)()) ((long long) shellcode & 0xfffffffffffff000);

	printf("Attempting to set %p + %x bytes RWX\n", ptr, (unsigned int) fsize + 0x1000);

	if(mprotect(ptr, fsize+0x1000, PROT_EXEC|PROT_WRITE|PROT_READ)){
		printf("Mprotect failure for %p\n", shellcode);
		printf("%s\n", strerror(errno));
		exit(1);
	}

	fread(shellcode, 1, fsize, f);
	shellcode();

}
