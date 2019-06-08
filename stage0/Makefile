build:
	nasm stage0.asm -o stage0.bin

clean:
	rm -f stage0.bin

test: clean build
	../loader/loader stage0.bin
