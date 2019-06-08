build:
	cd loader && make build
	cd stage0 && make build

clean:
	cd loader && make clean
	cd stage0 && make clean

test: clean build
	loader/loader stage0/stage0.bin
