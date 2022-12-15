class="aarch64-linux-gnu"
# arm-linux-gnueabihf
assembly:
	$(class)-gcc -O2 -S -c foo.c 


binary:
	$(class)-as foo.s

all: assembly binary
# sudo apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu