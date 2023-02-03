arm64="aarch64-linux-gnu"
arm="arm-linux-gnueabihf"
x64="x86_64-linux-gnu"
assembly_arm64:
	$(arm64)-gcc -O2 -S -c foo.c -o foo_arm64.s

binary_arm64:
	$(arm64)-as foo_arm64.s -o foo_arm64

assembly_arm:
	$(arm)-gcc -O2 -S -c foo.c -o foo_arm.s

binary_arm:
	$(arm)-as foo_arm.s -o foo_arm

assembly_x64:
	$(x64)-gcc -O2 -S -c foo.c -o foo_x64.s

binary_x64:
	$(x64)-as foo_x64.s -o foo_x64

build_arm: assembly_arm binary_arm
build_arm64: assembly_arm64 binary_arm64
build_x64: assembly_x64 binary_x64

clean:
	rm foo_*


all: build_arm build_arm64 build_x64
# sudo apt install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu