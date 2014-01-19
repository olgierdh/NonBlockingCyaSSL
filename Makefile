REV := $(shell git rev-parse --short --no-symbolic HEAD)


build_cyassl:
	cd ./imports/cyassl && ./autogen.sh && ./configure && make -j5

all: build_cyassl

