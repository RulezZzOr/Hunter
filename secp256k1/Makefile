.SUFFIXES:
.SUFFIXES: .cc .c .cu .o

# load options
include Makefile.in

# set shell
SHELL := /bin/bash

# compiler standard
STD = --std=c++11

# side libs paths
LIBS = -L/usr/local/lib -lcurl -I/usr/local/include -lssl -lcrypto -lnvidia-ml

# stub config content
CONFIG = '{ \
			 "mnemonic": "do not disclose the secret seed", \
			 "node": "http://188.166.89.71:9052", \
			 "keepPrehash": false \
		 }'

# compiler settings
CXX = nvcc
CFLAGS = -c --compiler-options -Wall
CXXFLAGS = -c $(STD) --compiler-options -Wall
COPT = -O3

# find CUDA compute capability available in this toolkit
SMS ?= $(strip $(shell nvcc --list-gpu-arch 2>/dev/null | grep -o 'sm_[0-9]\+' | sed 's/sm_//' | sort -n))
ifeq ($(SMS),)
SMS := $(CUDAARCH)
endif

ifeq ($(GENCODE_FLAGS),)
LOWEST_SM := $(strip $(firstword $(SMS)))
HIGHEST_SM := $(strip $(lastword $(SMS)))
REQUESTED_SM := $(strip $(if $(CUDAARCHS),$(CUDAARCHS),$(CUDAARCH)))
SUPPORTED_SM := $(strip $(filter $(SMS),$(REQUESTED_SM)))
UNSUPPORTED_SM := $(strip $(filter-out $(SMS),$(REQUESTED_SM)))

ifneq ($(UNSUPPORTED_SM),)
$(warning Requested CUDA architectures '$(UNSUPPORTED_SM)' are not supported by this nvcc and will be skipped)
endif

ifeq ($(SUPPORTED_SM),)
SUPPORTED_SM := $(HIGHEST_SM)
endif

ifneq ($(strip $(SUPPORTED_SM)),)
GENCODE_FLAGS += $(foreach sm,$(SUPPORTED_SM),-gencode arch=compute_$(sm),code=sm_$(sm))
endif

ifneq ($(HIGHEST_SM),)
GENCODE_FLAGS += -gencode arch=compute_$(HIGHEST_SM),code=compute_$(HIGHEST_SM)
endif

ifneq ($(LOWEST_SM),)
ifneq ($(LOWEST_SM),$(HIGHEST_SM))
GENCODE_FLAGS += -gencode arch=compute_$(LOWEST_SM),code=compute_$(LOWEST_SM)
endif
endif
endif

### NOTE: code=sm_xx means cuda binary generation for xx arch,
### code=compute_xx leaves PTX that newer drivers can JIT for newer GPUs,
### but native binaries are needed for optimal performance

# lib
AR = ar
LIBPATH = ./lib/lib.a

SRCDIR = ./src

# define sources
CUSOURCES = $(filter-out $(SRCDIR)/test.cu $(SRCDIR)/autolykos.cu, \
			$(wildcard $(SRCDIR)/*.cu))
CPPSOURCES = $(wildcard $(SRCDIR)/*.cc) $(wildcard $(SRCDIR)/bip39/*.cc)
CSOURCES = $(wildcard $(SRCDIR)/*.c)

# define objects
OBJECTS = $(CUSOURCES:.cu=.o) $(CPPSOURCES:.cc=.o) $(CSOURCES:.c=.o)

# define executables
AUTOEXEC = auto.out
TESTEXEC = test.out

# compile objects
%.o: %.cu
	$(CXX) $(COPT) $(CXXFLAGS) $(GENCODE_FLAGS) --maxrregcount $(MAXREG) \
		-DBLOCK_DIM=$(BLOCKDIM) -DNONCES_PER_ITER=$(WORKSPACE) $< -o $@
%.o: %.cc
	$(CXX) $(COPT) $(CXXFLAGS) $(EMBED) $< -o $@
%.o: %.c
	$(CXX) $(COPT) $(CFLAGS) $< -o $@

# default (miner executable)
all: clean lib autoexec
	@if ! [ -e "config.json" ]; then \
		echo $(CONFIG) > config.json; \
		echo "Stub config.json was generated"; \
	fi

# test executable
test: clean lib testexec 

# lib
lib: $(OBJECTS)
	mkdir -p ./lib;
	$(AR) rc $(LIBPATH) $(OBJECTS)
	ranlib $(LIBPATH)

# miner executable if lib made
autoexec:
	$(CXX) $(SRCDIR)/autolykos.cu $(LIBPATH) $(LIBS) $(COPT) $(STD) \
		$(GENCODE_FLAGS) -DBLOCK_DIM=$(BLOCKDIM) \
		-DNONCES_PER_ITER=$(WORKSPACE) -o $(AUTOEXEC)

# test executable if lib made
testexec: 
	$(CXX) $(SRCDIR)/test.cu $(LIBPATH) $(LIBS) $(COPT) $(STD) \
		$(GENCODE_FLAGS) -DBLOCK_DIM=$(BLOCKDIM) \
		-DNONCES_PER_ITER=$(WORKSPACE) -o $(TESTEXEC)

# kill them all
clean:
	rm -f $(OBJECTS) $(SRCDIR)/autolykos.o $(SRCDIR)/test.o $(LIBPATH) \
		$(TESTEXEC) $(AUTOEXEC)

.PHONY: all autoexec clean lib test testexec
