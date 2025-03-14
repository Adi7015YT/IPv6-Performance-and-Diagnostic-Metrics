# Makefile for DNS PDM BPF programs

# Compiler and flags
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CFLAGS := -g -O2 -Wall -target bpf -I/usr/include/$(shell uname -m)-linux-gnu

# Source and output files
SRC_DIR := src
OBJ_DIR := obj
HEADER_DIR := include

SRCS := $(SRC_DIR)/dns_request_handler.c $(SRC_DIR)/dns_response_handler.c
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Targets
all: dirs $(OBJS)

dirs:
	mkdir -p $(SRC_DIR) $(OBJ_DIR) $(HEADER_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

load: all
	sudo ./load.sh

unload:
	sudo ./unload.sh

.PHONY: all clean load unload dirs