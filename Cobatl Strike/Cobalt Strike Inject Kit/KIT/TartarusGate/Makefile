# Makefile

# Variables
SRC_DIR := src
BUILD_DIR := bin
TARGET_ARCH := x86_64-w64-mingw32
CFLAGS := -masm=intel

# Source files
SOURCES := process_inject_spawn.c process_inject_explicit.c

# Object files
OBJECTS := $(SOURCES:%.c=$(BUILD_DIR)/%.x64.o)

# Default rule
all: $(OBJECTS)

# Rule for building .o files from .c files
$(BUILD_DIR)/%.x64.o: $(SRC_DIR)/%.c
	@echo "Compile $<"
	@mkdir -p $(BUILD_DIR)
	@$(TARGET_ARCH)-gcc -c $< -o $@ $(CFLAGS)

# Clean rule
clean:
	@rm -rf $(BUILD_DIR)/*.x64.o