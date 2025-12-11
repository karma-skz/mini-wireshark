# Makefile for cshark - Terminal Packet Sniffer
# Compile: make
# Run: sudo ./cshark
# Clean: make clean

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -O2
LDFLAGS = -lpcap
TARGET = cshark
SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Compile individual object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Force rebuild
rebuild: clean all

# Mark targets as phony
.PHONY: all clean rebuild