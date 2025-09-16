# Makefile for Monitoring Agent Bypass Libraries
# Supports both Linux and Windows (cross-compilation)

# Compiler settings
CC_LINUX = gcc
CC_WINDOWS = x86_64-w64-mingw32-gcc
CFLAGS_LINUX = -Wall -O2 -fPIC -shared
CFLAGS_WINDOWS = -Wall -O2 -shared -static-libgcc
LIBS_WINDOWS = -ladvapi32 -lkernel32 -luser32

# Output files
LINUX_TARGET = bypass.so
WINDOWS_TARGET = bypass_windows.dll

# Source files
LINUX_SRC = bypass.c
WINDOWS_SRC = bypass_windows.c

# Default target
all: linux

# Linux target
linux: $(LINUX_TARGET)

$(LINUX_TARGET): $(LINUX_SRC)
	$(CC_LINUX) $(CFLAGS_LINUX) -o $@ $< -ldl

# Windows target (requires MinGW cross-compiler)
windows: $(WINDOWS_TARGET)

$(WINDOWS_TARGET): $(WINDOWS_SRC)
	$(CC_WINDOWS) $(CFLAGS_WINDOWS) -o $@ $< $(LIBS_WINDOWS)

# Check if MinGW is available
check-mingw:
	@which $(CC_WINDOWS) > /dev/null 2>&1 || (echo "MinGW cross-compiler not found. Install with: sudo apt-get install gcc-mingw-w64" && exit 1)

# Clean targets
clean:
	rm -f $(LINUX_TARGET) $(WINDOWS_TARGET)

# Install targets
install-linux: $(LINUX_TARGET)
	@echo "Linux bypass library ready: $(LINUX_TARGET)"

install-windows: check-mingw $(WINDOWS_TARGET)
	@echo "Windows bypass library ready: $(WINDOWS_TARGET)"

# Test targets
test-linux: $(LINUX_TARGET)
	@echo "Testing Linux bypass..."
	@LD_PRELOAD=./$(LINUX_TARGET) getent passwd wazuh 2>/dev/null && echo "✓ Linux bypass working" || echo "✗ Linux bypass not working"

test-windows: $(WINDOWS_TARGET)
	@echo "Windows DLL ready for testing: $(WINDOWS_TARGET)"
	@echo "To test on Windows, run PowerShell script with the DLL present"

# Help
help:
	@echo "Monitoring Agent Bypass Library Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all                 - Build Linux library (default)"
	@echo "  linux               - Build Linux shared library"
	@echo "  windows             - Build Windows DLL (requires MinGW)"
	@echo "  check-mingw         - Check if MinGW cross-compiler is available"
	@echo "  install-linux       - Build and prepare Linux library"
	@echo "  install-windows     - Build and prepare Windows library"
	@echo "  test-linux          - Test Linux bypass functionality"
	@echo "  test-windows        - Prepare Windows DLL for testing"
	@echo "  clean               - Remove built libraries"
	@echo "  help                - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  Linux:   gcc, libc-dev"
	@echo "  Windows: gcc-mingw-w64 (for cross-compilation)"
	@echo ""
	@echo "Examples:"
	@echo "  make linux          # Build for Linux"
	@echo "  make windows        # Build for Windows (requires MinGW)"
	@echo "  make test-linux     # Test Linux functionality"

.PHONY: all linux windows check-mingw clean install-linux install-windows test-linux test-windows help