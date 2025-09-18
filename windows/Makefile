CC = x86_64-w64-mingw32-gcc
CFLAGS = -shared -O2 -Wall -Wextra
LDFLAGS = -ladvapi32 -lkernel32 -luser32
SRC = bypass.c
TARGET = bypass.dll

all: $(TARGET)

$(TARGET): $(SRC)
$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

install: $(TARGET)
cp $(TARGET) lib/

clean:
rm -f $(TARGET) *.o

.PHONY: all install clean
