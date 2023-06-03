CC = g++
CFLAGS = -Wall
LDFLAGS = -lssl -lcrypto
SRC = secure_chat_interceptor.cpp
TARGET = secure_chat_interceptor

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)
