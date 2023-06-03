CC = g++
CFLAGS = -Wall
LDFLAGS = -lssl -lcrypto
SRC = secure_chat_app.cpp
TARGET = secure_chat_app

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET)
