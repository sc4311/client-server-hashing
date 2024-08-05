CC = gcc
CFLAGS = -Wall -Wextra
TARGET = server client  

all: $(TARGET)

server: server.c
	$(CC) $(CFLAGS) -o $@ $^ 

client: client.c sha256_lib.o
	$(CC) $(CFLAGS) -o $@ $^ 

sha256_lib.o: sha256_lib.c sha256_lib.h
	$(CC) $(CFLAGS) -c sha256_lib.c

clean:
	rm -f $(TARGET) *.o