CC = gcc
CFLAGS = -pipe --std=gnu99 -ggdb -Wall -pedantic
LDFLAGS = -lpcap -lcrypto -lpthread
SOURCES = main.c mask.c capture.c handler.c util.c crypto.c client.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = bkdoor

all : $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE) : $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@
	#sudo chown root:root $(EXECUTABLE)
	#sudo chmod +s $(EXECUTABLE)

.c.o :
	$(CC) $(CFLAGS) -c $< -o $@

clean :
	rm -f $(EXECUTABLE) $(OBJECTS)
