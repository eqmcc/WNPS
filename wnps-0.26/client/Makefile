CC 	= gcc
CFLAGS 	= -w -O2

.c.o:	$(CC) $(CFLAGS) \
	-c -o $*.o $<
OBJS = interface.o client.o socket.o
	
client: $(OBJS)
	$(CC) -o client $(OBJS)
clean:
	rm -f client *.o
