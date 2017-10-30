CC = gcc

DEFINES = -D WRITE_MODE
# DEFINES = -D READ_MODE
# DEFINES = -D WRITE_MODE

CFLAGS = -g -Wall -O2 $(DEFINES)
LDFLAGS = 

all: rpc_server rpc_client

rpc_server: rpc_server.c
	$(CC) $(CFLAGS) $< -o $@

rpc_client: rpc_client.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm rpc_server rpc_client
