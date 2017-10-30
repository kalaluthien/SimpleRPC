CC = gcc

DEFINES = -DREAD_MODE
# DEFINES = -DREAD_MODE
# DEFINES = -DWRITE_MODE

CFLAGS = -g -Wall -O2 $(DEFINES)
LDFLAGS = -lm

all: rpc_server rpc_client

rpc_server: rpc_server.c
	$(CC) $(CFLAGS) $< -o $@

rpc_client: rpc_client.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm rpc_server rpc_client
