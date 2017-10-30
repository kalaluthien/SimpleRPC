CC = gcc

SERVER_DEFINES = -DLOG_ENABLE
CLIENT_DEFINES = -DREAD_MODE
# CLIENT_DEFINES = -DREAD_MODE
# CLIENT_DEFINES = -DWRITE_MODE

CFLAGS = -g -Wall -O2
LDFLAGS = -lm

all: rpc_server rpc_client

rpc_server: rpc_server.c
	$(CC) $(SERVER_DEFINES) $(CFLAGS) $< -o $@ $(LDFLAGS)

rpc_client: rpc_client.c
	$(CC) $(CLIENT_DEFINES) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm rpc_server rpc_client
