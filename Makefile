CC = gcc

SERVER_DEFINES = -DLOG_ENABLE

CFLAGS = -g -Wall -O2
LDFLAGS = -lm -lssl -lcrypto

BIN_DIR = bin

all: rpc_server rpc_client

rpc_server: rpc_server.c
	mkdir -p $(BIN_DIR)
	$(CC) $(SERVER_DEFINES) $(CFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

rpc_client: rpc_client.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

clean:
	rm bin/rpc_server bin/rpc_client

reset:
	git fetch && git reset --hard origin/master
