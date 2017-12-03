CC = gcc

SERVER_DEFINES = -DLOG_ENABLE
CLIENT_READ_DEFINES = -DREAD_MODE
CLIENT_WRITE_DEFINES = -DWRITE_MODE

CFLAGS = -g -Wall -O2
LDFLAGS = -lm -lssl -lcrypto

BIN_DIR = bin

all: rpc_server rpc_client_read rpc_client_write

rpc_server: rpc_server.c
	mkdir -p $(BIN_DIR)
	$(CC) $(SERVER_DEFINES) $(CFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

rpc_client_read: rpc_client.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CLIENT_READ_DEFINES) $(CFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

rpc_client_write: rpc_client.c
	mkdir -p $(BIN_DIR)
	$(CC) $(CLIENT_WRITE_DEFINES) $(CFLAGS) $< -o $(BIN_DIR)/$@ $(LDFLAGS)

clean:
	rm rpc_server rpc_client_read rpc_client_write

reset:
	git fetch && git reset --hard origin/master
