# SimpleRPC
simple rpc server &amp; client implementation in C for DIP homework

# Usage
## Parameters
All parameters are defined in 'common.h'.
Record size for each entry is defined as DATA_SIZE.
Record number for entire file is defined as DB_COUNT.

## Server
```
./rpc_server simple.db
```

## Client
fix 'Makefile' to select read/write mode. (Using -D define macro)
```
./rpc_client <hostname> <trace10000s.txt|trace10000r.txt>
```
