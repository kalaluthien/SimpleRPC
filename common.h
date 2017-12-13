#ifndef __RPC_COMMON_H__
#define __RPC_COMMON_H__

#include <openssl/bn.h>

#define HOST_LEN 64

#define DATA_SIZE 1024
#define ENTRY_SIZE 2048
#define DB_COUNT 10000

#define TEST_PROG ((unsigned long) 0x20000001)
#define TEST_VERS ((unsigned long) 0x01)
#define TEST_RDOP ((unsigned long) 0x01)
#define TEST_WROP ((unsigned long) 0x02)
#define TEST_HSOP ((unsigned long) 0x03)

struct read_in_block {
  int key;
  int size;
};

struct read_out_block {
  char data[ENTRY_SIZE];
  int size;
};

struct write_in_block {
  char data[ENTRY_SIZE];
  int key;
  int size;
};

struct handshake_block {
  unsigned char data[ENTRY_SIZE];
  int size;
};


bool_t xdr_read_in(XDR *xdrs, struct read_in_block *blockp) {
  if (xdr_int(xdrs, &blockp->key) == 0 || xdr_int(xdrs, &blockp->size) == 0) {
    return 0;
  }

  return 1;
}

bool_t xdr_read_out(XDR *xdrs, struct read_out_block *blockp) {
  if (xdr_int(xdrs, &blockp->size) == 0) {
    return 0;
  }

  return xdr_vector(xdrs, blockp->data, blockp->size,
                    sizeof(char), (xdrproc_t) xdr_char);
}

bool_t xdr_write_in(XDR *xdrs, struct write_in_block *blockp) {
  if (xdr_int(xdrs, &blockp->key) == 0 || xdr_int(xdrs, &blockp->size) == 0) {
    return 0;
  }

  return xdr_vector(xdrs, blockp->data, blockp->size,
                    sizeof(char), (xdrproc_t) xdr_char);
}

bool_t xdr_handshake(XDR *xdrs, struct handshake_block *blockp) {
  if (xdr_int(xdrs, &blockp->size) == 0) {
    return 0;
  }

  return xdr_vector(xdrs, (char *) blockp->data, blockp->size,
                    sizeof(unsigned char), (xdrproc_t) xdr_u_char);
}

#endif
