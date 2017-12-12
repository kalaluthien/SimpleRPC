#ifndef __RPC_COMMON_H__
#define __RPC_COMMON_H__

#include <openssl/bn.h>

#define HOST_LEN 64

#define DATA_SIZE 1024
#define DB_COUNT 10000

#define TEST_PROG ((unsigned long) 0x20000001)
#define TEST_VERS ((unsigned long) 0x01)
#define TEST_RDOP ((unsigned long) 0x01)
#define TEST_WROP ((unsigned long) 0x02)
#define TEST_HSOP ((unsigned long) 0x03)

struct wb {
  int key;
  char data[DATA_SIZE];
};

struct hb {
  unsigned char data[DATA_SIZE];
  int size;
};


bool_t xdr_read(XDR *xdrs, char *buffer) {
  return xdr_vector(xdrs, buffer, DATA_SIZE,
                    sizeof(char), (xdrproc_t) xdr_char);
}

bool_t xdr_write(XDR *xdrs, struct wb *blockp) {
  if (xdr_int(xdrs, &blockp->key) == 0) {
    return 0;
  }

  return xdr_vector(xdrs, blockp->data, DATA_SIZE,
                    sizeof(char), (xdrproc_t) xdr_char);
}

bool_t xdr_handshake(XDR *xdrs, struct hb *blockp) {
  return xdr_vector(xdrs, blockp->data, blockp->size,
                    sizeof(unsigned char), (xdrproc_t) xdr_u_char);
}

#endif
