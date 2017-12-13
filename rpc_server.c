#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <rpc/rpc.h>

#include <openssl/dh.h>
#include <openssl/pem.h>

#include "common.h"

/* personal LOCK implementation in intel x86_64 */
static int rlock;
static int glock;
static int count;

#define LOCK_PREFIX "lock; "
#define ENDL "\n\t"

#define read_aquire() \
do { \
  __asm__ __volatile__( \
    "L_aquire_read%=:" ENDL \
    LOCK_PREFIX "bts $0, %0" ENDL \
    "jc L_aquire_read%=" ENDL \
    "" \
    "addl $1, %2" ENDL \
    "cmp $1, %2" ENDL \
    "jne L_after_global%=" ENDL \
    "" \
    "L_aquire_global%=:" ENDL \
    LOCK_PREFIX "bts $0, %1" ENDL \
    "jc L_aquire_global%=" ENDL \
    "" \
    "L_after_global%=:" \
    "movl $0, %0" ENDL \
    : "+m"(rlock), "+m"(glock), "+m"(count) \
  ); \
} while(0)

#define read_release() \
do { \
  __asm __volatile__( \
    "L_aquire_read%=:" ENDL \
    LOCK_PREFIX "bts $0, %0" ENDL \
    "jc L_aquire_read%=" ENDL \
    "" \
    "subl $1, %2" ENDL \
    "cmp $0, %2" ENDL \
    "jne L_after_global%=" ENDL \
    "movl $0, %1" ENDL \
    "" \
    "L_after_global%=:" \
    "movl $0, %0" ENDL \
    : "+m"(rlock), "+m"(glock), "+m"(count) \
  ); \
} while(0)

#define write_aquire() \
do { \
  __asm__ __volatile__( \
    "L_aquire_read%=:" ENDL \
    LOCK_PREFIX "bts $0, %0" ENDL \
    "jc L_aquire_read%=" ENDL \
    "" \
    "L_aquire_global%=:" ENDL \
    LOCK_PREFIX "bts $0, %1" ENDL \
    "jc L_aquire_global%=" ENDL \
    : "+m"(rlock), "+m"(glock) \
  ); \
} while(0)

#define write_release() \
do { \
  __asm __volatile__( \
    "movl $0, %1" ENDL \
    "movl $0, %0" ENDL \
    : "+m"(rlock), "+m"(glock) \
  ); \
} while(0)


/* Utility function prototypes */
void parse_argument(int argc, char *argv[]);
void get_host_status();

/* RPC function prototypes */
struct read_out_block *read_rpc(struct read_in_block *blockp);
void write_rpc(struct write_in_block *blockp);
struct handshake_block *handshake_rpc(struct handshake_block *blockp);


/* RPC global variables */
static FILE *db;


int main(int argc, char *argv[]) {
  parse_argument(argc, argv);
#ifdef LOG_ENABLE
  get_host_status();
#endif

  if (registerrpc(TEST_PROG, TEST_VERS, TEST_RDOP, read_rpc,
                  (xdrproc_t) xdr_read_in, (xdrproc_t) xdr_read_out) < 0) {
    fprintf(stderr, "registering read_rpc faild\n");
    exit(EXIT_FAILURE);
  }

  if (registerrpc(TEST_PROG, TEST_VERS, TEST_WROP, write_rpc,
                  (xdrproc_t) xdr_write_in, (xdrproc_t) xdr_void) < 0) {
    fprintf(stderr, "registering write_rpc faild\n");
    exit(EXIT_FAILURE);
  }

  if (registerrpc(TEST_PROG, TEST_VERS, TEST_HSOP, handshake_rpc,
                  (xdrproc_t) xdr_handshake, (xdrproc_t) xdr_handshake) < 0) {
    fprintf(stderr, "registering handshake_rpc faild\n");
    exit(EXIT_FAILURE);
  }

  svc_run();

  fprintf(stderr, "Error: svc_run returned\n");
  return 0;
}

/* Utility functions */
void parse_argument(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: ./rpc_server filename\n");
    exit(EXIT_FAILURE);
  }

  if ((db = fopen(argv[1], "r+")) == NULL) {
    fprintf(stderr, "Error: faild to open \"%s\" as db\n", argv[1]);
    exit(EXIT_FAILURE);
  }
}

void get_host_status() {
  char host_name[HOST_LEN];
  struct hostent *host_entry;

  if (gethostname(host_name, sizeof(host_name)) < 0) {
    fprintf(stderr, "Error: gethostname faild\n");
    exit(EXIT_FAILURE);
  }

  printf("hostname is \"%s\"\n", host_name);

  if ((host_entry = gethostbyname(host_name)) == NULL) {
    fprintf(stderr, "Error: gethostbyname faild\n");
    exit(EXIT_FAILURE);
  }

  struct in_addr **addr_list = (struct in_addr **) host_entry->h_addr_list;
  while (*addr_list != NULL) {
    printf("* %s\n", inet_ntoa(**addr_list++));
  }
}

/* RPC functions */
struct read_out_block *read_rpc(struct read_in_block *blockp) {
  static struct read_out_block block;

#ifdef LOG_ENABLE
  printf("read_rpc(%d, %d) requested\n", blockp->key, blockp->size);
#endif

  read_aquire();

  int offset = blockp->key * (sizeof(int) + sizeof(char) * ENTRY_SIZE) + sizeof(int);
  fseek(db, offset, SEEK_SET);
  block.size = fread(block.data, sizeof(char), blockp->size, db);

  read_release();

#ifdef LOG_ENABLE
  printf("read_rpc(%d, %d) returned\n", blockp->key, block.size);
#endif

  return &block;
}

void write_rpc(struct write_in_block *blockp) {
#ifdef LOG_ENABLE
  printf("write_rpc(%d, %d) requested\n", blockp->key, blockp->size);
#endif

  write_aquire();

  int offset = blockp->key * (sizeof(int) + sizeof(char) * ENTRY_SIZE) + sizeof(int);
  fseek(db, offset, SEEK_SET);
  fwrite(blockp->data, sizeof(char), blockp->size, db);

  write_release();

#ifdef LOG_ENABLE
  printf("write_rpc(%d, %d) retured\n", blockp->key, blockp->size);
#endif
}

struct handshake_block *handshake_rpc(struct handshake_block *blockp) {
#ifdef LOG_ENABLE
  printf("handshake_rpc(%d) requested\n", blockp->size);
#endif

  static struct handshake_block block;

  FILE *fpem = fopen("dh1024.pem", "r");

  DH *dh_server = PEM_read_DHparams(fpem, NULL, NULL, NULL);
  DH_generate_key(dh_server);

  unsigned char *dh_key = (unsigned char *) malloc(DH_size(dh_server));
  BIGNUM *client_pub_key = BN_new();
  BN_bin2bn(blockp->data, blockp->size, client_pub_key);

  DH_compute_key(dh_key, client_pub_key, dh_server);

  BN_free(client_pub_key);
  free(dh_key);
  fclose(fpem);

  block.size = BN_bn2bin(dh_server->pub_key, block.data);

#ifdef LOG_ENABLE
  printf("handshake_rpc(%d) returned\n", block.size);
#endif

  return &block;
}
