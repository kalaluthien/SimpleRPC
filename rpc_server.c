#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include "common.h"

#define LOG_ENABLE
#define LOCK_PREFIX "lock; "
#define ENDL "\n\t"

static FILE *db;
static int rlock;
static int glock;
static int count;

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

void parse_argument(int argc, char *argv[]);
void get_host_status();
char *read_rpc(int *keyp);
void write_rpc(struct wb *blockp);

int main(int argc, char *argv[]) {
  parse_argument(argc, argv);
#ifdef LOG_ENABLE
  get_host_status();
#endif

  if (registerrpc(TEST_PROG, TEST_VERS, TEST_RDOP, read_rpc,
                  (xdrproc_t) xdr_int, (xdrproc_t) xdr_read) < 0) {
    fprintf(stderr, "registering read_rpc faild\n");
    exit(EXIT_FAILURE);
  }

  if (registerrpc(TEST_PROG, TEST_VERS, TEST_WROP, write_rpc,
                  (xdrproc_t) xdr_write, (xdrproc_t) xdr_void) < 0) {
    fprintf(stderr, "registering write_rpc faild\n");
    exit(EXIT_FAILURE);
  }

  svc_run();

  fprintf(stderr, "Error: svc_run returned\n");
  return 0;
}

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

char *read_rpc(int *keyp) {
  static char buffer[DATA_SIZE];
  int key = *keyp;

#ifdef LOG_ENABLE
  printf("read_rpc(%d) requested\n", key);
#endif

  read_aquire();

  int offset = key * (sizeof(int) + sizeof(char) * DATA_SIZE) + sizeof(int);
  fseek(db, offset, SEEK_SET);
  fread(buffer, sizeof(char), DATA_SIZE, db);

  read_release();

#ifdef LOG_ENABLE
  printf("read_rpc(%d) returned\n", key);
#endif

  return buffer;
}

void write_rpc(struct wb *blockp) {
  int key = blockp->key;
  char *buffer = blockp->data;

#ifdef LOG_ENABLE
  printf("write_rpc(%d) requested\n", key);
#endif

  write_aquire();

  int offset = key * (sizeof(int) + sizeof(char) * DATA_SIZE) + sizeof(int);
  fseek(db, offset, SEEK_SET);
  fwrite(buffer, sizeof(char), DATA_SIZE, db);

  write_release();

#ifdef LOG_ENABLE
  printf("write_rpc(%d) retured\n", key);
#endif
}
