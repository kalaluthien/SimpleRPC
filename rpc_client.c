#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <rpc/rpc.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include "common.h"

#define PROGRESS_BAR "##################################################"

/* RPC function prototypes */
void parse_input(int argc, char *argv[]);
CLIENT *connect_server(char *host);
void print_stats();
void read_clnt(CLIENT *clnt, char *buffer, int key);
void write_clnt(CLIENT *clnt, char *buffer, int key);

/* Crypto function prototypes */
void set_crypto_scheme();
void init_buffer(char *buffer, int key);
void check_buffer(char *buffer, int key);
void none_setup();
void none_encrypt(char *data);
void none_decrypt(char *data);
void des_setup();
void des_encrypt(char *data);
void des_decrypt(char *data);
void three_des_setup();
void three_des_encrypt(char *data);
void three_des_decrypt(char *data);

/* Statistics global variables */
static double sum_of_response_time;
static double sum_of_response_time_sqare;
static double sum_of_encryption_time;
static double sum_of_encryption_time_sqare;
static double sum_of_decryption_time;
static double sum_of_decryption_time_sqare;

/* RPC global variables */
static struct timeval time_out = { .tv_sec = 10L, .tv_usec = 0L };
static int request_keys[DB_COUNT];
static int request_count;


/* Crypto global variables */
enum CRYPTO_SCHEME { CS_NONE, CS_DES, CS_3_DES, CS_AES, CS_DH, CS_RSA };
void (*setcrypt)(void);
void (*encrypt)(char *);
void (*decrypt)(char *);

int main(int argc, char *argv[]) {
  int i, progress_percent, num_done;
  double progress_ratio;
  char buf[DATA_SIZE];

  parse_input(argc, argv);

  CLIENT *clnt = connect_server(argv[1]);

  set_crypto_scheme(CS_DES);
  setcrypt();

  for (i = 0; i < request_count; i++) {
    usleep(100000);

#ifdef READ_MODE
    read_clnt(clnt, buf, request_keys[i]);

    decrypt(buf);
    check_buffer(buf, request_keys[i]);
#elif WRITE_MODE
    init_buffer(buf, request_keys[i]);
    encrypt(buf);

    write_clnt(clnt, buf, request_keys[i]);
#endif

    progress_ratio = (double) (i + 1) / request_count;
    progress_percent = (int) (progress_ratio * 100);
    num_done = progress_percent / 2;
    printf("\r%3d%% [%.*s%*s]",
           progress_percent, num_done, PROGRESS_BAR, 50 - num_done, "");
    fflush(stdout);
  }

  clnt_destroy(clnt);

  print_stats();

  return 0;
}

void parse_input(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: ./rpc_client hostname tracefile\n");
    exit(EXIT_FAILURE);
  }

  FILE *trace_fp = fopen(argv[2], "r");

  int record_key, record_size;
  while (fscanf(trace_fp, "%d %d", &record_key, &record_size) != EOF) {
    request_keys[request_count++] = record_key;
    if (DATA_SIZE != record_size) {
      fprintf(stderr, "reqested data size unavailable\n");
      exit(EXIT_FAILURE);
    }
  }

  printf("trace file (%s) parsed\n", argv[2]);

  fclose(trace_fp);
}

CLIENT *connect_server(char *host) {
  CLIENT *clnt;
  if ((clnt = clnt_create(host, TEST_PROG, TEST_VERS, "udp")) == NULL) {
    fprintf(stderr, "Error: clnt_create faild\n");
    exit (EXIT_FAILURE);
  }

  struct sockaddr_in sa;
  if (clnt_control(clnt, CLGET_SERVER_ADDR, (char *) &sa) == 0) {
    fprintf(stderr, "Error: clnt_control faild\n");
    exit (EXIT_FAILURE);
  }

  unsigned int ip = sa.sin_addr.s_addr;
  unsigned int port = sa.sin_port;

  printf("connected with %s as %u.%u.%u.%u:%u\n",
         host,
         ip % 0x100,
         ip / 0x100 % 0x100,
         ip / 0x10000 % 0x100,
         ip / 0x1000000 % 0x100,
         port);

  return clnt;
}

void print_stats() {
  double mean_response_time = sum_of_response_time / request_count;
  double var_response_time =
    (sum_of_response_time_sqare / request_count - mean_response_time * mean_response_time);

  double mean_encryption_time = sum_of_encryption_time / request_count;
  double var_encryption_time =
    (sum_of_encryption_time_sqare / request_count - mean_encryption_time * mean_encryption_time);

  double mean_decryption_time = sum_of_decryption_time / request_count;
  double var_decryption_time =
    (sum_of_decryption_time_sqare / request_count - mean_decryption_time * mean_decryption_time);

  printf("\n\n");

  printf("mean resopnse time = %.3lf us\n", mean_response_time * 1000000);
  printf("standatd deviation = %.3lf us\n\n", sqrt(var_response_time) * 1000000);

  printf("mean encryption time = %.3lf us\n", mean_encryption_time * 1000000);
  printf("standatd deviation = %.3lf us\n\n", sqrt(var_encryption_time) * 1000000);

  printf("mean decryption time = %.3lf us\n", mean_decryption_time * 1000000);
  printf("standatd deviation = %.3lf us\n\n", sqrt(var_decryption_time) * 1000000);
}

void read_clnt(CLIENT *clnt, char *buffer, int key) {

  clock_t time_begin = clock();
  enum clnt_stat stat = clnt_call(clnt, TEST_RDOP,
                                  (xdrproc_t) xdr_int, (char *) &key,
                                  (xdrproc_t) xdr_read, buffer, time_out);
  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: read_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}

void write_clnt(CLIENT *clnt, char *buffer, int key) {
  struct wb block;
  block.key = key;
  memcpy(block.data, buffer, sizeof(char) * DATA_SIZE);

  clock_t time_begin = clock();
  enum clnt_stat stat = clnt_call(clnt, TEST_WROP,
                                  (xdrproc_t) xdr_write, (char *) &block,
                                  (xdrproc_t) xdr_void, NULL, time_out);
  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: write_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}

void set_crypto_scheme(enum CRYPTO_SCHEME crypto_scheme) {
  switch (crypto_scheme) {
    case CS_DES:
      setcrypt = des_setup;
      encrypt = des_encrypt;
      decrypt = des_decrypt;
      break;

    case CS_3_DES:
      setcrypt = three_des_setup;
      encrypt = three_des_encrypt;
      decrypt = three_des_decrypt;
      break;

    case CS_NONE: default:
      setcrypt = none_setup;
      encrypt = none_encrypt;
      decrypt = none_decrypt;
      break;
  }
}

void init_buffer(char *buffer, int key) {
  srand(key + 2);

  int i;
  for (i = 0; i < DATA_SIZE; i++) {
    buffer[i] = rand() % ('Z' - 'A') + 'A';
  }
}

void check_buffer(char *buffer, int key) {
  srand(key + 2);

  int i, rand_val;
  for (i = 0; i < DATA_SIZE; i++) {
    rand_val = rand() % ('Z' - 'A') + 'A';
    if (buffer[i] != rand_val) {
      fprintf(stderr, "Error: decryption verification faild\n");
      exit(EXIT_FAILURE);
    }
  }
}

void none_setup() { }

void none_encrypt(char *data) { }

void none_decrypt(char *data) { }

static DES_cblock des_key[2] = {
  { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
  { 0x76, 0x98, 0xBA, 0x32, 0x10, 0xFE, 0xDC, 0x54 }
};
static DES_key_schedule des_keysched[2];

void des_setup() {
  static int is_already_set = 0;

  if (is_already_set++ > 0) {
    fprintf(stderr, "Error: DES setup called twice\n");
    exit(EXIT_FAILURE);
  }

  DES_set_key(&des_key[0], &des_keysched[0]);
}

void des_encrypt(char *data) {
  DES_cblock *in = (DES_cblock *) data;
  DES_cblock *out = (DES_cblock *) malloc(DATA_SIZE);

  if (DATA_SIZE % sizeof(DES_cblock) != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  int i;
  for (i = 0; i < DATA_SIZE / sizeof(DES_cblock); i++) {
    DES_ecb_encrypt(&in[i], &out[i], &des_keysched[0], DES_ENCRYPT);
  }

  double encryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_encryption_time += encryption_time;
  sum_of_encryption_time_sqare += encryption_time * encryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void des_decrypt(char *data) {
  DES_cblock *in = (DES_cblock *) data;
  DES_cblock *out = (DES_cblock *) malloc(DATA_SIZE);

  if (DATA_SIZE % sizeof(DES_cblock) != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  int i;
  for (i = 0; i < DATA_SIZE / sizeof(DES_cblock); i++) {
    DES_ecb_encrypt(&in[i], &out[i], &des_keysched[0], DES_DECRYPT);
  }

  double decryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_decryption_time += decryption_time;
  sum_of_decryption_time_sqare += decryption_time * decryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void three_des_setup() {
  static int is_already_set = 0;

  if (is_already_set++ > 0) {
    fprintf(stderr, "Error: DES setup called twice\n");
    exit(EXIT_FAILURE);
  }

  DES_set_key(&des_key[0], &des_keysched[0]);
  DES_set_key(&des_key[1], &des_keysched[1]);
}

void three_des_encrypt(char *data) {
  DES_cblock *in = (DES_cblock *) data;
  DES_cblock *out = (DES_cblock *) malloc(DATA_SIZE);

  if (DATA_SIZE % sizeof(DES_cblock) != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  int i;
  for (i = 0; i < DATA_SIZE / sizeof(DES_cblock); i++) {
    DES_ecb2_encrypt(&in[i], &out[i], &des_keysched[0], &des_keysched[1], DES_ENCRYPT);
  }

  double encryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_encryption_time += encryption_time;
  sum_of_encryption_time_sqare += encryption_time * encryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void three_des_decrypt(char *data) {
  DES_cblock *in = (DES_cblock *) data;
  DES_cblock *out = (DES_cblock *) malloc(DATA_SIZE);

  if (DATA_SIZE % sizeof(DES_cblock) != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  int i;
  for (i = 0; i < DATA_SIZE / sizeof(DES_cblock); i++) {
    DES_ecb2_encrypt(&in[i], &out[i], &des_keysched[0], &des_keysched[1], DES_DECRYPT);
  }

  double decryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_decryption_time += decryption_time;
  sum_of_decryption_time_sqare += decryption_time * decryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}
