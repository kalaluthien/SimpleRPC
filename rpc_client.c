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
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "common.h"

#define PROGRESS_BAR "##################################################"
#define MAGIC 137
#define RSA_EXP 65537

/* Utility function prototypes */
void parse_input(int argc, char *argv[]);
void print_stats();
void reset_stats();
void print_buffer(char *buffer, int size);

/* RPC function prototypes */
CLIENT *connect_server(char *host);
void read_clnt(CLIENT *clnt, char *buffer, int key);
void write_clnt(CLIENT *clnt, char *buffer, int key);

/* Crypto function prototypes */
void set_crypto_scheme();
void init_buffer(char *buffer, int key);
void check_buffer(char *buffer, int key);

void none_setup(CLIENT *clnt);
void none_encrypt(char *data);
void none_decrypt(char *data);

void des_setup(CLIENT *clnt);
void des_encrypt(char *data);
void des_decrypt(char *data);

void tdes_setup(CLIENT *clnt);
void tdes_encrypt(char *data);
void tdes_decrypt(char *data);

void aes_setup(CLIENT *clnt);
void aes_encrypt(char *data);
void aes_decrypt(char *data);

void dh_handshake(CLIENT *clnt);

void rsa_setup(CLIENT *clnt);
void rsa_encrypt(char *data);
void rsa_decrypt(char *data);


/* Statistics global variables */
static double sum_of_response_time;
static double sum_of_response_time_sqare;

static double sum_of_cryption_time;
static double sum_of_cryption_time_sqare;

static double handshake_time;

/* RPC global variables */
static struct timeval time_out = { .tv_sec = 10L, .tv_usec = 0L };
static int request_keys[DB_COUNT];
static int request_count;
static int entry_size = DATA_SIZE;

/* Crypto scheme */
enum CRYPTO_SCHEME { CS_NONE, CS_DES, CS_TDES, CS_AES, CS_RSA };
const char *crypto_name[] = {
  "None", "DES", "3-DES", "AES", "RSA"
};

/* Crypto fuction pointers */
static void (*setcrypt)(CLIENT *);
static void (*encrypt)(char *);
static void (*decrypt)(char *);

/* Crypto global variables */
static DES_cblock des_key[2] = {
  { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
  { 0x76, 0x98, 0xBA, 0x32, 0x10, 0xFE, 0xDC, 0x54 }
};
static DES_key_schedule des_keysched[2];

static unsigned char aes_cipher_key[AES_BLOCK_SIZE] = {
  0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};
static unsigned char iv_aes[AES_BLOCK_SIZE] = {
  0xCD, 0x67, 0xEF, 0x01, 0xAB, 0x89, 0x23, 0x45,
  0xDC, 0x76, 0xFE, 0x10, 0xBA, 0x98, 0x23, 0x54
};
static AES_KEY aes_key[2];

static unsigned char *dh_key;

static RSA *rsa_public_key;
static RSA *rsa_private_key;


int main(int argc, char *argv[]) {
  int i, progress_percent, num_done;
  double progress_ratio;
  char buf[DATA_SIZE];

  parse_input(argc, argv);

  CLIENT *clnt = connect_server(argv[1]);

  set_crypto_scheme(CS_AES);
  setcrypt(clnt);

  printf("%s start (WRITE MODE)\n", crypto_name[CS_AES]);

  for (i = 0; i < request_count; i++) {
    usleep(100000);

    init_buffer(buf, request_keys[i]);

    encrypt(buf);

    write_clnt(clnt, buf, request_keys[i]);

    progress_ratio = (double) (i + 1) / request_count;
    progress_percent = (int) (progress_ratio * 100);
    num_done = progress_percent / 2;
    printf("\r%3d%% [%.*s%*s]", progress_percent, num_done, PROGRESS_BAR, 50 - num_done, "");
    fflush(stdout);
  }

  print_stats();
  reset_stats();

  printf("\n%s start (READ MODE)\n", crypto_name[CS_AES]);

  for (i = 0; i < request_count; i++) {
    usleep(100000);

    read_clnt(clnt, buf, request_keys[i]);

    decrypt(buf);

    check_buffer(buf, request_keys[i]);

    progress_ratio = (double) (i + 1) / request_count;
    progress_percent = (int) (progress_ratio * 100);
    num_done = progress_percent / 2;
    printf("\r%3d%% [%.*s%*s]", progress_percent, num_done, PROGRESS_BAR, 50 - num_done, "");
    fflush(stdout);
  }

  clnt_destroy(clnt);

  return 0;
}


/* Util functions */
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

void print_stats() {
  double mean_response_time = sum_of_response_time / request_count;
  double var_response_time =
    (sum_of_response_time_sqare / request_count - mean_response_time * mean_response_time);

  double mean_cryption_time = sum_of_cryption_time / request_count;
  double var_cryption_time =
    (sum_of_cryption_time_sqare / request_count - mean_cryption_time * mean_cryption_time);

  printf("\n\n");

  printf("mean resopnse time = %.3lf us\n", mean_response_time * 1000000);
  printf("standatd deviation = %.3lf us\n\n", sqrt(var_response_time) * 1000000);

  printf("mean cryption time = %.3lf us\n", mean_cryption_time * 1000000);
  printf("standatd deviation = %.3lf us\n\n", sqrt(var_cryption_time) * 1000000);

  printf("handshake time = %.3lf us\n", handshake_time * 1000000);
}

void reset_stats() {
  sum_of_response_time = 0.0;
  sum_of_response_time_sqare = 0.0;

  sum_of_cryption_time = 0.0;
  sum_of_cryption_time_sqare = 0.0;

  handshake_time = 0.0;
}


/* RPC functions */
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

void read_clnt(CLIENT *clnt, char *buffer, int key) {
  struct read_in_block rib;
  struct read_out_block rob;

  rib.key = key;
  rib.size = entry_size;

  clock_t time_begin = clock();

  enum clnt_stat stat = clnt_call(clnt, TEST_RDOP,
                                  (xdrproc_t) xdr_read_in, (char *) &rib,
                                  (xdrproc_t) xdr_read_out, (char *) &rob,
                                  time_out);

  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: read_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }

  memcpy(buffer, rob.data, rob.size);
}

void write_clnt(CLIENT *clnt, char *buffer, int key) {
  struct write_in_block wib;

  wib.key = key;
  wib.size = entry_size;
  memcpy(wib.data, buffer, wib.size);

  clock_t time_begin = clock();

  enum clnt_stat stat = clnt_call(clnt, TEST_WROP,
                                  (xdrproc_t) xdr_write_in, (char *) &wib,
                                  (xdrproc_t) xdr_void, NULL,
                                  time_out);

  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: write_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}


/* Crypto functions */
void set_crypto_scheme(enum CRYPTO_SCHEME crypto_scheme) {
  switch (crypto_scheme) {
    case CS_DES:
      setcrypt = des_setup;
      encrypt = des_encrypt;
      decrypt = des_decrypt;
      break;

    case CS_TDES:
      setcrypt = tdes_setup;
      encrypt = tdes_encrypt;
      decrypt = tdes_decrypt;
      break;

    case CS_AES:
      setcrypt = aes_setup;
      encrypt = aes_encrypt;
      decrypt = aes_decrypt;
      break;

    case CS_RSA:
      setcrypt = rsa_setup;
      encrypt = rsa_encrypt;
      decrypt = rsa_decrypt;
      break;

    case CS_NONE: default:
      setcrypt = none_setup;
      encrypt = none_encrypt;
      decrypt = none_decrypt;
      break;
  }
}

void init_buffer(char *buffer, int key) {
  srand(key + MAGIC);

  int i;
  for (i = 0; i < DATA_SIZE; i++) {
    buffer[i] = rand() % ('Z' - 'A') + 'A';
  }
}

void check_buffer(char *buffer, int key) {
  srand(key + MAGIC);

  int i, rand_val;
  for (i = 0; i < DATA_SIZE; i++) {
    rand_val = rand() % ('Z' - 'A') + 'A';
    if (buffer[i] != rand_val) {
      fprintf(stderr, "Error: decryption verification faild\n");
      exit(EXIT_FAILURE);
    }
  }
}

void print_buffer(char *buffer, int size) {
  int i;

  printf("[");

  for (i = 0; i < size; i++) {
    printf("%c", buffer[i]);
  }

  printf("]\n");
}


void none_setup(CLIENT *clnt) { /* Do nothing */ }

void none_encrypt(char *data) { /* Do nothing */ }

void none_decrypt(char *data) { /* Do nothing */ }

void des_setup(CLIENT *clnt) {
  static int is_already_set = 0;
  entry_size = DATA_SIZE;

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

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

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

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void tdes_setup(CLIENT *clnt) {
  static int is_already_set = 0;
  entry_size = DATA_SIZE;

  if (is_already_set++ > 0) {
    fprintf(stderr, "Error: DES setup called twice\n");
    exit(EXIT_FAILURE);
  }

  DES_set_key(&des_key[0], &des_keysched[0]);
  DES_set_key(&des_key[1], &des_keysched[1]);
}

void tdes_encrypt(char *data) {
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

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void tdes_decrypt(char *data) {
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

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void aes_setup(CLIENT *clnt) {
  dh_handshake(clnt);

  int i;
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    aes_cipher_key[i] = dh_key[i];
  }

  entry_size = DATA_SIZE;

  AES_set_encrypt_key(aes_cipher_key, 128, &aes_key[0]);
  AES_set_decrypt_key(aes_cipher_key, 128, &aes_key[1]);
}

void aes_encrypt(char *data) {
  unsigned char *in = (unsigned char *) data;
  unsigned char *out = (unsigned char *) malloc(DATA_SIZE);

  if (DATA_SIZE % AES_BLOCK_SIZE != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  AES_cbc_encrypt(in, out, DATA_SIZE, &aes_key[0], iv_aes, AES_ENCRYPT);

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void aes_decrypt(char *data) {
  unsigned char *in = (unsigned char *) data;
  unsigned char *out = (unsigned char *) malloc(DATA_SIZE);

  if (DATA_SIZE % AES_BLOCK_SIZE != 0) {
    fprintf(stderr, "Error: data size invalid (%d)\n", DATA_SIZE);
    exit(EXIT_FAILURE);
  }

  clock_t time_begin = clock();

  AES_cbc_encrypt(in, out, DATA_SIZE, &aes_key[1], iv_aes, AES_DECRYPT);

  double cryption_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_cryption_time += cryption_time;
  sum_of_cryption_time_sqare += cryption_time * cryption_time;

  memcpy(in, out, DATA_SIZE);
  free(out);
}

void dh_handshake(CLIENT *clnt) {
  struct handshake_block block;

  clock_t time_begin = clock();

  FILE *fpem = fopen("dh1024.pem", "r");

  DH *dh_client = PEM_read_DHparams(fpem, NULL, NULL, NULL);
  DH_generate_key(dh_client);

  memset(block.data, 0, sizeof(block.data));
  block.size = BN_num_bytes(dh_client->pub_key);

  if (block.size != BN_bn2bin(dh_client->pub_key, block.data)) {
    fprintf(stderr, "Error: dh block size invalid\n");
    exit(EXIT_FAILURE);
  }

  enum clnt_stat stat = clnt_call(clnt, TEST_HSOP,
                                  (xdrproc_t) xdr_handshake, (char *) &block,
                                  (xdrproc_t) xdr_handshake, (char *) &block,
                                  time_out);

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: dh_setup faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }

  BIGNUM *server_pub_key = BN_new();
  BN_bin2bn(block.data, block.size, server_pub_key);

  dh_key = (unsigned char *) malloc(DH_size(dh_client));
  DH_compute_key(dh_key, server_pub_key, dh_client);

  BN_free(server_pub_key);
  fclose(fpem);

  handshake_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
}

void rsa_setup(CLIENT *clnt) {
  entry_size = DATA_SIZE;
  rsa_private_key = RSA_generate_key(DATA_SIZE, RSA_EXP, NULL, NULL);

  unsigned char *n_bin = (unsigned char *) malloc(RSA_size(rsa_private_key));
  unsigned char *e_bin = (unsigned char *) malloc(RSA_size(rsa_private_key));

  int n_size = BN_bn2bin(rsa_private_key->n, n_bin);
  int e_size = BN_bn2bin(rsa_private_key->e, e_bin);

  rsa_public_key = RSA_new();

  rsa_public_key->n = BN_bin2bn(n_bin, n_size, NULL);
  rsa_public_key->e = BN_bin2bn(e_bin, e_size, NULL);
}

void rsa_encrypt(char *data) {
}

void rsa_decrypt(char *data) {
}
