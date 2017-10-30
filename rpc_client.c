#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <rpc/rpc.h>
#include "common.h"

void parse_input(int argc, char *argv[]);
void print_stats();
void sleep_req(int ms);

void read_clnt(char *host, char *buffer, int key);
void write_clnt(char *host, char *buffer, int key);

double sum_of_response_time;
double sum_of_response_time_sqare;
int request_keys[DB_COUNT];
int request_count;

int main(int argc, char *argv[]) {
  char buf[DATA_SIZE];

  parse_input(argc, argv);

  int i;
  for (i = 0; i < request_count; i++) {
    sleep_req(100);
#ifdef READ_MODE
    read_clnt(argv[1], buf, request_keys[i]);
#elif WRITE_MODE
    write_clnt(argv[1], buf, request_keys[i]);
#else
#endif
    if (i % (request_keys / 20) == 0) {
      printf("*");
      fflush(stdout);
    }
  }
  printf(" done!\n");

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

  fclose(trace_fp);
}

void print_stats() {
  double mean_response_time = sum_of_response_time / request_count;
  double var_response_time =
    (sum_of_response_time_sqare / request_count - mean_response_time * mean_response_time);

  printf("mean resopnse time = %.4lf ns\n", mean_response_time * 1000000);
  printf("standatd deviation = %.4lf ns\n", sqrt(var_response_time) * 1000000);
}

void sleep_req(int ms) {
  static struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000;
  nanosleep(&ts, NULL);
}

void read_clnt(char *host, char *buffer, int key) {
  clock_t time_begin = clock();
  enum clnt_stat stat = callrpc(host, TEST_PROG, TEST_VERS, TEST_RDOP,
                                (xdrproc_t) xdr_int, (const char *) &key,
                                (xdrproc_t) xdr_read, buffer);
  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: read_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}

void write_clnt(char *host, char *buffer, int key) {
  struct wb block;
  block.key = key;
  memcpy(block.data, buffer, sizeof(char) * DATA_SIZE);

  clock_t time_begin = clock();
  enum clnt_stat stat = callrpc(host, TEST_PROG, TEST_VERS, TEST_WROP,
                                (xdrproc_t) xdr_write, (const char *) &block,
                                (xdrproc_t) xdr_void, NULL);
  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: write_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}
