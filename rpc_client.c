#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <rpc/rpc.h>
#include "common.h"

void parse_input(int argc, char *argv[]);
void print_stats();
void sleep_req(int ms);

void read_clnt(char *host, char *buffer, int key);
void write_clnt(char *host, char *buffer, int key);

double laytancy_sum;
int req_keys[DB_COUNT];
int req_count;

int main(int argc, char *argv[]) {
  char buf[DATA_SIZE];

  parse_input(argc, argv);

  int i;
  for (i = 0; i < req_count; i++) {
    sleep_req(100);
#ifdef READ_MODE
    read_clnt(argv[1], buf, req_keys[i]);
#elif WRITE_MODE
    write_clnt(argv[1], buf, req_keys[i]);
#else
#endif
  }

  print_stats();
  return 0;
}

void parse_input(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: ./rpc_client hostname tracefile\n");
    exit(EXIT_FAILURE);
  }

  FILE *trace_fp = fopen(argv[2], "r");

  int rec_key, rec_size;
  while (fscanf(trace_fp, "%d %d", &rec_key, &rec_size) != EOF) {
    req_keys[req_count++] = rec_key;
    if (DATA_SIZE != rec_size) {
      fprintf(stderr, "reqested data size unavailable\n");
      exit(EXIT_FAILURE);
    }
  }

  fclose(trace_fp);
}

void print_stats() {
  double mean_response_time = laytancy_sum / req_count;
  printf("mean resopnse time = %.6lf ms\n", mean_response_time * MS);
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
  laytancy_sum += (double) (clock() - time_begin) / CLOCKS_PER_SEC;

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
  laytancy_sum += (double) (clock() - time_begin) / CLOCKS_PER_SEC;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: write_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}
