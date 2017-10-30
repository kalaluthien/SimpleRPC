#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <rpc/rpc.h>
#include "common.h"

void parse_input(int argc, char *argv[]);
CLIENT *connect_server(char *host);
void print_stats();
void sleep_req(int ms);
void read_clnt(CLIENT *clnt, char *buffer, int key);
void write_clnt(CLIENT *clnt, char *buffer, int key);

static double sum_of_response_time;
static double sum_of_response_time_sqare;
static int request_keys[DB_COUNT];
static int request_count;

struct timeval time_out = { .tv_sec = 1L, .tv_usec = 0L };

int main(int argc, char *argv[]) {
  char buf[DATA_SIZE];

  parse_input(argc, argv);

  CLIENT *clnt = connect_server(argv[1]);

  int i;
  for (i = 0; i < request_count; i++) {
#ifdef READ_MODE
    read_clnt(clnt, buf, request_keys[i]);
#elif WRITE_MODE
    write_clnt(clnt, buf, request_keys[i]);
#else
#endif
    if (i % (request_count / 20) == 0) {
      printf("*");
      fflush(stdout);
    }

    sleep_req(100);
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

  fclose(trace_fp);
}

CLIENT *connect_server(char *host) {
  CLIENT *clnt = clnt_create(host, TEST_PROG, TEST_VERS, "tcp");

  struct sockaddr_in sa;
  if (clnt_control(clnt, CLGET_SERVER_ADDR, (char *) &sa) == 0) {
    fprintf(stderr, "Error: clnt_control faild\n");
    exit (EXIT_FAILURE);
  }

  printf("connected with %s as %u:%hu", host, sa.sin_addr.s_addr, sa.sin_port);

  return clnt;
}

void print_stats() {
  double mean_response_time = sum_of_response_time / request_count;
  double var_response_time =
    (sum_of_response_time_sqare / request_count - mean_response_time * mean_response_time);

  printf("\n\n");
  printf("mean resopnse time = %.3lf us\n", mean_response_time * 1000000);
  printf("standatd deviation = %.3lf us\n", sqrt(var_response_time) * 1000000);
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
  enum clnt_stat stat = clnt_call(clnt, TEST_RDOP,
                                  (xdrproc_t) xdr_int, (char *) &key,
                                  (xdrproc_t) xdr_read, buffer, time_out);
  double response_time = (double) (clock() - time_begin) / CLOCKS_PER_SEC;
  sum_of_response_time += response_time;
  sum_of_response_time_sqare += response_time * response_time;

  if (stat != RPC_SUCCESS) {
    clnt_perrno(stat);
    fprintf(stderr, "Error: write_clnt faild at %d\n", stat);
    exit(EXIT_FAILURE);
  }
}

void sleep_req(int ms) {
  static struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000;
  nanosleep(&ts, NULL);
}
