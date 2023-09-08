#include <gflags/gflags.h>

#include <gflags/gflags.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "certifier_utilities.h"

using namespace certifier::utilities;

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8127, "port for application requests");
DEFINE_string(executable, "service_example_app.exe", "executable to run");
DEFINE_string(args, "service_example_app.exe", "service example arguments");

#define DEBUG


bool parse_args(const string &in, int *num_an, string *av) {
  // for now, just assume commas can only be delimiters
  const char *start = in.c_str();
  const char *end = start;

  *num_an = 0;
  while (end != nullptr) {
    if (*start == '\"') {
      start++;
      end++;
    }
    if (*end == ',' || *end == '\0') {
      if (*(end - 1) == '\"') {
        av[*num_an].assign(start, end - start - 1);
      } else {
        av[*num_an].assign(start, end - start);
      }
      av[*num_an].append('\0', 1);
      (*num_an)++;
      if (*end == '\0')
        return true;
      end++;
      start = end;
    }
    end++;
  }

  return true;
}

void print_run_request(run_request &r) {
  if (r.has_location()) {
    printf("Executable: %s\n", r.location().c_str());
  }
  for (int i = 0; i < r.args_size(); i++) {
    printf("  arg[%d]: %s\n", i, r.args(i).c_str());
  }
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  run_request  req;
  run_response rsp;


  // Set executable
  printf("Executable: %s\n", FLAGS_executable.c_str());
  req.set_location(FLAGS_executable);

  // Set flags
  const int max_args = 15;
  int       num_args = max_args;
  string    s_args[max_args];
  if (!parse_args(FLAGS_args, &num_args, s_args)) {
    printf("Can't parse argument list\n");
    num_args = 0;
  }

  // req.args
  for (int i = 0; i < num_args; i++) {
    string *n_a = req.add_args();
    n_a->assign(s_args[i]);
  }

#ifdef DEBUG
  printf("\n%d args\n", num_args);
  print_run_request(req);
  printf("\n");
#endif

  // dial service
  struct sockaddr_in address;
  memset((byte *)&address, 0, sizeof(struct sockaddr_in));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return 1;
  }
  struct hostent *he = gethostbyname(FLAGS_server_app_host.c_str());
  if (he == nullptr) {
    return 1;
  }
  memcpy(&(address.sin_addr.s_addr), he->h_addr, he->h_length);
  address.sin_family = AF_INET;
  address.sin_port = htons(FLAGS_server_app_port);
  if (connect(sock, (struct sockaddr *)&address, sizeof(address)) != 0) {
    return 1;
  }

  // write request
  string serialized_request;
  if (!req.SerializeToString(&serialized_request)) {
    return 1;
  }
  if (sized_socket_write(sock,
                         serialized_request.size(),
                         (byte *)serialized_request.data())
      < 0) {
    return 1;
  }

  // read response
  string serialized_response;
  int    n = sized_socket_read(sock, &serialized_response);
  if (n < 0) {
    printf("Can't read response\n");
    return 1;
  }

  if (!rsp.ParseFromString(serialized_response)) {
    printf("Can't parse response\n");
    return 1;
  }
  printf("Return: %s\n", rsp.status().c_str());
  return 0;
}
