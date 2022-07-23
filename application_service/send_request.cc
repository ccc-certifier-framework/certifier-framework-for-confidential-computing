#include <support.h>
#include <gflags/gflags.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8127, "port for application requests");
DEFINE_string(executable, "hello_world.exe", "executable to run");

int main(int an, char**av) {
  run_request req;
  run_response rsp;

 // dial service
  struct sockaddr_in address;
  memset((byte*)&address, 0, sizeof(struct sockaddr_in));
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return 1;
  }
  struct hostent* he = gethostbyname(FLAGS_server_app_host.c_str());
  if (he == nullptr) {
    return 1;
  }
  memcpy(&(address.sin_addr.s_addr), he->h_addr, he->h_length);
  address.sin_family = AF_INET;
  address.sin_port = htons(FLAGS_server_app_port);
  if(connect(sock,(struct sockaddr *) &address, sizeof(address)) != 0) {
    return 1;
  }

  req.set_location(FLAGS_executable);
  string serialized_request;
  if (!req.SerializeToString(&serialized_request)) {
    return 1;
  }
  // write request
  if (write(sock, (byte*)serialized_request.data(), serialized_request.size()) < 0) {
    return 1;
  }

  // read response
  int size_response_buf = 32000;
  byte response_buf[size_response_buf];
  int n = read(sock, response_buf, size_response_buf);
  if (n < 0) {
     printf("Can't read response\n");
    return 1;
  }

  string serialized_response;
  serialized_response.assign((char*)response_buf, n);
  if (!rsp.ParseFromString(serialized_response)) {
    printf("Can't parse response\n");
    return 1;
  }
  printf("Return: %s\n", rsp.status().c_str());
  return 0;
}
