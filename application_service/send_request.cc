#include <support.h>
#include <gflags/gflags.h>

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8124, "port for application requests");
DEFINE_string(executable, "hello_world.exe", "executable to run");


int main(int an, char**av) {
  run_request req;
  // send request to run hello world
  return 0;
}
