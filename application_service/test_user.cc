#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "certifier.pb.h"
#include <mutex>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

int main(int an, char**av) {
  string enclave("application-enclave");
  string id("1");

  printf("num args: %d\n", an);
  for (int i = 0; i < an; i++) {
    printf("argv[%d]: %s\n", i, av[i]);
  }
  printf("\n");
  int in_fd = 5;
  int out_fd = 8;
  if (an >= 2) {
    in_fd = atoi(av[an - 2]);
    out_fd = atoi(av[an - 1]);
  }

  // In general, at this point the app should subtract 2 from an.
  //    (an, av) will then have the original arguments for the call.

  //  This is the Init call you would make early in an
  //    application_enclave application.
  //  After that, the application uses normal certifier calls
  //    (as below).  Normally, you'd have a Certifier Service
  //    associated with a security domain and you would have
  //    embedded a policy key and carry out the same procedure
  //    illustrated in the sample_app.  This is just a test
  //    program to make sure the primitives work.
  string parent_enclave_type("simulated-enclave");
  if (!application_Init(parent_enclave_type, in_fd, out_fd)) {
    printf("Can't init application-enclave\n");
    return 1;
  }

  printf("test_user.exe is running on (%d, %d)\n", in_fd, out_fd);

  string secret("abc");
  int out_size = 128;
  byte out[out_size];
  string sealed;
  string unsealed;

  printf("secret  : ");
  print_bytes((int)secret.size(), (byte*)secret.data());
  printf("\n");
 
  int t_out = out_size; 
  if (!Seal(enclave, id, (int)secret.size(), (byte*)secret.data(), &t_out, out)) {
    printf("Application seal failed\n");
    return 1;
  }
  sealed.assign((char*)out, t_out);

  printf("sealed  : ");
  print_bytes((int)sealed.size(), (byte*)sealed.data());
  printf("\n");

  t_out = out_size; 
  if (!Unseal(enclave, id, (int)sealed.size(), (byte*)sealed.data(), &t_out, out)) {
    printf("Application unseal failed\n");
    return 1;
  }
  unsealed.assign((char*)out, t_out);

  printf("unsealed: ");
  print_bytes((int)unsealed.size(), (byte*)unsealed.data());
  printf("\n");

  printf("\ntest_user.exe succeeded\n");
  return 0;
}
