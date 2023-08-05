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

#include <certifier_framework.h>
#include <certifier_utilities.h>

using namespace certifier::framework;
using namespace certifier::utilities;

int main(int an, char **av) {
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
  int    out_size = 16000;
  byte   out[out_size];
  string sealed;
  string unsealed;
  string attest;

  // Seal test
  printf("secret  : ");
  print_bytes((int)secret.size(), (byte *)secret.data());
  printf("\n");
  int t_out = out_size;
  if (!Seal(enclave,
            id,
            (int)secret.size(),
            (byte *)secret.data(),
            &t_out,
            out)) {
    printf("Application seal failed\n");
    return 1;
  }
  sealed.assign((char *)out, t_out);
  printf("sealed  : ");
  print_bytes((int)sealed.size(), (byte *)sealed.data());
  printf("\n");

  // Unseal test
  t_out = out_size;
  if (!Unseal(enclave,
              id,
              (int)sealed.size(),
              (byte *)sealed.data(),
              &t_out,
              out)) {
    printf("Application unseal failed\n");
    return 1;
  }
  unsealed.assign((char *)out, t_out);
  printf("unsealed: ");
  print_bytes((int)unsealed.size(), (byte *)unsealed.data());
  printf("\n");

  // GetPlatformStatement test
  t_out = out_size;
  string other_enclave("application-enclave");
  if (!GetPlatformStatement(other_enclave, id, &t_out, out)) {
    printf("Application getplatformstatement failed\n");
    return 1;
  }
  signed_claim_message sc;
  if (t_out > 0) {
    string ser_sc;
    ser_sc.assign((char *)out, t_out);
    sc.ParseFromString(ser_sc);
    printf("Platform claim:\n");
    print_signed_claim(sc);
    printf("\n");
  }

  // Attest test
  t_out = out_size;
  const int what_to_say_size = 20;
  byte      what_to_say[what_to_say_size] = {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  };
  if (!Attest(enclave, what_to_say_size, what_to_say, &t_out, out)) {
    printf("Application attest failed\n");
    return 1;
  }
  attest.assign((char *)out, t_out);
  printf("attest  : ");
  print_bytes((int)attest.size(), (byte *)attest.data());
  printf("\n");

  printf("\ntest_user.exe succeeded\n");
  return 0;
}
