//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "application_enclave.h"
#include "certifier.pb.h"
#include "cc_helpers.h"
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

#include <pwd.h>
#include <unistd.h>
#include <linux/memfd.h>
#include <sys/mman.h>

using namespace certifier::framework;
using namespace certifier::utilities;

DEFINE_string(parent_enclave, "simulated-enclave", "parent enclave");
DEFINE_bool(help_me, false, "Want help?");
DEFINE_bool(cold_init_service, false, "Start over");

DEFINE_bool(print_all, false, "verbose");
DEFINE_bool(print_log, false, "print log");
DEFINE_string(log_file_name, "service.log", "service log file");

DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy_cert");
DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");

DEFINE_string(service_dir, "./service/", "directory for service data");
DEFINE_string(service_policy_store,
              "policy_store.bin",
              "policy store for service");

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8127, "port for application requests");

DEFINE_string(run_policy,
              "all",
              "what programs to run");  // "signed" is other possibility
DEFINE_string(host_enclave_type, "simulated-enclave", "Primary enclave");

// For simulated enclave only
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "app_service.measurement", "measurement");

DEFINE_string(guest_login_name, "jlm", "guest name");

DEFINE_string(ark_cert_file,
              "./service/milan_ark_cert.der",
              "ark cert file name");
DEFINE_string(ask_cert_file,
              "./service/milan_ask_cert.der",
              "ask cert file name");
DEFINE_string(vcek_cert_file,
              "./service/milan_vcek_cert.der",
              "vcek cert file name");


//#define DEBUG

// ---------------------------------------------------------------------------------

#include "policy_key.cc"

class spawned_children {
 public:
  bool              valid_;
  string            app_name_;
  string            location_;
  string            measurement_;
  int               pid_;
  int               parent_read_fd_;
  int               parent_write_fd_;
  std::thread *     thread_obj_;
  spawned_children *next_;
};

std::mutex        kid_mtx;
spawned_children *my_kids = nullptr;

spawned_children *new_kid() {
  spawned_children *nk = new (spawned_children);
  if (nk == nullptr)
    return nullptr;
  kid_mtx.lock();
  nk->valid_ = false;
  nk->next_ = my_kids;
  nk->thread_obj_ = nullptr;
  my_kids = nk;
  kid_mtx.unlock();
  return nk;
}

spawned_children *find_kid(int pid) {
  kid_mtx.lock();
  spawned_children *k = my_kids;
  while (k != nullptr) {
    if (k->pid_ == pid)
      break;
    k = k->next_;
  }
  kid_mtx.unlock();
  return k;
}

void remove_kid(int pid) {
  kid_mtx.lock();
  if (my_kids == nullptr) {
    kid_mtx.unlock();
    return;
  }
  if (my_kids->pid_ == pid) {
    delete my_kids;
    my_kids = nullptr;
  }
  spawned_children *k = my_kids;
  while (k != nullptr) {
    if (k->next_ == nullptr)
      break;
    if (k->next_->pid_ == pid) {
      spawned_children *to_remove = k->next_;
      k->next_ = to_remove->next_;
      delete to_remove;
      break;
    }
    k = k->next_;
  }
  kid_mtx.unlock();
}

bool measure_binary(const string &file, string *m) {
  int size = file_size(file.c_str());
  if (size <= 0) {
    printf("%s() error, line %d, Can't get executable file %s\n",
           __func__,
           __LINE__,
           file.c_str());
    return false;
  }
  byte *file_contents = (byte *)malloc(size);
  int   bytes_read = size;
  if (!read_file(file, &bytes_read, file_contents) || bytes_read < size) {
    printf("%s() error, line %d, Executable read failed\n", __func__, __LINE__);
    free(file_contents);
    return false;
  }
  byte         digest[32];
  unsigned int len = 32;
  if (!digest_message(Digest_method_sha256,
                      file_contents,
                      bytes_read,
                      digest,
                      len)) {
    printf("%s() error, line %d, Digest failed\n", __func__, __LINE__);
    free(file_contents);
    return false;
  }
  m->assign((char *)digest, (int)len);
  free(file_contents);
  return true;
}

bool measure_in_mem_binary(byte *file_contents, int size, string *m) {
  byte         digest[32];
  unsigned int len = 32;
  if (!digest_message(Digest_method_sha256,
                      file_contents,
                      (unsigned)size,
                      digest,
                      len)) {
    printf("%s() error, line %d, Digest failed\n", __func__, __LINE__);
    return false;
  }
  m->assign((char *)digest, (int)len);
  return true;
}

void delete_child(int signum) {
  int               pid = wait(nullptr);
  spawned_children *c = find_kid(pid);
  if (c->thread_obj_ != nullptr) {
    delete c->thread_obj_;
  }
  // close parent fds/
  remove_kid(pid);
}

// ---------------------------------------------------------------------------------

const int max_pad_size = 128;

// The support functions use the helper object
//    This is just a reference, object is local to main
cc_trust_manager *trust_mgr = nullptr;


bool soft_Seal(spawned_children *kid, string in, string *out) {
#if 1
  printf("soft_Seal\n");
  const char *alg = trust_mgr->symmetric_key_algorithm_.c_str();
  printf("alg: %s\n", trust_mgr->symmetric_key_algorithm_.c_str());
  int ks = cipher_key_byte_size(alg);
  printf("key (%d): ", ks);
  print_bytes(ks, trust_mgr->sealing_key_bytes_);
  printf("\n");
#endif

  string buffer_to_seal;
  buffer_to_seal.assign(kid->measurement_.data(), kid->measurement_.size());
  buffer_to_seal.append(in.data(), in.size());

  int  t_size = buffer_to_seal.size() + max_pad_size;
  byte t_out[t_size];

  byte iv[block_size];
  if (!get_random(8 * block_size, iv)) {
    return false;
  }
  if (!authenticated_encrypt(trust_mgr->symmetric_key_algorithm_.c_str(),
                             (byte *)buffer_to_seal.data(),
                             buffer_to_seal.size(),
                             trust_mgr->sealing_key_bytes_,
                             trust_mgr->max_symmetric_key_size_,
                             iv,
                             block_size,
                             t_out,
                             &t_size)) {
    printf("%s() error, line %d, soft_Seal: authenticated encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  out->assign((char *)t_out, t_size);
  return true;
}

bool soft_Unseal(spawned_children *kid, string in, string *out) {
#if 1
  printf("soft_Unseal\n");
  const char *alg = trust_mgr->symmetric_key_algorithm_.c_str();
  printf("alg: %s\n", trust_mgr->symmetric_key_algorithm_.c_str());
  int ks = cipher_key_byte_size(alg);
  printf("key (%d): ", ks);
  print_bytes(ks, trust_mgr->sealing_key_bytes_);
  printf("\n");
#endif

  int  t_size = in.size();
  byte t_out[t_size];

  if (!authenticated_decrypt(trust_mgr->symmetric_key_algorithm_.c_str(),
                             (byte *)in.data(),
                             in.size(),
                             trust_mgr->sealing_key_bytes_,
                             trust_mgr->max_symmetric_key_size_,
                             t_out,
                             &t_size)) {
    printf("%s() error, line %d, soft_Unseal: authenticated decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
#ifdef DEBUG
  printf("Unsealed  : ");
  print_bytes(t_size, t_out);
  printf("\n");
  printf("Measurment: ");
  print_bytes(kid->measurement_.size(), (byte *)kid->measurement_.data());
  printf("\n");
#endif
  if (memcmp(t_out, (byte *)kid->measurement_.data(), kid->measurement_.size())
      != 0) {
    printf("%s() error, line %d, soft_Unseal: mis-matched measurements\n",
           __func__,
           __LINE__);
    return false;
  }
  out->assign((char *)&t_out[kid->measurement_.size()],
              t_size - kid->measurement_.size());
  return true;
}

bool soft_Attest(spawned_children *kid, string in, string *out) {
#ifdef DEBUG
  printf("soft_Attest\n");
#endif

  // in  is a serialized vse-attestation
  if (!trust_mgr->cc_service_key_initialized_) {
    printf("%s() error, line %d, soft_Attest: service key not initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  vse_attestation_report_info report_info;
  string                      serialized_report_info;
  report_info.set_enclave_type("application-enclave");

  string     nb, na;
  time_point tn, tf;
  if (!time_now(&tn))
    return false;
  if (!add_interval_to_time_point(tn, 24.0 * 365.0, &tf))
    return false;
  if (!time_to_string(tn, &nb))
    return false;
  if (!time_to_string(tf, &na))
    return false;

  report_info.set_not_before(nb);
  report_info.set_not_after(na);
  // in should be a serialized attestation_user_data
  report_info.set_user_data((byte *)in.data(), in.size());
  report_info.set_verified_measurement((byte *)kid->measurement_.data(),
                                       kid->measurement_.size());
  if (!report_info.SerializeToString(&serialized_report_info)) {
    return false;
  }

  const string type("vse-attestation-report");
  string       signing_alg;

  if (trust_mgr->private_service_key_.key_type()
      == Enc_method_rsa_2048_private) {
    signing_alg.assign(Enc_method_rsa_2048_sha256_pkcs_sign);
  } else if (trust_mgr->private_service_key_.key_type()
             == Enc_method_rsa_4096_private) {
    signing_alg.assign(Enc_method_rsa_4096_sha384_pkcs_sign);
  } else if (trust_mgr->private_service_key_.key_type()
             == Enc_method_ecc_384_private) {
    signing_alg.assign(Enc_method_ecc_384_sha384_pkcs_sign);
  } else {
    return false;
  }

  if (!sign_report(type,
                   serialized_report_info,
                   signing_alg,
                   trust_mgr->private_service_key_,
                   out)) {
    printf("%s() error, line %d, Can't sign report\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool soft_GetPlatformStatement(spawned_children *kid, string *out) {
#ifdef DEBUG
  printf("soft_GetPlatformStatement\n");
#endif
  if (!trust_mgr->cc_service_platform_rule_initialized_) {
    printf("%s() error, line %d, soft_GetPlatformStatement: not initialized\n",
           __func__,
           __LINE__);
    return false;
  }
  trust_mgr->platform_rule_.SerializeToString(out);
  return true;
}

bool soft_GetParentEvidence(spawned_children *kid, string *out) {
#ifdef DEBUG
  printf("soft_GetPlatformStatement\n");
#endif
  if (!trust_mgr->cc_service_platform_rule_initialized_) {
    printf("%s() error, line %d, soft_GetPlatformStatement: not initialized\n",
           __func__,
           __LINE__);
    return false;
  }
  trust_mgr->platform_rule_.SerializeToString(out);
  return true;
}

// This Getmeasurement stays
bool soft_Getmeasurement(spawned_children *kid, string *out) {
#ifdef DEBUG
  printf("soft_Getmeasurement\n");
#endif
  out->assign(kid->measurement_.data(), kid->measurement_.size());
  return true;
}

void app_service_loop(spawned_children *kid, int read_fd, int write_fd) {
  bool continue_loop = true;

#ifdef DEBUG
  printf("[%d] Application Service loop: read_fd=%d write_fd=%d\n",
         __LINE__,
         read_fd,
         write_fd);
#endif
  while (continue_loop) {
    bool   succeeded = false;
    string in;
    string out;
    string str_app_req;
    int    n = sized_pipe_read(read_fd, &str_app_req);
    if (n <= 0) {
      continue;
    }
    app_request req;
    if (!req.ParseFromString(str_app_req)) {
      printf("[%d] Request read: %s\n", __LINE__, str_app_req.c_str());
      goto finishreq;
    }

    printf("app_service_loop, service requested: %s\n", req.function().c_str());
    if (req.function() == "seal") {
      in = req.args(0);
      succeeded = soft_Seal(kid, in, &out);
    } else if (req.function() == "unseal") {
      in = req.args(0);
      succeeded = soft_Unseal(kid, in, &out);
    } else if (req.function() == "attest") {
      in = req.args(0);
      succeeded = soft_Attest(kid, in, &out);
    } else if (req.function() == "getmeasurement") {
      succeeded = soft_Getmeasurement(kid, &out);
    } else if (req.function() == "getplatformstatement") {
      succeeded = soft_GetPlatformStatement(kid, &out);
    } else if (req.function() == "getcerts") {
      succeeded = soft_GetParentEvidence(kid, &out);
    }

finishreq:
#ifdef DEBUG
    if (succeeded)
      printf("Service response: succeeded\n");
    else
      printf("Service response: failed\n");
#endif
    app_response rsp;
    string       str_app_rsp;
    rsp.set_function(req.function());

    if (succeeded) {
      rsp.set_status("succeeded");
      rsp.add_args(out);
    } else {
      rsp.set_status("failed");
    }
    if (!rsp.SerializeToString(&str_app_rsp)) {
      printf("%s() error, line %d, Can't serialize response\n",
             __func__,
             __LINE__);
    }
    if (write(write_fd, (byte *)str_app_rsp.data(), str_app_rsp.size())
        < (int)str_app_rsp.size()) {
      printf("Response write failed\n");
    }

#ifdef DEBUG
    printf("Service loop: ended\n");
#endif
  }
}

bool start_app_service_loop(spawned_children *kid, int read_fd, int write_fd) {
#ifdef DEBUG
  printf("\n[%d] %s\n", __LINE__, __func__);
#endif
#ifndef NOTHREAD
  std::thread *t = new std::thread(app_service_loop, kid, read_fd, write_fd);
  kid->thread_obj_ = t;
  t->detach();
#else
  app_service_loop(kid, read_fd, write_fd);
#endif
  return true;
}

#define INMEMEXEC
bool process_run_request(run_request &req) {

  // measure binary
  string m;
#ifndef INMEMEXEC
  if (!req.has_location() || !measure_binary(req.location(), &m)) {
    printf("%s() error, line %d, Can't measure binary\n", __func__, __LINE__);
    return false;
  }
#else
  if (!req.has_location()) {
    printf("%s() error, line %d, Program location unspecified\n",
           __func__,
           __LINE__);
    return false;
  }

  string mem_app_name(req.location());
  mem_app_name.append("_in_mem_app");
  int mem_fd = memfd_create(mem_app_name.c_str(), MFD_CLOEXEC);
  if (mem_fd < 0) {
    printf("%s() error, line %d, Can't create in mem file\n",
           __func__,
           __LINE__);
    return false;
  }

  int   fsz = file_size(req.location());
  byte *file_buffer = (byte *)malloc(fsz);

  if (!read_file(req.location(), &fsz, file_buffer)) {
    printf("%s() error, line %d, Can't read executable\n", __func__, __LINE__);
    free(file_buffer);
    close(mem_fd);
    return false;
  }

  // Make sure you read the binary to exec into “buffer”
  if (write(mem_fd, file_buffer, fsz) != fsz) {
    printf("%s() error, line %d, Failed to copy app binary.\n",
           __func__,
           __LINE__);
    close(mem_fd);
    free(file_buffer);
    return false;
  }

  if (!measure_in_mem_binary(file_buffer, fsz, &m)) {
    printf("%s() error, line %d, Can't measure in_mem binary\n",
           __func__,
           __LINE__);
    close(mem_fd);
    free(file_buffer);
    return false;
  }
#endif

  int fd1[2];
  if (pipe2(fd1, O_DIRECT) < 0) {
    printf("%s() error, line %d, Pipe 1 failed\n", __func__, __LINE__);
    return false;
  }

  int fd2[2];
  if (pipe2(fd2, O_DIRECT) < 0) {
    printf("%s() error, line %d, Pipe 2 failed\n", __func__, __LINE__);
    return false;
  }

  // Is this what I want?
  int parent_read_fd = fd2[0];
  int parent_write_fd = fd1[1];
  int child_read_fd = fd1[0];
  int child_write_fd = fd2[1];

#ifdef DEBUG
  printf("pipes made: fds[]:"
         "  parent_read_fd = %d, parent_write_fd = %d,"
         "  child_read_fd = %d,  child_write_fd = %d\n",
         parent_read_fd,
         parent_write_fd,
         child_read_fd,
         child_write_fd);
#endif

  // fork and get pid
  pid_t pid = fork();
  if (pid < 0) {
    printf("Can't fork\n");
    close(fd1[0]);
    close(fd1[1]);
    close(fd2[0]);
    close(fd2[1]);
    return false;
  } else if (pid == 0) {  // child
    close(parent_read_fd);
    close(parent_write_fd);

    // Change process owner
    struct passwd *ent = getpwnam(FLAGS_guest_login_name.c_str());
    if (ent == nullptr) {
      printf("Login '%s' is not a user\n", FLAGS_guest_login_name.c_str());
#ifdef INMEMEXEC
      free(file_buffer);
      close(mem_fd);
#endif
      return false;
    }
    // Make sure this is not a privileged account?
    uid_t uid = ent->pw_uid;
    gid_t gid = ent->pw_gid;
#ifdef DEBUG
    printf("Changing to gid: %d, uid: %d\n", gid, uid);
#endif
    ent = nullptr;
    if (setgid(gid) != 0 || setuid(uid) != 0) {
      printf("%s() error, line %d, Can't seettuid\n", __func__, __LINE__);
#ifdef INMEMEXEC
      free(file_buffer);
      close(mem_fd);
#endif
      return false;
    }

#ifdef DEBUG
    printf("Child about to exec %s, read: %d, write: %d\n",
           req.location().c_str(),
           child_read_fd,
           child_write_fd);
#endif

    string n1 = std::to_string(child_read_fd);
    string n2 = std::to_string(child_write_fd);
    int    num_args = req.args_size();
    char **argv = new char *[num_args + 3];
    for (int i = 0; i < num_args; i++) {
      argv[i] = (char *)req.args(i).c_str();
    }
    argv[num_args] = (char *)n1.c_str();
    argv[num_args + 1] = (char *)n2.c_str();
    argv[num_args + 2] = nullptr;

    char *envp[1] = {nullptr};

#ifndef INMEMEXEC
    if (execve(req.location().c_str(), argv, envp) < 0) {
      printf("Exec failed\n");
      return false;
    }
#else
    if (fexecve(mem_fd, argv, envp) < 0) {
      printf("%s() error, line %d, Exec failed\n", __func__, __LINE__);
      free(file_buffer);
      close(mem_fd);
      return false;
    }
    free(file_buffer);
    close(mem_fd);
#endif
  } else {  // parent
    signal(SIGCHLD, delete_child);
    // If we close these, reads become non blocking
    //    close(child_read_fd);
    //    close(child_write_fd);

#ifdef DEBUG
    printf("parent returned, readfd=%d, writefd=%d\n",
           parent_read_fd,
           parent_write_fd);
#endif

    // add it to lists
    spawned_children *nk = new_kid();
    if (nk == nullptr) {
      printf("%s() error, line %d, Can't add kid\n", __func__, __LINE__);
      return false;
    }
    nk->location_ = req.location();
    nk->measurement_.assign((char *)m.data(), m.size());
    ;
    nk->pid_ = pid;
    nk->parent_read_fd_ = parent_read_fd;
    nk->parent_write_fd_ = parent_write_fd;
    nk->valid_ = true;
    if (!start_app_service_loop(nk, parent_read_fd, parent_write_fd)) {
      printf("%s() error, line %d, Couldn't start service loop\n",
             __func__,
             __LINE__);
      return false;
    }
  }
  return true;
}

bool app_request_server() {
  // This is the TCP server that requests to start
  // protected programs.
  const char *       hostname = FLAGS_server_app_host.c_str();
  int                port = FLAGS_server_app_port;
  struct sockaddr_in addr;

  struct hostent *he = nullptr;
  if ((he = gethostbyname(hostname)) == NULL) {
    printf("%s() error, line %d, gethostbyname failed\n", __func__, __LINE__);
    return false;
  }
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    printf("%s() error, line %d, socket call failed\n", __func__, __LINE__);
    return false;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(he->h_addr);
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    printf("%s() error, line %d, bind failed\n", __func__, __LINE__);
    return false;
  }
  if (listen(sd, 10) != 0) {
    printf("listen failed\n");
    return false;
  }

  unsigned int len = 0;
  while (1) {
    printf("[%d] application_service server at accept\n", __LINE__);
    struct sockaddr_in addr;
    int                client = accept(sd, (struct sockaddr *)&addr, &len);
#ifdef DEBUG
    printf("\nclient: %d\n", client);
#endif

    // read run request
    string str_req;
    int    n = sized_socket_read(client, &str_req);
    if (n < 0) {
      printf("%s() error, line %d, Read failed in application server\n",
             __func__,
             __LINE__);
      continue;
    }

    // This should be a serialized run_request
    run_request req;
    bool        ret = false;
    if (!req.ParseFromString(str_req)) {
      goto done;
    }

    if (FLAGS_run_policy != "all") {
      // Todo: Fix - check certificate?
    }
    printf("[%d] at process_run_request: %s\n",
           __LINE__,
           req.location().c_str());
    ret = process_run_request(req);

done:
    run_response resp;
    if (ret) {
      resp.set_status("succeeded");
    } else {
      resp.set_status("failed");
    }
    string str_resp;
    if (resp.SerializeToString(&str_resp)) {
      if (sized_socket_write(client, str_resp.size(), (byte *)str_resp.data())
          < (int)str_resp.size()) {
        printf("%s() error, line %d, Write failed\n", __func__, __LINE__);
      }
    }
    close(client);
  }
  close(sd);
  return true;
}

// ------------------------------------------------------------------------------

// Standard algorithms for the enclave
string public_key_alg(Enc_method_rsa_2048);
string symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);


// Parameters for simulated enclave
bool get_simulated_enclave_parameters(string **s, int *n) {

  // serialized attest key, measurement, serialized endorsement, in that order
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_service_dir + FLAGS_attest_key_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_service_dir + FLAGS_measurement_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!read_file_into_string(
          FLAGS_service_dir + FLAGS_platform_attest_endorsement,
          &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    return false;
  }

  *n = 3;
  return true;
}

// General initialization for sev enclave
bool get_sev_enclave_parameters(string **s, int *n) {

  // ark cert file, ask cert file, vcek cert file
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_service_dir + FLAGS_ark_cert_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_service_dir + FLAGS_ask_cert_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!read_file_into_string(FLAGS_service_dir + FLAGS_vcek_cert_file,
                             &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    return false;
  }

  *n = 3;
  return true;
}

// -----------------------------------------------------------------------------------------

int main(int an, char **av) {
  string usage("Application Service utility");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_help_me) {
    printf("\
app_service.exe --print_all=true|false --policy_host=policy-host-address \n\
                --policy_port=policy-host-port \n\
                --service_dir=-directory-for-service-data \n\
                --server_service_host=my-server-host-address \n\
                --server_service_port=server-host-port \n\
                --policy_cert_file=self-signed-policy-cert-file-name \n\
                --policy_store_file=policy-store-file-name \n\
                --host_enclave_type=\"simulated-enclave\"\n");
    return 0;
  }

  SSL_library_init();
  string enclave_type(FLAGS_parent_enclave);
  string purpose("attestation");

  string store_file(FLAGS_service_dir);
  store_file.append(FLAGS_service_policy_store);
  cc_trust_manager helper(enclave_type, purpose, store_file);
  trust_mgr = &helper;

  // Init policy key info
  if (!helper.init_policy_key(initialized_cert, initialized_cert_size)) {
    printf("%s() error, line %d, Can't init policy key\n", __func__, __LINE__);
    return false;
  }

  if (FLAGS_host_enclave_type == "simulated-enclave") {

    // get parameters
    int     n = 0;
    string *params = nullptr;
    if (!get_simulated_enclave_parameters(&params, &n) || params == nullptr) {
      printf("%s() error, line %d, Can't get simulated enclave parameters\n",
             __func__,
             __LINE__);
      return false;
    }

    // Init simulated enclave
    if (!helper.initialize_enclave(n, params)) {
      printf("%s() error, line %d, Can't init simulated enclave\n",
             __func__,
             __LINE__);
      return 1;
    }
    if (params != nullptr) {
      delete[] params;
      params = nullptr;
    }
  } else if (FLAGS_host_enclave_type == "oe-enclave") {
    printf("%s() error, line %d, Unsupported host enclave\n",
           __func__,
           __LINE__);
    return 1;
  } else if (FLAGS_host_enclave_type == "sev-enclave") {

    // get parameters
    int     n = 0;
    string *params = nullptr;
    if (!get_sev_enclave_parameters(&params, &n) || params == nullptr) {
      printf("%s() error, line %d, Can't get simulated enclave parameters\n",
             __func__,
             __LINE__);
      return false;
    }

    // Init sev enclave
    if (!helper.initialize_enclave(n, params)) {
      printf("%s() error, line %d, Can't init sev-enclave\n",
             __func__,
             __LINE__);
      return 1;
    }
    if (params != nullptr) {
      delete[] params;
      params = nullptr;
    }
  } else {
    printf("%s() error, line %d, Unsupported host enclave\n",
           __func__,
           __LINE__);
    return 1;
  }

  // initialize and certify service data
  if (FLAGS_cold_init_service || file_size(store_file) <= 0) {
    if (!helper.cold_init(public_key_alg,
                          symmetric_key_alg,
                          "application_enclave_domain",
                          FLAGS_policy_host,
                          FLAGS_policy_port,
                          FLAGS_server_app_host,
                          FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      return 1;
    }

    if (!helper.certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      return 1;
    }
  } else {
    if (!helper.warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      return 1;
    }
  }

  // run service response
  if (!app_request_server()) {
    printf("%s() error, line %d, Can't run request server\n",
           __func__,
           __LINE__);
    return 1;
  }

  helper.clear_sensitive_data();
  return 0;
}
