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

//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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

DEFINE_bool(help_me, false, "Want help?");
DEFINE_bool(cold_init_service, false, "Start over");

DEFINE_bool(print_all, false,  "verbose");
DEFINE_bool(print_log, false,  "print log");
DEFINE_string(log_file_name, "service.log", "service log file");

DEFINE_string(policy_cert_file, "policy_cert_file.bin", "policy_cert");
DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");

DEFINE_string(service_dir, "./service/", "directory for service data");
DEFINE_string(service_policy_store, "policy_store.bin", "policy store for service");

DEFINE_string(server_app_host, "localhost", "address for application requests");
DEFINE_int32(server_app_port, 8127, "port for application requests");

DEFINE_string(run_policy, "all", "what programs to run");  // "signed" is other possibility
DEFINE_string(host_enclave_type, "simulated-enclave", "Primary enclave");

// For simulated enclave only
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement, "platform_attest_endorsement.bin", "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "app_service.measurement", "measurement");

DEFINE_string(guest_login_name, "jlm", "guest name");

//#define DEBUG

// ---------------------------------------------------------------------------------

#include "policy_key.cc"

class spawned_children {
public:
  bool valid_;
  string app_name_;
  string location_;
  string measurement_;
  int pid_;
  int parent_read_fd_;
  int parent_write_fd_;
  std::thread * thread_obj_;
  spawned_children* next_;
};

std::mutex kid_mtx;
spawned_children* my_kids = nullptr;

spawned_children* new_kid() {
  spawned_children* nk = new(spawned_children);
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

spawned_children* find_kid(int pid) {
  kid_mtx.lock();
  spawned_children* k = my_kids;
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
  spawned_children* k = my_kids;
  while (k != nullptr) {
    if (k->next_ == nullptr)
      break;
    if (k->next_->pid_ == pid) {
      spawned_children* to_remove = k->next_;
      k->next_ = to_remove->next_;
      delete to_remove;
      break;
    }
    k = k->next_;
  }
  kid_mtx.unlock();
}

bool measure_binary(const string& file, string* m) {
  int size = file_size(file.c_str());
  if (size <= 0) {
    printf("Can't get executable file\n");
    return false;
  }
  byte* file_contents = (byte*)malloc(size);
  int bytes_read = size;
  if (!read_file(file, &bytes_read, file_contents) || bytes_read < size) {
    printf("Executable read failed\n");
    free(file_contents);
    return false;
  }
  byte digest[32];
  unsigned int len = 32;
  if (!digest_message("sha256", file_contents, bytes_read,
          digest, len)) {
    printf("Digest failed\n");
    free(file_contents);
    return false;
  }
  m->assign((char*)digest, (int)len);
  free(file_contents);
  return true;
}

bool measure_in_mem_binary(byte* file_contents, int size, string* m) {
  byte digest[32];
  unsigned int len = 32;
  if (!digest_message("sha256", file_contents, (unsigned) size,
          digest, len)) {
    printf("Digest failed\n");
    return false;
  }
  m->assign((char*)digest, (int)len);
  return true;
}

void delete_child(int signum) {
    int pid = wait(nullptr);
    spawned_children* c = find_kid(pid);
    if (c->thread_obj_ != nullptr) {
      delete c->thread_obj_;
    }
    // close parent fds/
    remove_kid(pid);
}

// ---------------------------------------------------------------------------------

// The support functions use the helper object
//    This is just a reference, object is local to main
cc_trust_data* app_trust_data = nullptr;


bool soft_Seal(spawned_children* kid, string in, string* out) {
#ifdef DEBUG
  printf("soft_Seal\n");
#endif

  string buffer_to_seal;
  buffer_to_seal.assign(kid->measurement_.data(), kid->measurement_.size());
  buffer_to_seal.append(in.data(), in.size());

  int t_size = buffer_to_seal.size() + 128;
  byte t_out[t_size];

  byte iv[16];
  if (!get_random(8 * 16, iv)) {
    return false;
  }
  if (!authenticated_encrypt((byte*)buffer_to_seal.data(), buffer_to_seal.size(),
        app_trust_data->service_symmetric_key_, iv, t_out, &t_size)) {
    printf("soft_Seal: authenticated encrypt failed\n");
    return false;
  }
  out->assign((char*)t_out, t_size);
  return true;
}

bool soft_Unseal(spawned_children* kid, string in, string* out) {
#ifdef DEBUG
  printf("soft_Unseal\n");
#endif

  int t_size = in.size();
  byte t_out[t_size];

  if (!authenticated_decrypt((byte*)in.data(), in.size(), app_trust_data->service_symmetric_key_,
            t_out, &t_size)) {
    printf("soft_Unseal: authenticated decrypt failed\n");
    return false;
  }
#ifdef DEBUG
  printf("Unsealed  : ");
  print_bytes(t_size, t_out);
  printf("\n");
  printf("Measurment: ");
  print_bytes(kid->measurement_.size(), (byte*)kid->measurement_.data());
  printf("\n");
#endif
  if (memcmp(t_out, (byte*)kid->measurement_.data(),
      kid->measurement_.size()) != 0) {
    printf("soft_Unseal: mis-matched measurements\n");
    return false;
  }
  out->assign((char*)&t_out[kid->measurement_.size()],
        t_size - kid->measurement_.size());
  return true;
}

bool soft_Attest(spawned_children* kid, string in, string* out) {
#ifdef DEBUG
  printf("soft_Attest\n");
#endif

  // in  is a serialized vse-attestation
  if (!app_trust_data->cc_service_key_initialized_) {
    printf("soft_Attest: service key not initialized\n");
    return false;
  }

#if 0
  claim_message cm;
  string nb, na;
  time_point tn, tf;
  if (!time_now(&tn))
    return false;
  if (!add_interval_to_time_point(tn, 24.0 * 365.0, &tf))
    return false;
  if (!time_to_string(tn, &nb))
    return false;
  if (!time_to_string(tf, &na))
    return false;
  string cf("vse-attestation");
  string desc("");
  if (!make_claim(in.size(), (byte*)in.data(), cf, desc,
        nb, na, &cm)) {
    printf("soft_Attest: error 1\n");
    return false;
  }
  string ser_cm;
  if (!cm.SerializeToString(&ser_cm)) {
    printf("soft_Attest: error 2\n");
    return false;
  }

  signed_claim_message scm;
  if (!make_signed_claim("rsa-2048-sha256-pkcs-sign", cm, app_trust_data->private_service_key_, &scm)) {
    printf("soft_Attest: Signing failed\n");
    return false;
  }
  if (!scm.SerializeToString(out)) {
    printf("soft_Attest: Serialize failed\n");
    return false;
  }
#else
  vse_attestation_report_info report_info;
  string serialized_report_info;
  report_info.set_enclave_type("application-enclave");

  string nb, na;
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
  report_info.set_user_data((byte*)in.data(), in.size());
  report_info.set_verified_measurement((byte*)kid->measurement_.data(),
    kid->measurement_.size());
  if (!report_info.SerializeToString(&serialized_report_info)) {
    return false;
  }

  const string type("vse-attestation-report");
  string signing_alg;

  if (app_trust_data->private_service_key_.key_type() == "rsa-2048-private") {
    signing_alg.assign("rsa-2048-sha256-pkcs-sign");
  } else if (app_trust_data->private_service_key_.key_type() == "rsa-4096-private") {
    signing_alg.assign("rsa-4096-sha384-pkcs-sign");
  } else if (app_trust_data->private_service_key_.key_type() == "ecc-384-private") {
    signing_alg.assign("ecc-384-sha384-pkcs-sign");
  } else {
    return false;
  }

  if (!sign_report(type, serialized_report_info,
      signing_alg, app_trust_data->private_service_key_, out)) {
    printf("Can't sign report\n");
    return false;
  }
#endif

  return true;
}

bool soft_GetPlatformStatement(spawned_children* kid, string* out) {
#ifdef DEBUG
  printf("soft_GetPlatformStatement\n");
#endif
  if (!app_trust_data->cc_service_platform_rule_initialized_) {
    printf("soft_GetPlatformStatement: not initialized\n");
    return false;
  }
  app_trust_data->platform_rule_.SerializeToString(out);
  return true;
}

bool soft_GetParentEvidence(spawned_children* kid, string* out) {
#ifdef DEBUG
  printf("soft_GetPlatformStatement\n");
#endif
  if (!app_trust_data->cc_service_platform_rule_initialized_) {
    printf("soft_GetPlatformStatement: not initialized\n");
    return false;
  }
  app_trust_data->platform_rule_.SerializeToString(out);
  return true;
}

bool soft_Getmeasurement(spawned_children* kid, string* out) {
#ifdef DEBUG
  printf("soft_Getmeasurement\n");
#endif
  out->assign(kid->measurement_.data(), kid->measurement_.size());
  return true;
}

void app_service_loop(spawned_children* kid, int read_fd, int write_fd) {
  bool continue_loop = true;

#ifdef DEBUG
  printf("\napplication service loop: %d %d\n", read_fd, write_fd);
#endif
  while(continue_loop) {
    bool succeeded = false;
    string in;
    string out;
    string str_app_req;
    int n = sized_pipe_read(read_fd, &str_app_req);
    if (n <= 0) {
      continue;
    }
    app_request req;
    if (!req.ParseFromString(str_app_req)) {
      goto finishreq;
    }

    printf("app_service_loop, service requested: %s\n", req.function().c_str());
    if (req.function() == "seal") {
        in = req.args(0);
        succeeded= soft_Seal(kid, in, &out);
    } else if (req.function() == "unseal") {
        in = req.args(0);
        succeeded= soft_Unseal(kid, in, &out);
    } else if (req.function() == "attest") {
        in = req.args(0);
        succeeded= soft_Attest(kid, in, &out);
    } else if (req.function() == "getmeasurement") {
        succeeded= soft_Getmeasurement(kid, &out);
    } else if (req.function() == "getplatformstatement") {
        succeeded= soft_GetPlatformStatement(kid, &out);
    } else if (req.function() == "getcerts") {
        succeeded= soft_GetParentEvidence(kid, &out);
    }

finishreq:
#ifdef DEBUG
    if (succeeded)
      printf("Service response: succeeded\n");
    else
      printf("Service response: failed\n");
#endif
    app_response rsp;
    string str_app_rsp;
    rsp.set_function(req.function());

    if (succeeded) {
      rsp.set_status("succeeded");
      rsp.add_args(out);
    } else {
      rsp.set_status("failed");
    }
    if (!rsp.SerializeToString(&str_app_rsp)) {
      printf("Can't serialize response\n");
    }
    if (write(write_fd, (byte*)str_app_rsp.data(), str_app_rsp.size()) <
            (int)str_app_rsp.size()) {
      printf("Response write failed\n");
    }
#ifdef DEBUG
    printf("Service loop: ended\n");
#endif
  }
}

bool start_app_service_loop(spawned_children* kid, int read_fd, int write_fd) {
#ifdef DEBUG
  printf("start_app_service_loop\n");
#endif
#ifndef NOTHREAD
  std::thread* t = new std::thread(app_service_loop, kid, read_fd, write_fd);
  kid->thread_obj_ = t;
  t->detach();
#else
  app_service_loop(kid, read_fd, write_fd);
#endif
  return true;
}

#define INMEMEXEC
bool process_run_request(run_request& req) {

  // measure binary
  string m;
#ifndef INMEMEXEC
  if (!req.has_location() || !measure_binary(req.location(), &m)) {
    printf("Can't measure binary\n");
    return false;
  }
#else
  if (!req.has_location()) {
    printf("Program location unspecified\n");
    return false;
  }

  string mem_app_name(req.location());
  mem_app_name.append("_in_mem_app");
  int mem_fd = memfd_create(mem_app_name.c_str(), MFD_CLOEXEC);
  if (mem_fd < 0) {
    printf("Can't create in mem file\n");
    return false;
  }

  int fsz = file_size(req.location());
  byte* file_buffer = (byte*)malloc(fsz);

  if (!read_file(req.location(), &fsz, file_buffer)) {
    printf("Can't read executable\n");
    free(file_buffer);
    close(mem_fd);
    return false;
  }

  // Make sure you read the binary to exec into “buffer”
  if (write(mem_fd, file_buffer, fsz) != fsz) {
    printf("Failed to copy app binary.\n");
    close(mem_fd);
    free(file_buffer);
    return false;
  }

  if (!measure_in_mem_binary(file_buffer, fsz, &m)) {
    printf("Can't measure in_mem binary\n");
    close(mem_fd);
    free(file_buffer);
    return false;
  }
#endif

  int fd1[2];
  int fd2[2];
  if (pipe2(fd1, O_DIRECT) < 0) {
    printf("Pipe 1 failed\n");
    return false;
  }
  if (pipe2(fd2, O_DIRECT) < 0) {
    printf("Pipe 2 failed\n");
    return false;
  }

#ifdef DEBUG
  printf("pipes made %d %d %d %d\n", fd1[0], fd1[1], fd2[0], fd2[1]);
#endif

  // Is this what I want?
  int parent_read_fd = fd2[0];
  int parent_write_fd = fd1[1];
  int child_read_fd = fd1[0];
  int child_write_fd = fd2[1];

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
    struct passwd* ent = getpwnam(FLAGS_guest_login_name.c_str());
    if (ent == nullptr) {
      printf("Guest is not a user\n");
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
    if (setgid(gid) != 0 || setuid (uid) != 0) {
      printf("Can't seettuid\n");
#ifdef INMEMEXEC
      free(file_buffer);
      close(mem_fd);
#endif
      return false;
    }

#ifdef DEBUG
    printf("Child about to exec %s, read: %d, write: %d\n",
        req.location().c_str(), child_read_fd, child_write_fd);
#endif

    string n1 = std::to_string(child_read_fd);
    string n2 = std::to_string(child_write_fd);
    int num_args = req.args_size();
    char **argv = new char*[num_args + 3];
    for (int i = 0; i < num_args; i++) {
      argv[i] = (char*)req.args(i).c_str();
    }
    argv[num_args] = (char*)n1.c_str();
    argv[num_args + 1] = (char*)n2.c_str();
    argv[num_args + 2] = nullptr;

    char *envp[1]= {
      nullptr
    };

#ifndef INMEMEXEC
    if (execve(req.location().c_str(), argv, envp) < 0) {
      printf("Exec failed\n");
      return false;
    }
#else
    if (fexecve(mem_fd, argv, envp) < 0) {
      printf("Exec failed\n");
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
    printf("parent returned, read: %d, write: %d\n", parent_read_fd, parent_write_fd);
#endif

    // add it to lists
    spawned_children* nk = new_kid();
    if (nk == nullptr) {
      printf("Can't add kid\n");
      return false;
    }
    nk->location_ = req.location();
    nk->measurement_.assign((char*)m.data(), m.size());;
    nk->pid_ = pid;
    nk->parent_read_fd_ = parent_read_fd;
    nk->parent_write_fd_ = parent_write_fd;
    nk->valid_ = true;
    if (!start_app_service_loop(nk, parent_read_fd, parent_write_fd)) {
      printf("Couldn't start service loop\n");
      return false;
    }
  }
  return true;
}

bool app_request_server() {
  // This is the TCP server that requests to start
  // protected programs.
  const char* hostname = FLAGS_server_app_host.c_str();
  int port= FLAGS_server_app_port;
  struct sockaddr_in addr;

  struct hostent *he = nullptr;
  if ((he = gethostbyname(hostname)) == NULL) {
    printf("gethostbyname failed\n");
    return false;
  }
  int sd = socket(AF_INET, SOCK_STREAM, 0);
  if (sd < 0) {
    printf("socket call failed\n");
    return false;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(he->h_addr);
  if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    printf("bind failed\n");
    return false;
  }
  if (listen(sd, 10) != 0) {
    printf("listen failed\n");
    return false;
  }

  unsigned int len = 0;
  while (1) {
    printf("application_service server at accept\n");
    struct sockaddr_in addr;
    int client = accept(sd, (struct sockaddr*)&addr, &len);
#ifdef DEBUG
    printf("\nclient: %d\n", client);
#endif

    // read run request
    string str_req;
    int n = sized_pipe_read(client, &str_req);
    if (n < 0) {
      printf("Read failed in application server\n");
      continue;
    }

    // This should be a serialized run_request
    run_request req;
    bool ret = false;
    if (!req.ParseFromString(str_req)) {
      goto done;
    }

    if (FLAGS_run_policy != "all") {
      // Todo: Fix - check certificate?
    }
    printf("at process_run_request: %s\n", req.location().c_str());
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
      if(write(client, (byte*)str_resp.data(), str_resp.size()) < 0) {
        printf("Write failed\n");
      }
    }
    close(client);
  }
  close(sd);
  return true;
}

// ------------------------------------------------------------------------------


// Standard algorithms for the enclave
string public_key_alg("rsa-2048");
string symmetric_key_alg("aes-256");;
string hash_alg("sha-256");
string hmac_alg("sha-256-hmac");


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_help_me) {
    printf("app_service.exe --print_all=true|false --policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --service_dir=-directory-for-service-data --server_service_host=my-server-host-address --server_service_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
    printf("\t --host_enclave_type=\"simulated-enclave\"");
    return 0;
  }

  SSL_library_init();
  string enclave_type("simulated-enclave");
  string purpose("attestation");

  string store_file(FLAGS_service_dir);
  store_file.append(FLAGS_service_policy_store);
  cc_trust_data helper(enclave_type, purpose, store_file);
  app_trust_data = &helper;

  // Init policy key info
  if (!helper.init_policy_key(initialized_cert_size, initialized_cert)) {
    printf("Can't init policy key\n");
    return false;
  }

  if (FLAGS_host_enclave_type == "simulated-enclave") {

    // Init simulated enclave
    string attest_key_file_name(FLAGS_service_dir);
    attest_key_file_name.append(FLAGS_attest_key_file);
    string platform_attest_file_name(FLAGS_service_dir);
    platform_attest_file_name.append(FLAGS_platform_attest_endorsement);
    string measurement_file_name(FLAGS_service_dir);
    measurement_file_name.append(FLAGS_measurement_file);
    string attest_endorsement_file_name(FLAGS_service_dir);
    attest_endorsement_file_name.append(FLAGS_platform_attest_endorsement);

    if (!helper.initialize_simulated_enclave_data(attest_key_file_name,
      measurement_file_name, attest_endorsement_file_name)) {
      printf("Can't init simulated enclave\n");
      return 1;
    }
  } else if (FLAGS_host_enclave_type == "oe-enclave") {
    printf("Unsupported host enclave\n");
    return 1;
  } else if (FLAGS_host_enclave_type == "sev-snp") {
    printf("Unsupported host enclave\n");
    return 1;
  } else {
    printf("Unsupported host enclave\n");
    return 1;
  }

  // initialize and certify service data
  if (FLAGS_cold_init_service || file_size(store_file) <= 0) {
    if (!helper.cold_init(public_key_alg, symmetric_key_alg,
            hash_alg, hmac_alg)) {
      printf("cold-init failed\n");
      return 1;
    }

    if (!helper.certify_me(FLAGS_policy_host, FLAGS_policy_port)) {
        printf("certification failed\n");
        return 1;
      }
  } else  if (!helper.warm_restart()) {
    printf("warm-restart failed\n");
    return 1;
  }

  // run service response
  if (!app_request_server()) {
    printf("Can't run request server\n");
    return 1;
  }

  helper.clear_sensitive_data();
  return 0;
}
