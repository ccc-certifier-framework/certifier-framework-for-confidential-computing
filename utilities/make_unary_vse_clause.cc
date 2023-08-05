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

// make_unary_vse_clause.exe --key_subject=file --measurement_subject=file
// --platform_subject=file
//    --environment_subject=file --verb="is-trusted" --output=output-file-name

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(output, "simple_clause.bin", "output file");
DEFINE_string(key_subject, "", "key subject file");
DEFINE_string(measurement_subject, "", "measurement subject file");
DEFINE_string(platform_subject, "", "platform subject file");
DEFINE_string(environment_subject, "", "environment subject file");
DEFINE_string(verb, "verb", "verb to use");
DEFINE_string(cert_subject, "", "cert file");

bool get_clause_from_file(const string &in, vse_clause *cl) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_cl[in_size];

  if (!read_file(in, &in_read, serialized_cl)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string cl_str;
  cl_str.assign((char *)serialized_cl, in_size);
  if (!cl->ParseFromString(cl_str)) {
    printf("Can't parse clause\n");
    return false;
  }
  return true;
}

int make_unary_clause_file_utility(entity_message &subject,
                                   const string &  verb,
                                   const string &  output) {

  vse_clause out_cl;
  string     v = verb;
  if (!make_unary_vse_clause(subject, FLAGS_verb, &out_cl)) {
    printf("Can't make clause\n");
    return 1;
  }

  string out_string;
  if (!out_cl.SerializeToString(&out_string)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(output, out_string.size(), (byte *)out_string.data())) {
    printf("Can't write %s\n", output.c_str());
    return 1;
  }

  if (FLAGS_print_all) {
    printf("Clause constructed: ");
    print_vse_clause(out_cl);
    printf("\n");
  }

  print_vse_clause(out_cl);
  printf("\n");
  return 0;
}

bool get_key_from_cert_file(const string &in, key_message *k) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte asn_cert[in_size];

  if (!read_file(in, &in_read, asn_cert)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string cert;
  cert.assign((char *)asn_cert, in_size);
  if (!PublicKeyFromCert(cert, k)) {
    printf("Can't get key from cert\n");
    return false;
  }
  return true;
}

bool get_key_from_file(const string &in, key_message *k) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_key[in_size];

  if (!read_file(in, &in_read, serialized_key)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  key_message kt;
  string      k_str;
  k_str.assign((char *)serialized_key, in_size);
  if (!kt.ParseFromString(k_str)) {
    printf("Can't parse key\n");
    return false;
  }
  return private_key_to_public_key(kt, k);
}

bool get_measurement_entity_from_file(const string &in, entity_message *em) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte m[in_size];

  if (!read_file(in, &in_read, m)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string m_str;
  m_str.assign((char *)m, in_size);
  if (!make_measurement_entity(m_str, em)) {
    printf("Can't make measurement entity\n");
    return false;
  }
  return true;
}

bool get_platform_entity_from_file(const string &in, entity_message *em) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte pfp[in_size];

  if (!read_file(in, &in_read, pfp)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string pfp_str;
  pfp_str.assign((char *)pfp, in_size);
  platform pl;
  if (!pl.ParseFromString(pfp_str)) {
    printf("Can't parse platform\n");
    return false;
  }
  if (!make_platform_entity(pl, em)) {
    printf("Can't make environemnt entity\n");
    return false;
  }
  return true;
}

bool get_environment_entity_from_file(const string &in, entity_message *em) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte env[in_size];

  if (!read_file(in, &in_read, env)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string env_str;
  env_str.assign((char *)env, in_size);
  environment en;
  if (!en.ParseFromString(env_str)) {
    printf("Can't parse environment\n");
    return false;
  }
  if (!make_environment_entity(en, em)) {
    printf("Can't make environemnt entity\n");
    return false;
  }
  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_key_subject == "" && FLAGS_cert_subject == ""
      && FLAGS_measurement_subject == "" && FLAGS_platform_subject == ""
      && FLAGS_environment_subject == "") {
    printf("No subject\n");
    return 1;
  }

  entity_message sub_ent;

  if (FLAGS_key_subject != "") {
    key_message k;
    if (!get_key_from_file(FLAGS_key_subject, &k)) {
      printf("Can't get subject key\n");
      return 1;
    }
    if (!make_key_entity(k, &sub_ent)) {
      printf("Can't get subject entity\n");
      return 1;
    }
  } else if (FLAGS_cert_subject != "") {
    key_message k;
    if (!get_key_from_cert_file(FLAGS_cert_subject, &k)) {
      printf("Can't get subject key\n");
      return 1;
    }
    if (!make_key_entity(k, &sub_ent)) {
      printf("Can't get subject entity\n");
      return 1;
    }
  } else if (FLAGS_measurement_subject != "") {
    if (!get_measurement_entity_from_file(FLAGS_measurement_subject,
                                          &sub_ent)) {
      printf("Can't make subject measurement\n");
      return 1;
    }
  } else if (FLAGS_platform_subject != "") {
    if (!get_platform_entity_from_file(FLAGS_platform_subject, &sub_ent)) {
      printf("Can't make subject measurement\n");
      return 1;
    }
  } else if (FLAGS_environment_subject != "") {
    if (!get_environment_entity_from_file(FLAGS_environment_subject,
                                          &sub_ent)) {
      printf("Can't make subject measurement\n");
      return 1;
    }
  }

  return make_unary_clause_file_utility(sub_ent, FLAGS_verb, FLAGS_output);
}
