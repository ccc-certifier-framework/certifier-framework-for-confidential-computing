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

// make_simple_vse_clause.exe --key_subject=file --measurement_subject=file
//  --platform_subject=file --environment_subject=file --verb="speaks-for"
//  --key_object=file --measurement_object=file --platform_object=file
//  --environment_object=file
//  --output=output-file-name

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(output, "simple_clause.bin", "output file");
DEFINE_string(key_subject, "", "subject file");
DEFINE_string(measurement_subject, "", "subject file");
DEFINE_string(platform_subject, "", "platform subject file");
DEFINE_string(environment_subject, "", "environment subject file");
DEFINE_string(verb, "verb", "verb to use");
DEFINE_string(key_object, "", "object file");
DEFINE_string(measurement_object, "", "object file");
DEFINE_string(platform_object, "", "platform object file");
DEFINE_string(environment_object, "", "environment object file");

int make_simple_clause_file_utility(entity_message &subject,
                                    const string &  verb,
                                    entity_message &object,
                                    const string &  output) {

  vse_clause cl;
  string     v = verb;
  if (!make_simple_vse_clause(subject, v, object, &cl)) {
    printf("Can't make clause\n");
    return 1;
  }

  string out_string;
  if (!cl.SerializeToString(&out_string)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(output, out_string.size(), (byte *)out_string.data())) {
    printf("Can't write %s\n", output.c_str());
    return 1;
  }

  if (FLAGS_print_all) {
    printf("Clause constructed: ");
    print_vse_clause(cl);
    printf("\n");
  }

  return 0;
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

  if (FLAGS_key_subject == "" && FLAGS_measurement_subject == ""
      && FLAGS_platform_subject == "" && FLAGS_environment_subject == "") {
    printf("No subject\n");
    return 1;
  }
  if (FLAGS_key_object == "" && FLAGS_measurement_object == ""
      && FLAGS_platform_object == "" && FLAGS_environment_object == "") {
    printf("No object\n");
    return 1;
  }

  entity_message sub_ent;
  entity_message obj_ent;

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
  } else if (FLAGS_measurement_subject != "") {
    if (!get_measurement_entity_from_file(FLAGS_measurement_subject,
                                          &sub_ent)) {
      printf("Can't make subject measurement\n");
      return 1;
    }
  } else if (FLAGS_platform_subject != "") {
    if (!get_platform_entity_from_file(FLAGS_platform_subject, &sub_ent)) {
      printf("Can't make subject platform\n");
      return 1;
    }
  } else if (FLAGS_environment_subject != "") {
    if (!get_environment_entity_from_file(FLAGS_environment_subject,
                                          &sub_ent)) {
      printf("Can't make subject environment\n");
      return 1;
    }
  }

  if (FLAGS_key_object != "") {
    key_message k;
    if (!get_key_from_file(FLAGS_key_object, &k)) {
      printf("Can't get object key\n");
      return 1;
    }
    if (!make_key_entity(k, &obj_ent)) {
      printf("Can't make object key entity\n");
      return 1;
    }
  } else if (FLAGS_measurement_object != "") {
    if (!get_measurement_entity_from_file(FLAGS_measurement_object, &obj_ent)) {
      printf("Can't make object measurement\n");
      return 1;
    }
  } else if (FLAGS_platform_object != "") {
    if (!get_platform_entity_from_file(FLAGS_platform_object, &obj_ent)) {
      printf("Can't make platform object\n");
      return 1;
    }
  } else if (FLAGS_environment_subject != "") {
    if (!get_environment_entity_from_file(FLAGS_environment_object, &obj_ent)) {
      printf("Can't make object environment\n");
      return 1;
    }
  }

  return make_simple_clause_file_utility(sub_ent,
                                         FLAGS_verb,
                                         obj_ent,
                                         FLAGS_output);
}
