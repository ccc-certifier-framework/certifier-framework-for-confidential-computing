#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

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

// make_platform.exe 

DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(property_name, "",  "property name");
DEFINE_string(property_type, "",  "property type");
// values are "=", ">="
DEFINE_string(comparator, "=",  "comparator");
DEFINE_int32(int_value, 0,  "int value");
DEFINE_string(string_value, "",  "string value");
DEFINE_string(output, "prop.bin",  "output file");

bool make_property(string& name, string& type, string& cmp, int int_value,
    string& string_value, property* prop) {
  prop->set_name(name);
  prop->set_comparator(cmp);
  if (type == "int") {
    prop->set_int_value(int_value);
  } else if (type == "string") {
    prop->set_string_value(string_value);
  } else {
    return false;
  }

  return true;
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_key_subject == "" && FLAGS_cert_subject == "" && FLAGS_measurement_subject == "") {
    printf("No subject\n");
    return 1;
  }

  property prop;
  if (!make_property(FLAGS_property_name, FLAGS_property_type, FLAGS_comparator,
        FLAGS_int_value, FLAGS_string_value, &prop)) {
    printf("Can't make property\n");
    return 1;
  }

  string p_out;
  if (!prop->SaveToString(&p_out)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(FLAGS_output, p_out.size(), (byte*) p_out.data())) {
      printf("Can't write cert file\n");
      return 1;
    }

  return 0;
}
