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

// make_property.exe --property_name=name --type=type --comparator="X"
//      --int=int-value --string_value=value

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(property_name, "", "property name");
DEFINE_string(property_type, "", "property type");
// values are "=", ">="
DEFINE_string(comparator, "=", "comparator");
DEFINE_uint64(int_value, 0, "int value");
DEFINE_string(string_value, "", "string value");
DEFINE_string(output, "prop.bin", "output file");

int main(int an, char **av) {
  string usage("Specify a platform policy property used in policy.");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  string usage_str("--property_name=<name> --property_type=<type> "
                   "--comparator=<cmp> --int_value=3 "
                   "--string_value=<string> --output=<output_file>");
  if (FLAGS_property_name == "") {
    printf("No property name\n");
    printf("%s %s\n", av[0], usage_str.c_str());
    return 1;
  }

  property prop;
  if (!make_property(FLAGS_property_name,
                     FLAGS_property_type,
                     FLAGS_comparator,
                     FLAGS_int_value,
                     FLAGS_string_value,
                     &prop)) {
    printf("Can't make property\n");
    return 1;
  }

  string p_out;
  if (!prop.SerializeToString(&p_out)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(FLAGS_output, p_out.size(), (byte *)p_out.data())) {
    printf("Can't write cert file\n");
    return 1;
  }

  print_property(prop);
  return 0;
}
