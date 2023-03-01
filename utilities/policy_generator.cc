#include <fstream>
#include <iostream>
#include <iomanip>
#include <gflags/gflags.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>

//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights reserved.
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

using namespace std;
using nlohmann::json;
using nlohmann::json_schema::json_validator;

DEFINE_bool(debug, false,  "verbose");
DEFINE_string(schema_input, "policy_schema.json", "Policy schema input file");
DEFINE_string(policy_input, "policy.json", "Policy input file");
DEFINE_string(policy_output, "policy.bin", "Policy output file");

int main(int argc, char* argv[])
{
    json_validator validator; // create validator
    json policy_schema, policy;

    gflags::ParseCommandLineFlags(&argc, &argv, true);

    ifstream policy_schema_file(FLAGS_schema_input);
    ifstream policy_file(FLAGS_policy_input);

    if (!policy_schema_file.good()) {
        cerr << "Schema file not found: " << FLAGS_schema_input << "\n";
        return EXIT_FAILURE;
    }

    if (!policy_file.good()) {
        cerr << "Policy file not found: " << FLAGS_policy_input << "\n";
        return EXIT_FAILURE;
    }

    /* Parse the schema and the policy JSON files */
    policy_schema = json::parse(policy_schema_file);
    policy = json::parse(policy_file);

    try {
        validator.set_root_schema(policy_schema); // insert root-schema
    } catch (const exception &e) {
        cerr << "Validation of schema failed: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    if (FLAGS_debug) {
        cout << "Validating policy:\n" << setw(2) << policy << endl;
    }
    try {
        validator.validate(policy); // validate the document - uses the default throwing error-handler
    } catch (const std::exception &e) {
        cerr << "Validation failed: " << e.what() << "\n";
        return EXIT_FAILURE;
    }

    if (FLAGS_debug) {
        cout << "Policy file: " << FLAGS_policy_input << " validated successfully!\n";
    }

    /* TODO: Parsing the policy file */

    return EXIT_SUCCESS;
}
