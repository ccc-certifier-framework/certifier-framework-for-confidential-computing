//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
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

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <stdio.h>
#include <gflags/gflags.h>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>

using namespace std;
using nlohmann::json;
using nlohmann::json_schema::json_validator;

DEFINE_bool(debug, false, "verbose");
DEFINE_bool(script, false, "Generate script instead of policy package");
DEFINE_string(util_path, "", "Path to Certifier utilities");
DEFINE_string(schema_input, "policy_schema.json", "Policy schema input file");
DEFINE_string(policy_input, "policy.json", "Policy input file");
DEFINE_string(policy_output, "policy.bin", "Policy output file");

#define MAKE_PROPERTY_CMD        "make_property.exe"
#define COMBINE_PROPERTY_CMD     "combine_properties.exe"
#define MAKE_PLATFORM_CMD        "make_platform.exe"
#define MAKE_UNARY_CLAUSE_CMD    "make_unary_vse_clause.exe"
#define MAKE_SIMPLE_CLAUSE_CMD   "make_simple_vse_clause.exe"
#define MAKE_INDIRECT_CLAUSE_CMD "make_indirect_vse_clause.exe"
#define MEASUREMENT_INIT_CMD     "measurement_init.exe"
#define MAKE_SIGNED_CLAIM_CMD    "make_signed_claim_from_vse_clause.exe"
#define PACKAGE_CLAIM_CMD        "package_claims.exe"

typedef struct property {
  string comparator;
  string type;
  string name;
  string value;
} property;

typedef enum subject_type {
  KEY_SUBJECT,
  CERT_SUBJECT,
  MEASUREMENT_SUBJECT,
  ENVIRONMENT_SUBJECT,
  PLATFORM_SUBJECT,
  NONE_SUBJECT,
} subject_type;

typedef enum object_type {
  KEY_OBJECT,
  MEASUREMENT_OBJECT,
  ENVIRONMENT_OBJECT,
  PLATFORM_OBJECT,
  NONE_OBJECT,
} object_type;

typedef enum clause_type {
  SIMPLE_CLAUSE,
  UNARY_CLAUSE,
  INDIRECT_CLAUSE,
  NONE_CLAUSE,
} clause_type;

typedef struct clause {
  string       sub;
  subject_type stype;
  string       verb;
  string       obj;
  object_type  otype;
  clause_type  ctype;
  /* For indirect clause only */
  string       ssub;
  subject_type sstype;
  string       sobj;
  object_type  sotype;
  string       sverb;
} clause;

typedef struct claim {
  string       sub;
  subject_type stype;
  string       verb;
  clause_type  ctype;
  clause       cl;
  string       skey;
} claim;

typedef struct platform {
  string           type;
  vector<property> props;
} platform;

void print_claim(claim &c, const string prefix = "") {
  map<clause_type, string> cname = {
      {SIMPLE_CLAUSE, "simpleClause"},
      {UNARY_CLAUSE, "unaryClause"},
      {INDIRECT_CLAUSE, "indirectClause"},
      {NONE_CLAUSE, ""},
  };
  map<subject_type, string> sname = {
      {KEY_SUBJECT, "keySubject"},
      {CERT_SUBJECT, "certSubject"},
      {MEASUREMENT_SUBJECT, "measurementSubject"},
      {PLATFORM_SUBJECT, "platformSubject"},
      {ENVIRONMENT_SUBJECT, "environmentSubject"},
  };
  map<object_type, string> oname = {
      {KEY_OBJECT, "keyObject"},
      {MEASUREMENT_OBJECT, "measurementObject"},
      {PLATFORM_OBJECT, "platformObject"},
      {ENVIRONMENT_OBJECT, "environmentObject"},
  };

  if (c.skey != "") {
    cout << prefix << "Claim signing key: " << c.skey << endl;
  } else {
    cout << prefix << "Claim signing key: policyKey" << endl;
  }
  cout << prefix << "verb: " << c.verb << endl;
  cout << prefix << sname[c.stype] << ": " << c.sub << endl;
  cout << prefix << cname[c.ctype] << ": " << endl;
  cout << prefix << "\t"
       << "verb: " << c.cl.verb << endl;
  cout << prefix << "\t" << sname[c.cl.stype] << ": " << c.cl.sub << endl;
  if (c.ctype == SIMPLE_CLAUSE) {
    cout << prefix << "\t" << oname[c.cl.otype] << ": " << c.cl.obj << endl;
  }
  if (c.cl.ctype != NONE_CLAUSE) {
    cout << prefix << "\t\t"
         << "verb: " << c.cl.sverb << endl;
    cout << prefix << "\t\t" << sname[c.cl.sstype] << ": " << c.cl.ssub << endl;
    if (c.cl.ctype == SIMPLE_CLAUSE) {
      cout << prefix << "\t\t" << oname[c.cl.sotype] << ": " << c.cl.sobj
           << endl;
    }
  }
}

void from_json(const json &j, property &p) {
  map<string, string> cmap = {
      {"eq", "="},
      {"ge", ">="},
      {"gt", ">"},
      {"le", "<="},
      {"lt", "<"},
  };
  if (cmap.find(j["comparator"]) == cmap.end()) {
    cerr << "Illegal comparator: " << j["comparator"] << endl;
  } else {
    p.comparator = cmap[j["comparator"].get<string>()];
  }
  j.at("type").get_to(p.type);
  j.at("name").get_to(p.name);
  j.at("value").get_to(p.value);
}

void from_json(const json &j, clause &cl) {
  clause tmp_cl;

  j.at("verb").get_to(cl.verb);

  if (j.find("certSubject") != j.end()) {
    cl.stype = CERT_SUBJECT;
    j.at("certSubject").get_to(cl.sub);
  } else if (j.find("keySubject") != j.end()) {
    cl.stype = KEY_SUBJECT;
    j.at("keySubject").get_to(cl.sub);
  } else if (j.find("measurementSubject") != j.end()) {
    cl.stype = MEASUREMENT_SUBJECT;
    j.at("measurementSubject").get_to(cl.sub);
  } else if (j.find("environmentSubject") != j.end()) {
    cl.stype = ENVIRONMENT_SUBJECT;
    j.at("environmentSubject").get_to(cl.sub);
  } else if (j.find("platformSubject") != j.end()) {
    cl.stype = PLATFORM_SUBJECT;
    j.at("platformSubject").get_to(cl.sub);
  }

  if (j.find("keyObject") != j.end()) {
    cl.otype = KEY_OBJECT;
    j.at("keyObject").get_to(cl.obj);
  } else if (j.find("measurementObject") != j.end()) {
    cl.otype = MEASUREMENT_OBJECT;
    j.at("measurementObject").get_to(cl.obj);
  } else if (j.find("environmentObject") != j.end()) {
    cl.otype = ENVIRONMENT_OBJECT;
    j.at("environmentObject").get_to(cl.obj);
  } else if (j.find("platformObject") != j.end()) {
    cl.otype = PLATFORM_OBJECT;
    j.at("platformObject").get_to(cl.obj);
  } else {
    cl.otype = NONE_OBJECT;
    cl.obj = "";
  }

  if (j.find("unaryClause") != j.end()) {
    cl.ctype = UNARY_CLAUSE;
    tmp_cl = j["unaryClause"].get<clause>();
    cl.ssub = tmp_cl.sub;
    cl.sstype = tmp_cl.stype;
    cl.sverb = tmp_cl.verb;
    cl.sotype = NONE_OBJECT;
    cl.sobj = "";
  } else if (j.find("simpleClause") != j.end()) {
    cl.ctype = SIMPLE_CLAUSE;
    tmp_cl = j["simpleClause"].get<clause>();
    cl.ssub = tmp_cl.sub;
    cl.sstype = tmp_cl.stype;
    cl.sverb = tmp_cl.verb;
    cl.sotype = tmp_cl.otype;
    cl.sobj = tmp_cl.obj;
  } else {
    cl.ctype = NONE_CLAUSE;
    cl.ssub = "";
    cl.sstype = NONE_SUBJECT;
    cl.sverb = "";
    cl.sotype = NONE_OBJECT;
    cl.sobj = "";
  }
}

void from_json(const json &j, claim &c) {
  j.at("verb").get_to(c.verb);

  if (j.find("certSubject") != j.end()) {
    c.stype = CERT_SUBJECT;
    j.at("certSubject").get_to(c.sub);
  } else if (j.find("keySubject") != j.end()) {
    c.stype = KEY_SUBJECT;
    j.at("keySubject").get_to(c.sub);
  } else if (j.find("measurementSubject") != j.end()) {
    c.stype = MEASUREMENT_SUBJECT;
    j.at("measurementSubject").get_to(c.sub);
  } else if (j.find("environmentSubject") != j.end()) {
    c.stype = ENVIRONMENT_SUBJECT;
    j.at("environmentSubject").get_to(c.sub);
  } else if (j.find("platformSubject") != j.end()) {
    c.stype = PLATFORM_SUBJECT;
    j.at("platformSubject").get_to(c.sub);
  }

  if (j.find("signingKey") != j.end()) {
    j.at("signingKey").get_to(c.skey);
  } else {
    c.skey = "";
  }

  /* Parse Sub clauses */
  if (j.find("unaryClause") != j.end()) {
    c.ctype = UNARY_CLAUSE;
    c.cl = j["unaryClause"].get<clause>();
  } else if (j.find("simpleClause") != j.end()) {
    c.ctype = SIMPLE_CLAUSE;
    c.cl = j["simpleClause"].get<clause>();
  } else if (j.find("indirectClause") != j.end()) {
    c.ctype = INDIRECT_CLAUSE;
    c.cl = j["indirectClause"].get<clause>();
  }
}

vector<platform> platforms;
vector<string>   measurements;
vector<claim>    claims;
string           policyKey;

vector<string> signed_claims;
vector<string> intermediate_files;

static int exec_cmd(const string &command, bool print = false) {
  int                     exitcode = -1;
  array<char, 512 * 1024> buffer {};
  string                  result;

  FILE *pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return -1;
  }
  try {
    size_t bytesread;
    while (
        (bytesread =
             fread(buffer.data(), sizeof(buffer.at(0)), sizeof(buffer), pipe))
        != 0) {
      result += string(buffer.data(), bytesread);
    }
  } catch (...) {
    pclose(pipe);
    return -1;
  }
  if (print) {
    cout << result << endl;
  }
  exitcode = WEXITSTATUS(pclose(pipe));
  return exitcode;
}

template<class... Args>
string string_format(const string &format, Args... args) {
  int size = snprintf(nullptr, 0, format.c_str(), args...) + 1;
  if (size <= 0) {
    return "";
  }
  unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), (size_t)size, format.c_str(), args...);
  return string(buf.get(), (size_t)(size - 1));
}

static string make_property_cmd(string name,
                                string type,
                                string comparator,
                                string value,
                                string output) {
  return string_format("%s --property_name=%s --property_type=\'%s\' "
                       "comparator=\"%s\" --%s_value=%s --output=%s",
                       (FLAGS_util_path + MAKE_PROPERTY_CMD).c_str(),
                       name.c_str(),
                       type.c_str(),
                       comparator.c_str(),
                       type.c_str(),
                       value.c_str(),
                       output.c_str());
}

static string make_unary_clause_cmd(string subjectType,
                                    string subject,
                                    string verb,
                                    string output) {
  return string_format("%s --%s_subject=%s --verb=\"%s\" --output=%s",
                       (FLAGS_util_path + MAKE_UNARY_CLAUSE_CMD).c_str(),
                       subjectType.c_str(),
                       subject.c_str(),
                       verb.c_str(),
                       output.c_str());
}

static string make_simple_clause_cmd(string subjectType,
                                     string subject,
                                     string verb,
                                     string objectType,
                                     string object,
                                     string output) {
  return string_format("%s --%s_subject=%s --verb=%s --%s_object=%s "
                       "--output=%s",
                       (FLAGS_util_path + MAKE_SIMPLE_CLAUSE_CMD).c_str(),
                       subjectType.c_str(),
                       subject.c_str(),
                       verb.c_str(),
                       objectType.c_str(),
                       object.c_str(),
                       output.c_str());
}

static string make_indirect_clause_cmd(string subjectType,
                                       string subject,
                                       string verb,
                                       string clause,
                                       string output) {
  return string_format("%s --%s_subject=%s --verb=\"%s\" --clause=%s "
                       "--output=%s",
                       (FLAGS_util_path + MAKE_INDIRECT_CLAUSE_CMD).c_str(),
                       subjectType.c_str(),
                       subject.c_str(),
                       verb.c_str(),
                       clause.c_str(),
                       output.c_str());
}

static string make_signed_claim_cmd(string vseFile,
                                    string duration,
                                    string pKey,
                                    string output) {
  return string_format("%s --vse_file=%s --duration=%s --private_key_file=%s "
                       "--output=%s",
                       (FLAGS_util_path + MAKE_SIGNED_CLAIM_CMD).c_str(),
                       vseFile.c_str(),
                       duration.c_str(),
                       pKey.c_str(),
                       output.c_str());
}

#define RUN_CMD(cmd, script, ret)                                              \
  if (script) {                                                                \
    cout << cmd << endl;                                                       \
  } else {                                                                     \
    if (exec_cmd(cmd, FLAGS_debug)) {                                          \
      cerr << "Command execution failed! Failed command: " << cmd << endl;     \
      return ret;                                                              \
    }                                                                          \
  }

static bool generate_platform_policy(string           policyKey,
                                     vector<platform> platforms,
                                     bool             script) {
  for (auto platform : platforms) {
    int    i = 1;
    string all_props = "", plat_file;
    string combine_cmd, claim_cmd;
    for (auto prop : platform.props) {
      string prop_path = string_format("property%d.bin", i++);
      string cmd;
      if (all_props == "") {
        all_props.append(prop_path);
      } else {
        all_props.append(",").append(prop_path);
      }
      cmd = make_property_cmd(prop.name,
                              prop.type,
                              prop.comparator,
                              prop.value,
                              prop_path);
      RUN_CMD(cmd, script, false);
    }
    combine_cmd =
        string_format("%s --in=%s --output=%s",
                      (FLAGS_util_path + COMBINE_PROPERTY_CMD).c_str(),
                      all_props.c_str(),
                      "properties.bin");
    RUN_CMD(combine_cmd, script, false);
    plat_file = string_format("%s-platform.bin", platform.type.c_str());
    claim_cmd = string_format("%s --platform_type=%s --properties_file=%s "
                              "--output=%s",
                              (FLAGS_util_path + MAKE_PLATFORM_CMD).c_str(),
                              platform.type.c_str(),
                              "properties.bin",
                              plat_file.c_str());
    RUN_CMD(claim_cmd, script, false);
    intermediate_files.push_back(plat_file);
    claim_cmd = make_unary_clause_cmd("platform",
                                      plat_file,
                                      "has-trusted-platform-property",
                                      "isplatform.bin");
    RUN_CMD(claim_cmd, script, false);
    claim_cmd = make_indirect_clause_cmd("key",
                                         policyKey,
                                         "says",
                                         "isplatform.bin",
                                         "saysisplatform.bin");
    RUN_CMD(claim_cmd, script, false);
    claim_cmd = make_signed_claim_cmd("saysisplatform.bin",
                                      "9000",
                                      policyKey,
                                      (platform.type + ".bin").c_str());
    signed_claims.push_back(platform.type + ".bin");
    RUN_CMD(claim_cmd, script, false);
    claim_cmd = "rm -rf property*.bin properties.bin "
                "isplatform.bin saysisplatform.bin";
    RUN_CMD(claim_cmd, script, false);
  }
  return true;
}

static bool generate_measurement_policy(string         policyKey,
                                        vector<string> measurements,
                                        bool           script) {
  int i = 1;
  for (auto mea : measurements) {
    string cmd, claim_file;
    cmd = string_format("%s --mrenclave=%s --out_file=%s",
                        (FLAGS_util_path + MEASUREMENT_INIT_CMD).c_str(),
                        mea.c_str(),
                        "meas.bin");
    RUN_CMD(cmd, script, false);
    cmd = make_unary_clause_cmd("measurement",
                                "meas.bin",
                                "is-trusted",
                                "measurement.bin");
    RUN_CMD(cmd, script, false);
    cmd = make_indirect_clause_cmd("key",
                                   policyKey,
                                   "says",
                                   "measurement.bin",
                                   "saysmeasurement.bin");
    RUN_CMD(cmd, script, false);
    claim_file = string_format("signed_measurement%d.bin", i++);
    cmd = make_signed_claim_cmd("saysmeasurement.bin",
                                "9000",
                                policyKey,
                                claim_file);
    RUN_CMD(cmd, script, false);
    signed_claims.push_back(claim_file);
    cmd = "rm -rf meas.bin measurement.bin saysmeasurement.bin";
    RUN_CMD(cmd, script, false);
  }
  return true;
}

static pair<string, string> subject_conversion(subject_type stype,
                                               string       sub,
                                               bool         script) {
  string actual_sub, cleanup_cmd = "", cmd;

  switch (stype) {
    case PLATFORM_SUBJECT:
      actual_sub = string_format("%s-platform.bin", sub.c_str());
      break;
    case MEASUREMENT_SUBJECT:
      actual_sub = "tmp_meas.bin";
      cmd = string_format("%s --mrenclave=%s --out_file=%s",
                          (FLAGS_util_path + MEASUREMENT_INIT_CMD).c_str(),
                          sub.c_str(),
                          actual_sub.c_str());
      RUN_CMD(cmd, script, make_pair("", ""));
      cleanup_cmd = string_format("rm -rf %s", actual_sub.c_str());
      break;
    // TODO: Handle environment subject
    default:
      actual_sub = sub;
  }

  return make_pair(actual_sub, cleanup_cmd);
}

static string generate_clause(string      policyKey,
                              clause      cl,
                              clause_type ct,
                              bool        script) {
  map<subject_type, string> sname = {
      {KEY_SUBJECT, "key"},
      {CERT_SUBJECT, "cert"},
      {MEASUREMENT_SUBJECT, "measurement"},
      {PLATFORM_SUBJECT, "platform"},
      {ENVIRONMENT_SUBJECT, "environment"},
  };
  map<object_type, string> oname = {
      {KEY_OBJECT, "key"},
      {MEASUREMENT_OBJECT, "measurement"},
      {PLATFORM_OBJECT, "platform"},
      {ENVIRONMENT_OBJECT, "environment"},
  };

  string               cmd, actual_sub, cleanup_cmd;
  pair<string, string> p = subject_conversion(cl.stype, cl.sub, script);
  actual_sub = p.first;
  cleanup_cmd = p.second;

  if (ct == UNARY_CLAUSE) {
    cmd = make_unary_clause_cmd(sname[cl.stype],
                                actual_sub,
                                cl.verb,
                                "clause.bin");
    RUN_CMD(cmd, script, "");
  } else if (ct == SIMPLE_CLAUSE) {
    cmd = make_simple_clause_cmd(sname[cl.stype],
                                 actual_sub,
                                 cl.verb,
                                 oname[cl.otype],
                                 cl.obj,
                                 "clause.bin");
    RUN_CMD(cmd, script, "");
  } else if (ct == INDIRECT_CLAUSE) {
    string               scleanup_cmd, actual_ssub;
    pair<string, string> s = subject_conversion(cl.sstype, cl.ssub, script);
    actual_ssub = s.first;
    scleanup_cmd = s.second;
    if (cl.ctype == UNARY_CLAUSE) {
      cmd = make_unary_clause_cmd(sname[cl.sstype],
                                  actual_ssub,
                                  cl.sverb,
                                  "subclause.bin");
      RUN_CMD(cmd, script, "");
    } else if (cl.ctype == SIMPLE_CLAUSE) {
      // TODO: Handle special objects
      cmd = make_simple_clause_cmd(sname[cl.sstype],
                                   actual_ssub,
                                   cl.sverb,
                                   oname[cl.sotype],
                                   cl.sobj,
                                   "subclause.bin");
      RUN_CMD(cmd, script, "");
    } else {
      return "";
    }
    cmd = make_indirect_clause_cmd(sname[cl.stype],
                                   actual_sub,
                                   cl.verb,
                                   "subclause.bin",
                                   "clause.bin");
    RUN_CMD(cmd, script, "");
    cmd = "rm -rf subclause.bin";
    RUN_CMD(cmd, script, "");
    if (scleanup_cmd != "") {
      RUN_CMD(scleanup_cmd, script, "");
    }
  } else {
    return "";
  }

  if (cleanup_cmd != "") {
    RUN_CMD(cleanup_cmd, script, "");
  }

  return "clause.bin";
}

static bool generate_claim_policy(string        policyKey,
                                  vector<claim> claims,
                                  bool          script) {
  map<subject_type, string> sname = {
      {KEY_SUBJECT, "key"},
      {CERT_SUBJECT, "cert"},
      {MEASUREMENT_SUBJECT, "measurement"},
      {PLATFORM_SUBJECT, "platform"},
      {ENVIRONMENT_SUBJECT, "environment"},
  };

  int i = 1;
  for (auto claim : claims) {
    string               cmd, clauseFile, claimFile, signedClaimFile;
    string               actual_sub, cleanup_cmd = "";
    pair<string, string> p;
    claimFile = string_format("claim%d.bin", i);
    signedClaimFile = string_format("signed_claim%d.bin", i);
    clauseFile = generate_clause(policyKey, claim.cl, claim.ctype, script);
    if (clauseFile == "") {
      return false;
    }
    p = subject_conversion(claim.stype, claim.sub, script);
    actual_sub = p.first;
    cleanup_cmd = p.second;
    cmd = make_indirect_clause_cmd(sname[claim.stype],
                                   actual_sub,
                                   claim.verb,
                                   clauseFile,
                                   claimFile);
    RUN_CMD(cmd, script, false);
    cmd = make_signed_claim_cmd(claimFile,
                                "9000",
                                claim.skey == "" ? policyKey : claim.skey,
                                signedClaimFile);
    RUN_CMD(cmd, script, false);
    if (cleanup_cmd != "") {
      RUN_CMD(cleanup_cmd, script, false);
    }
    signed_claims.push_back(signedClaimFile);
    cmd = string_format("rm -rf %s %s", clauseFile.c_str(), claimFile.c_str());
    RUN_CMD(cmd, script, false);
    i++;
  }
  return true;
}

static bool generate_packaged_claims(vector<string> signed_claims,
                                     string         output,
                                     bool           script) {
  string cList = "", cmd;
  for (auto sc : signed_claims) {
    if (cList == "") {
      cList.append(sc);
    } else {
      cList.append(",").append(sc);
    }
  }
  if (cList == "") {
    return false;
  }
  cmd = string_format("%s --input=%s --output=%s",
                      (FLAGS_util_path + PACKAGE_CLAIM_CMD).c_str(),
                      cList.c_str(),
                      output.c_str());
  RUN_CMD(cmd, script, false);
  return true;
}

/*
 * When script is set to true, a list of commands will be generated that can
 * be redirected to create a shell script which can be used later to generate
 * the policy bundle.
 */
static bool generate_policy(string           policyKey,
                            vector<platform> platforms,
                            vector<string>   measurements,
                            vector<claim>    claims,
                            bool             script) {
  bool   res = false;
  string files = "", cmd;

  if (script) {
    cout << "#!/bin/bash" << endl;
  }
  if (FLAGS_util_path != "" && FLAGS_util_path.back() != '/') {
    FLAGS_util_path.append("/");
  }
  if (!generate_claim_policy(policyKey, claims, script)) {
    goto done;
  }
  if (!generate_measurement_policy(policyKey, measurements, script)) {
    goto done;
  }
  if (!generate_platform_policy(policyKey, platforms, script)) {
    goto done;
  }
  if (!generate_packaged_claims(signed_claims, FLAGS_policy_output, script)) {
    goto done;
  }
  res = true;

done:
  for (auto f : signed_claims) {
    files.append(f).append(" ");
  }
  for (auto f : intermediate_files) {
    files.append(f).append(" ");
  }
  cmd = string_format("rm -rf %s", files.c_str());
  RUN_CMD(cmd, script, false);
  return res;
}

int main(int argc, char *argv[]) {
  json_validator validator;  // create validator
  json           policy_schema, policy;

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
    validator.set_root_schema(policy_schema);  // insert root-schema
  } catch (const exception &e) {
    cerr << "Validation of schema failed: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  if (FLAGS_debug) {
    cout << "Validating policy:\n" << setw(2) << policy << endl;
  }
  try {
    validator.validate(policy);  // validate the document - uses the default
                                 // throwing error-handler
  } catch (const std::exception &e) {
    cerr << "Validation failed: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  if (FLAGS_debug) {
    cout << "Policy file: " << FLAGS_policy_input
         << " validated successfully!\n";
  }

  /* Parsing the policy file */
  policyKey = policy["policyKey"];
  if (FLAGS_debug) {
    cout << "Policy key: " << policyKey << endl;
  }

  /* Parse platform properties */
  for (auto plat : policy["platforms"]) {
    platform new_platform;
    new_platform.type = plat["type"];
    for (auto prop : plat["props"]) {
      auto p = prop.get<property>();
      new_platform.props.push_back(p);
    }
    platforms.push_back(new_platform);
  }

  if (FLAGS_debug) {
    cout << platforms.size() << " platforms:" << endl;
    for (unsigned int i = 0; i < platforms.size(); i++) {
      cout << "Platform " << platforms[i].type << ", "
           << platforms[i].props.size() << " properties:" << endl;
      for (auto p : platforms[i].props) {
        cout << "\t" << p.name << " " << p.type << " " << p.comparator << " "
             << p.value << endl;
      }
    }
  }

  /* Parse trusted measurements */
  for (auto m : policy["measurements"]) {
    measurements.push_back(m);
  }

  if (FLAGS_debug) {
    cout << "Trusted measurements:" << endl;
    for (auto m : measurements) {
      cout << "\t" << m << endl;
    }
  }

  /* Parse claims */
  for (auto cl : policy["claims"]) {
    auto c = cl.get<claim>();
    claims.push_back(c);
  }

  if (FLAGS_debug) {
    if (claims.size() > 0) {
      cout << claims.size() << " claims:" << endl;
      for (auto c : claims) {
        print_claim(c);
      }
    }
  }

  /* Policy generation */
  if (!generate_policy(policyKey,
                       platforms,
                       measurements,
                       claims,
                       FLAGS_script)) {
    cerr << "Policy generation failed!" << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
