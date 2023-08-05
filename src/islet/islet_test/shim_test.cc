/*
 *  Copyright (c) 2023 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the language governing permissions and
 *  limitations under the License
 */

#include "../islet_api.h"

static void print_buf(int sz, byte *buf) {
  for (int i = 0; i < sz; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

// Some reasonable size to allocate an attestation report on-stack buffers.
// Typical attestation report size is over 1K.
#define BUFFER_SIZE 2048

bool attestation_test() {
  byte report[BUFFER_SIZE];
  byte measurement[BUFFER_SIZE];
  byte what_was_said[BUFFER_SIZE];
  int  report_len = 0;
  int  measurement_len = 0;

  memset(report, 0, sizeof(report));
  memset(measurement, 0, sizeof(measurement));
  memset(what_was_said, 0, sizeof(what_was_said));

  std::string what_to_say("User Custom data");

  if (!islet_Attest(what_to_say.size(),
                    (byte *)what_to_say.data(),
                    &report_len,
                    report))
    return false;

  if (!islet_Verify(what_to_say.size(),
                    (byte *)what_to_say.data(),
                    report_len,
                    report,
                    &measurement_len,
                    measurement))
    return false;

  printf("report size: %d\n", report_len);
  print_buf(report_len, report);
  printf("What was said originally: %s\n", (char *)what_to_say.c_str());
  printf("Measurement: ");
  for (int i = 0; i < measurement_len; i++) {
    printf("%02X", measurement[i]);
  }
  printf("\n");

  return true;
}

bool sealing_test() {
  byte sealed[BUFFER_SIZE];
  byte unsealed[BUFFER_SIZE];

  int sealed_len = 0;
  int unsealed_len = 0;

  memset(sealed, 0, sizeof(sealed));
  memset(unsealed, 0, sizeof(unsealed));

  std::string plaintext("Plaintext");
  if (!islet_Seal(plaintext.size(),
                  (byte *)plaintext.c_str(),
                  &sealed_len,
                  sealed))
    return false;

  if (!islet_Unseal(sealed_len, sealed, &unsealed_len, unsealed))
    return false;

  printf("Success sealing round trip.\n");

  return true;
}

int main() {
  bool rv = attestation_test();
  printf("Attestation test %s.\n", (rv ? "succeeded" : "failed"));
  if (!rv)
    return -1;

  rv = sealing_test();
  printf("Sealing test %s.\n", (rv ? "succeeded" : "failed"));

  return 0;
}
