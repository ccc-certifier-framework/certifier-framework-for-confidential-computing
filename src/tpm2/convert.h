//
// Copyright 2014 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// Project: New Cloudproxy Crypto
// file: convert.h

#ifndef _CONVERT_H__
#define _CONVERT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tpm2_types.h>

#include <string>
#include <memory>

using std::string;

char value_to_hex(byte_t x);
byte_t hex_to_value(char x);

string* byte_to_base64_left_to_right(int size, byte_t* in);
string* byte_to_base64_right_to_left(int size, byte_t* in);
int base64_to_byte_left_to_right(char* in, int size, byte_t* out);
int base_64_to_byte_right_to_left(char* in, int size, byte_t* out);

string* byte_to_hex_left_to_right(int, byte_t*);
string* byte_to_hex_right_to_left(int, byte_t*);
int hex_to_byte_left_to_right(char*, int, byte_t*);
int hex_to_byte_right_to_left(char*, int, byte_t*);
#endif
