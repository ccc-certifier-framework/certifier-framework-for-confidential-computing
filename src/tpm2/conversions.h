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
// file: conversions.h

#ifndef _CRYPTO_CONVERSIONS_H__
#define _CRYPTO_CONVERSIONS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tpm2_types.h>

#include <string>
#include <memory>

using std::string;

char ValueToHex(byte x);
byte HexToValue(char x);

string* ByteToBase64LeftToRight(int size, byte* in);
string* ByteToBase64RightToLeft(int size, byte* in);
int Base64ToByteLeftToRight(char* in, int size, byte* out);
int Base64ToByteRightToLeft(char* in, int size, byte* out);

string* ByteToHexLeftToRight(int, byte*);
string* ByteToHexRightToLeft(int, byte*);
int HexToByteLeftToRight(char*, int, byte*);
int HexToByteRightToLeft(char*, int, byte*);
#endif
