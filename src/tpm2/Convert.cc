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

#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <tpm2_types.h>

using namespace std;

const char* websafebase64_order =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void ThreeBytesToBase64(byte a, byte b, byte c, char* out) {
  byte x;

  x = (a >> 2) & 0x3f;
  *out = websafebase64_order[x];
  x = ((a << 4) & 0x3f) | (b >> 4);
  *(out + 1) = websafebase64_order[x];
  x = ((b << 2) & 0x3f) | (c >> 6);
  *(out + 2) = websafebase64_order[x];
  x = c & 0x3f;
  *(out + 3) = websafebase64_order[x];
  return;
}

void TwoBytesToBase64(byte a, byte b, char* out) {
  byte x;

  x = (a >> 2) & 0x3f;
  *out = websafebase64_order[x];
  x = ((a << 4) & 0x3f) | (b >> 4);
  *(out + 1) = websafebase64_order[x];
  x = (b << 2) & 0x3f;
  *(out + 2) = websafebase64_order[x];
  *(out + 3) = '=';
  return;
}

void OneByteToBase64(byte a, char* out) {
  byte x;

  x = a >> 2;
  *out = websafebase64_order[x];
  x = (a & 0x3) << 4;
  *(out + 1) = websafebase64_order[x];
  *(out + 2) = '=';
  *(out + 3) = '=';
  return;
}

int NumBase64StringInBytes(int size, byte* in) {
  int n = (size + 3) / 3;
  return n * 4;
}

int NumBytesInBase64String(char* in) {
  if (in == nullptr)
    return 0;
  int j = strlen(in);
  // j should be a multiple of 4
  if ((j & 0x3) != 0)
    return -1;
  int n = (j / 4) * 3;
  if (in[j - 1] == '=') {
    if (in[j - 2] == '=')
      return n - 2;
    return n - 1;
  }
  return n;
}

byte Base64CharValue(char a) {
  if (a >= 'A' && a <= 'Z') {
    return a - 'A';
  } else if (a >= 'a' && a <= 'z') {
    return a - 'a' + 26;
  } else if (a >= '0' && a <= '9') {
    return a - '0' + 52;
  } else if (a == '-') {
    return 62;
  } else if (a == '_') {
    return 63;
  } else {
    return 0xff;
  }
}

bool FourBase64ToBytes(char* in, byte* out) {
  byte x, y;

  x = Base64CharValue(*in);
  y = Base64CharValue(*(in + 1));
  if (x == 0xff || y == 0xff)
    return false;
  *out = (x << 2) | (y >> 4);
  if (*(in + 2) == '=') {
    return true;
  }
  x = Base64CharValue(*(in + 2));
  if (x == 0xff)
    return false;
  *(out + 1) = y << 4 | x >> 2;
  if (*(in + 3) == '=')
    return true;
  y = Base64CharValue(*(in + 3));
  if (y == 0xff)
    return false;
  *(out + 2) = (x << 6) | y;
  return true;
}

bool FourBase64ToBytesReverse(char* in, byte* out) {
  byte x, y;

  x = Base64CharValue(*in);
  y = Base64CharValue(*(in + 1));
  if (x == 0xff || y == 0xff)
    return false;
  *out = (x << 2) | (y >> 4);
  if (*(in + 2) == '=') {
    return true;
  }
  x = Base64CharValue(*(in + 2));
  if (x == 0xff)
    return false;
  *(out - 1) = y << 4 | x >> 2;
  if (*(in + 3) == '=')
    return true;
  y = Base64CharValue(*(in + 3));
  if (y == 0xff)
    return false;
  *(out - 2) = (x << 6) | y;
  return true;
}

string* ByteToBase64LeftToRight(int size, byte* in) {
  int n = NumBase64StringInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();

  if (size <= 0 || in == nullptr)
    return nullptr;
  while (size >= 3) {
    ThreeBytesToBase64(*in, *(in + 1), *(in + 2), str);
    in += 3;
    str += 4;
    size -= 3;
  }
  if (size == 2) {
    TwoBytesToBase64(*in, *(in + 1), str);
    in += 2;
    str += 4;
    size -= 2;
  }
  if (size == 1) {
    OneByteToBase64(*in, str);
    in += 1;
    str += 4;
    size -= 1;
  }
  return out;
}

string* ByteToBase64RightToLeft(int size, byte* in) {
  int n = NumBase64StringInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();

  if (size <= 0 || in == nullptr)
    return nullptr;
  in += size - 1;
  while (size >= 3) {
    ThreeBytesToBase64(*in, *(in - 1), *(in - 2), str);
    in -= 3;
    str += 4;
    size -= 3;
  }
  if (size == 2) {
    TwoBytesToBase64(*in, *(in - 1), str);
    in -= 2;
    str += 4;
    size -= 2;
  }
  if (size == 1) {
    OneByteToBase64(*in, str);
    in -= 1;
    str += 4;
    size -= 1;
  }
  return out;
}

int Base64ToByteLeftToRight(char* in, int size, byte* out) {
  if (in == nullptr)
     return -1;

  int k = strlen(in);
  if ((k & 0x3) != 0)
    return -1;
  int n = NumBytesInBase64String(in);

  if (n > size)
    return -1;

  while (k > 0) {
    FourBase64ToBytes(in, out);
    in += 4;
    out += 3;
    k -= 4;
  }

  return n;
}

int Base64ToByteRightToLeft(char* in, int size, byte* out) {
  if (in == nullptr)
    return -1;
  int k = strlen(in);
  if ((k & 0x3) != 0)
    return -1;

  int n = NumBytesInBase64String(in);
  if (n > size)
    return -1;

  out += n - 1;
  while (k > 0) {
    FourBase64ToBytesReverse(in, out);
    in += 4;
    out -= 3;
    k -= 4;
  }
  return n;
}

int NumHexInBytes(int size, byte* in) { return 2 * size; }

int NumBytesInHex(char* in) {
  if (in == nullptr)
    return -1;
  int len = strlen(in);
  return ((len + 1) / 2);
}

char ValueToHex(byte x) {
  if (x >= 0 && x <= 9) {
    return x + '0';
  } else if (x >= 10 && x <= 15) {
    return x - 10 + 'a';
  } else {
    return ' ';
  }
}

byte HexToValue(char x) {
  if (x >= '0' && x <= '9') {
    return x - '0';
  } else if (x >= 'a' && x <= 'f') {
    return x + 10 - 'a';
  } else {
    return 0;
  }
}

string* ByteToHexLeftToRight(int size, byte* in) {
  if (in == nullptr)
    return nullptr;
  int n = NumHexInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte a, b;

  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in++;
    *(str++) = ValueToHex(a);
    *(str++) = ValueToHex(b);
    size--;
  }
  return out;
}

int HexToByteLeftToRight(char* in, int size, byte* out) {
  if (in == nullptr)
    return -1;
  int n = NumBytesInHex(in);
  int m = strlen(in);
  byte a, b;

  if (n > size) {
    return -1;
  }
  while (m > 0) {
    a = HexToValue(*(in++));
    b = HexToValue(*(in++));
    *(out++) = (a << 4) | b;
    m -= 2;
  }
  return n;
}

string* ByteToHexRightToLeft(int size, byte* in) {
  if (in == nullptr)
    return nullptr;
  int n = NumHexInBytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte a, b;

  in += size - 1;
  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in--;
    *(str++) = ValueToHex(a);
    *(str++) = ValueToHex(b);
    size--;
  }
  return out;
}

int HexToByteRightToLeft(char* in, int size, byte* out) {
  if (in == nullptr) {
    return -1;
  }
  int n = NumBytesInHex(in);
  int m = strlen(in);
  byte a, b;

  out += n - 1;
  if (m < 0) {
    return -1;
  }
  while (m > 0) {
    a = HexToValue(*(in++));
    b = HexToValue(*(in++));
    *(out--) = (a << 4) | b;
    m -= 2;
  }
  return n;
}
