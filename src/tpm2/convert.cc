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
// File: convert.cc

#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <tpm2_types.h>

using namespace std;

const char* websafebase64_order =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void three_bytes_to_base64(byte_t a, byte_t b, byte_t c, char* out) {
  byte_t x;

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

void two_bytes_to_base64(byte_t a, byte_t b, char* out) {
  byte_t x;

  x = (a >> 2) & 0x3f;
  *out = websafebase64_order[x];
  x = ((a << 4) & 0x3f) | (b >> 4);
  *(out + 1) = websafebase64_order[x];
  x = (b << 2) & 0x3f;
  *(out + 2) = websafebase64_order[x];
  *(out + 3) = '=';
  return;
}

void one_byte_to_base64(byte_t a, char* out) {
  byte_t x;

  x = a >> 2;
  *out = websafebase64_order[x];
  x = (a & 0x3) << 4;
  *(out + 1) = websafebase64_order[x];
  *(out + 2) = '=';
  *(out + 3) = '=';
  return;
}

int num_base64_string_in_bytes(int size, byte_t* in) {
  int n = (size + 3) / 3;
  return n * 4;
}

int num_bytes_in_base64_string(char* in) {
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

byte_t base64_char_value(char a) {
  if (a >= 'A' && a <= 'Z') {
    return (byte_t)(a - 'A');
  } else if (a >= 'a' && a <= 'z') {
    return (byte_t)(a - 'a' + 26);
  } else if (a >= '0' && a <= '9') {
    return (byte_t)(a - '0' + 52);
  } else if (a == '-') {
    return 62;
  } else if (a == '_') {
    return 63;
  } else {
    return 0xff;
  }
}

bool four_base64_to_bytes(char* in, byte_t* out) {
  byte_t x, y;

  x = base64_char_value(*in);
  y = base64_char_value(*(in + 1));
  if (x == 0xff || y == 0xff)
    return false;
  *out = (x << 2) | (y >> 4);
  if (*(in + 2) == '=') {
    return true;
  }
  x = base64_char_value(*(in + 2));
  if (x == 0xff)
    return false;
  *(out + 1) = y << 4 | x >> 2;
  if (*(in + 3) == '=')
    return true;
  y = base64_char_value(*(in + 3));
  if (y == 0xff)
    return false;
  *(out + 2) = (x << 6) | y;
  return true;
}

bool four_base64_to_bytesReverse(char* in, byte_t* out) {
  byte_t x, y;

  x = base64_char_value(*in);
  y = base64_char_value(*(in + 1));
  if (x == 0xff || y == 0xff)
    return false;
  *out = (x << 2) | (y >> 4);
  if (*(in + 2) == '=') {
    return true;
  }
  x = base64_char_value(*(in + 2));
  if (x == 0xff)
    return false;
  *(out - 1) = y << 4 | x >> 2;
  if (*(in + 3) == '=')
    return true;
  y = base64_char_value(*(in + 3));
  if (y == 0xff)
    return false;
  *(out - 2) = (x << 6) | y;
  return true;
}

string* byte_to_base64_left_to_right(int size, byte_t* in) {
  int n = num_base64_string_in_bytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();

  if (size <= 0 || in == nullptr)
    return nullptr;
  while (size >= 3) {
    three_bytes_to_base64(*in, *(in + 1), *(in + 2), str);
    in += 3;
    str += 4;
    size -= 3;
  }
  if (size == 2) {
    two_bytes_to_base64(*in, *(in + 1), str);
    in += 2;
    str += 4;
    size -= 2;
  }
  if (size == 1) {
    one_byte_to_base64(*in, str);
    in += 1;
    str += 4;
    size -= 1;
  }
  return out;
}

string* byte_to_base64_right_to_left(int size, byte_t* in) {
  int n = num_base64_string_in_bytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();

  if (size <= 0 || in == nullptr)
    return nullptr;
  in += size - 1;
  while (size >= 3) {
    three_bytes_to_base64(*in, *(in - 1), *(in - 2), str);
    in -= 3;
    str += 4;
    size -= 3;
  }
  if (size == 2) {
    two_bytes_to_base64(*in, *(in - 1), str);
    in -= 2;
    str += 4;
    size -= 2;
  }
  if (size == 1) {
    one_byte_to_base64(*in, str);
    in -= 1;
    str += 4;
    size -= 1;
  }
  return out;
}

int base64_to_byte_left_to_right(char* in, int size, byte_t* out) {
  if (in == nullptr)
     return -1;

  int k = strlen(in);
  if ((k & 0x3) != 0)
    return -1;
  int n = num_bytes_in_base64_string(in);

  if (n > size)
    return -1;

  while (k > 0) {
    four_base64_to_bytes(in, out);
    in += 4;
    out += 3;
    k -= 4;
  }

  return n;
}

int base_64_to_byte_right_to_left(char* in, int size, byte_t* out) {
  if (in == nullptr)
    return -1;
  int k = strlen(in);
  if ((k & 0x3) != 0)
    return -1;

  int n = num_bytes_in_base64_string(in);
  if (n > size)
    return -1;

  out += n - 1;
  while (k > 0) {
    four_base64_to_bytesReverse(in, out);
    in += 4;
    out -= 3;
    k -= 4;
  }
  return n;
}

int num_hex_in_bytes(int size, byte_t* in) { return 2 * size; }

int num_bytes_in_hex(char* in) {
  if (in == nullptr)
    return -1;
  int len = strlen(in);
  return ((len + 1) / 2);
}

char value_to_hex(byte_t x) {
  if (x >= 0 && x <= 9) {
    return x + '0';
  } else if (x >= 10 && x <= 15) {
    return x - 10 + 'a';
  } else {
    return ' ';
  }
}

byte_t hex_to_value(char x) {
  if (x >= '0' && x <= '9') {
    return x - '0';
  } else if (x >= 'a' && x <= 'f') {
    return x + 10 - 'a';
  } else {
    return 0;
  }
}

string* byte_to_hex_left_to_right(int size, byte_t* in) {
  if (in == nullptr)
    return nullptr;
  int n = num_hex_in_bytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte_t a, b;

  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in++;
    *(str++) = value_to_hex(a);
    *(str++) = value_to_hex(b);
    size--;
  }
  return out;
}

int hex_to_byte_left_to_right(char* in, int size, byte_t* out) {
  if (in == nullptr)
    return -1;
  int n = num_bytes_in_hex(in);
  int m = strlen(in);
  byte_t a, b;

  if (n > size) {
    return -1;
  }
  while (m > 0) {
    a = hex_to_value(*(in++));
    b = hex_to_value(*(in++));
    *(out++) = (a << 4) | b;
    m -= 2;
  }
  return n;
}

string* byte_to_hex_right_to_left(int size, byte_t* in) {
  if (in == nullptr)
    return nullptr;
  int n = num_hex_in_bytes(size, in);
  string* out = new string(n, 0);
  char* str = (char*)out->c_str();
  byte_t a, b;

  in += size - 1;
  while (size > 0) {
    a = (*in) >> 4;
    b = (*in) & 0xf;
    in--;
    *(str++) = value_to_hex(a);
    *(str++) = value_to_hex(b);
    size--;
  }
  return out;
}

int hex_to_byte_right_to_left(char* in, int size, byte_t* out) {
  if (in == nullptr) {
    return -1;
  }
  int n = num_bytes_in_hex(in);
  int m = strlen(in);
  byte_t a, b;

  out += n - 1;
  if (m < 0) {
    return -1;
  }
  while (m > 0) {
    a = hex_to_value(*(in++));
    b = hex_to_value(*(in++));
    *(out--) = (a << 4) | b;
    m -= 2;
  }
  return n;
}
