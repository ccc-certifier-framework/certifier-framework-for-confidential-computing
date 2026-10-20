#include <stdio.h>
#include <string.h>

//
//      CPUID Decode
//

//  Copyright (c) 2021-22, John L. Manferdelli.  All rights
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


#ifndef _TYPES_H
#define _TYPES_H

typedef unsigned                u32;
typedef int                     i32;
typedef long long unsigned      u64;
typedef long long int           i64;
#endif


/*
 *      CPUID Documentation
 *
 *  The CPUID instruction takes no parameters as CPUID implicitly uses the EAX register.
 *
 *  EAX=0: Get vendor ID
 *      This returns the CPU's manufacturer ID string
 *  EAX=1: Processor Info and Feature Bits
 *      3:0 - Stepping
 *      7:4 - Model
 *      11:8 - Family
 *      13:12 - Processor Type
 *      19:16 - Extended Model
 *      27:20 - Extended Family
 *
 *      Bit     EDX                                 ECX
 *      0       fpu Onboard x87 FPU                 sse3   Prescott New Instructions-SSE3 (PNI)
 *      1       vme Virtual 8086 mode extension     pclmulqdq PCLMULQDQ support
 *      2       de Debugging extensions             dtes64   64-bit debug store (edx bit 21)
 *      3       pse Page Size Extension             MONITOR and MWAIT instructions (SSE3)
 *      4       tsc Time Stamp Counter              ds-cpl   CPL qualified debug store
 *      5       msr Model-specific registers        vmx   Virtual Machine eXtensions
 *      6       pae Physical Address Extension      smx   Safer Mode Extensions (LaGrande)
 *      7       mce Machine Check Exception         est   Enhanced SpeedStep
 *      8       cx8 CMPXCHG8 (compare-and-swap)     tm2   Thermal Monitor 2
 *      9       apic Onboard APIC                   ssse3   Supplemental SSE3 instructions
 *      11      sep SYSENTER and SYSEXIT            sdbg   Silicon Debug interface
 *      12      mtrr Memory Type Range Registers    fma   Fused multiply-add (FMA3)
 *      13      pge Page Global Enable bit in CR4   cx16   CMPXCHG16B instruction
 *      14      mca Machine check architecture      xtpr   Can disable sending task priority messages
 *      15      cmov Conditional move and FCMOV     pdcm   Perfmon & debug capability
 *      16      pat  Page Attribute Table
 *      17      pse-36  36-bit page size extension  pcid   Process context identifiers (CR4 bit 17)
 *      18      psn                                 dca   Direct cache access for DMA writes[12][13]
 *      19      clfsh                               sse4.1
 *      21      ds                                  x2apic
 *      22      acpi thermal MSRs for ACPI          movbe (big-endian)
 *      23      mmx                                 popcnt
 *      24      fxsr                                tsc-deadline
 *      25      sse (Katmai) Instructions           aes
 *      26      sse2                                xsave
 *      27      ss CPU cache supports self-snoop    osxsave XSAVE enabled by OS
 *      28      htt Hyper-threading                 avx
 *      29      tm Thermal monitor limits temp      f16c half-precision FP support
 *      30      ia64 processor emulating x86        rdrnd
 *      31      pbe                                 hypervisor Running on a hypervisor
 *
 *  EAX=2: Cache and TLB Descriptor information
 *    This returns a list of cache and TLB capabilities in EAX, EBX, ECX and EDX registers.
 *
 *  EAX=3: Processor Serial Number
 *
 *  EAX=4 and EAX=Bh: Intel thread/core and cache topology
 *
 *  EAX=7, ECX=0: Extended Features
 *    Bit     EBX                                     ECX
 *    0       fsgsbase                                prefetchwt1   PREFETCHWT1 instruction
 *    1       IA32_TSC_ADJUST                         avx512vbmi
 *    2       sgx Software Guard Extensions           umip   User-mode Instruction Prevention
 *    3       bmi1  Bit Manipulation Set 1            pku   Memory Protection Keys for User-mode pages
 *    4       hle Transactional Synchronization       ospke   PKU enabled by OS
 *    5       avx2 Advanced Vector Extensions 2
 *    7       smep Supervisor-Mode Execution Prevent
 *    8       bmi2 Bit Manipulation                   gfni  Galois Field instructions
 *    9       erms Enhanced REP MOVSB/STOSB           vaes  Vector AES instruction set (VEX-256/EVEX)
 *    10      invpcid                                 vpclmulqdq
 *    11      rtm  Transactional Synchronization      avx512vnni
 *    12      pqm  Platform Service Monitoring        avx512bitalg   AVX-512 BITALG instructions
 *    14      mpx  Intel MPX                          avx512vpopcntdq
 *    15      pqe  Platform QOS
 *    16      avx512f
 *    17      avx512dq
 *    18      rdseed RDSEED instruction
 *    19      adx
 *    20      smap Supervisor Mode Access Prevention
 *    21      avx512ifma
 *    22      pcommit                                 rdpid   Read Processor ID
 *    23      clflushopt
 *    24      clwb
 *    25      intel_pt Processor Trace
 *    26      avx512pf  Prefetch Instructions
 *    27      avx512er  Exponential and Reciprocal
 *    28      avx512cd  Conflict Detection
 *    29      sha
 *    30      avx512bw
 *    31      avx512vl
 *
 *    Bit     EDX
 *    2       avx512_4vnniw   AVX-512 4-register Neural Network Instructions
 *    3       avx512_4fmaps   AVX-512 4-register Multiply Accumulation Single precision
 *    18      pconfig   Memory Encryption Technologies Instructions
 *    26      spec_ctrl
 *    29     IA32_ARCH_CAPABILITIES
 *    31     Speculative Store Bypass Disable (SSBD)
 *
 *  EAX=80000000h: Get Highest Extended Function Supported
 *    The highest calling parameter is returned in EAX.
 *
 *   EAX=2: Cache and TLB Descriptor information
 *     Returns descriptors indicating cache and TLB capabilities in EAX, EBX, ECX and EDX
 *
 *  EAX=3: Processor Serial Number
 *  EAX=80000000h: Get Highest Extended Function Supported
 *     The highest calling parameter is returned in EAX.
 *
 *  EAX=80000001h: Extended Processor Info and Feature Bits
 *     This returns extended feature flags in EDX and ECX.
 *
 *  EAX=80000002h,80000003h,80000004h: Processor Brand String
 *  EAX=80000005h: L1 Cache and TLB Identifiers
 *      This function contains the processor’s L1 cache and TLB characteristics.
 *
 *  EAX=80000006h: Extended L2 Cache Features
 *  EAX=80000007h: Advanced Power Management Information
 *     This function provides advanced power management feature identifiers.
 *
 *  EAX=80000008h: Virtual and Physical address Sizes
 *      Returns largest virtual and physical address sizes in EAX.
 */

#define MAXCALL 64
char* rgCallName[MAXCALL] = {
  (char*) "vendor id",                        // 0
  (char*) "capabilities",                     // 1
  (char*) "cache and tlb",                    // 2
  (char*) "psn",                              // 3
  (char*) "cache parameters",                 // 4
  (char*) "monitor/mwait",                    // 5
  (char*) "thermal",                          // 6
  (char*) "extended features",                // 7
  (char*) "reserved",                         // 8
  (char*) "cache enable",                     // 9
  (char*) "performance monitor",              // 10, 0xa
  (char*) "x2APIC",         // 11, 0xb
  (char*) "reserved",       // 12, 0xc
  (char*) "xsave",          // 13, 0xd
  (char*) "processor trace",        // 14, 0xe
  (char*) "bus and core",        // 15, 0xf

  (char*) "architectural performance",        // 16, 0x10
  (char*) "x2APIC",         // 17, 0x11
  (char*) "sgx",            // 18, 0x12
  (char*) "new",            // 19, 0x13
  (char*) "processor trace",// 20, 0x14
  (char*) "bus",            // 21, 0x15
  (char*) "new",            // 22, 0x16
  (char*) "soc",            // 23, 0x17
  (char*) "tlb",            // 24, 0x18
  (char*) "new",            // 25, 0x19
  (char*) "new",            // 26, 0x1a
  (char*) "new",            // 27, 0x1b
  (char*) "new",            // 28, 0x1c
  (char*) "new",            // 29, 0x1d
  (char*) "new",            // 30, 0x1e
  (char*) "new",            // 31, 0x1f

  (char*) "new",            // 32, 0x20
  (char*) "tdx",            // 33, 0x21
  (char*) "new",            // 34, 0x22
  (char*) "new",            // 35, 0x23
  (char*) "new",            // 36, 0x24
  (char*) "new",            // 37, 0x25
  (char*) "new",            // 38, 0x26
  (char*) "new",            // 39, 0x27
  (char*) "new",            // 40, 0x28
  (char*) "new",            // 41, 0x29
  (char*) "new",            // 42, 0x2a
  (char*) "new",            // 43, 0x2b
  (char*) "new",            // 44, 0x2c
  (char*) "new",            // 46, 0x2d
  (char*) "new",            // 46, 0x2e
  (char*) "new",            // 47, 0x2f

  (char*) "new",            // 48, 0x30
  (char*) "new",            // 49, 0x31
  (char*) "new",            // 50, 0x32
  (char*) "new",            // 51, 0x33
  (char*) "new",            // 52, 0x34
  (char*) "new",            // 53, 0x35
  (char*) "new",            // 54, 0x36
  (char*) "new",            // 55, 0x37
  (char*) "new",            // 56, 0x38
  (char*) "new",            // 57, 0x39
  (char*) "svm",            // 58, 0x3a
  (char*) "encrypted memory",// 59, 0x3b
  (char*) "new",            // 60, 0x3c
  (char*) "new",            // 61, 0x3d
  (char*) "new",            // 62, 0x3e
  (char*) "new",            // 63, 0x3f

};


struct cpuCapability {
  int   offset;
  char*   feature;
};

struct cpuCapability EDXCapability[32]= {
  0, (char*)"fpu onboard",
  1, (char*)"vme virtual mode extensions",
  2, (char*)"de  debugging extensions",
  3, (char*)"pse page size extensions",
  4, (char*)"tsc time Stamp Counter",
  5, (char*)"msr model-specific registers",
  6, (char*)"pae physical Address extension",
  7, (char*)"mce machine Check Exception  ",
  8, (char*)"cx8 mMPXCGH8 instruction",
  9, (char*)"apic on-chip APIC",
  -10, (char*) "(reserved)",
  11, (char*)"SYSENTER and SYSEXIT instructions",
  12, (char*)"mtrr memory-type range registers",
  13, (char*)"pge TLB not flushed on task transition",
  14, (char*)"mca Machine check",
  15, (char*)"cmov Conditional move",
  16, (char*)"pat Page Attribute Table",
  17, (char*)"pse36 36-bit page huge pages ",
  18, (char*)"pn Processor Serial Number dca",
  19, (char*)"clflush CLFLUSH instruction",
  -20, (char*)"(reserved)",
  21, (char*)"dts save trace of jumps",
  22, (char*)"acp power managementi",
  23, (char*)"mmx MMX instructions",
  24, (char*)"fxsr",
  25, (char*)"sse SSE instructions",
  26, (char*)"sse2 SSE2 instructions ",
  27, (char*)"ss CPU cache supports self-snoop",
  28, (char*)"ht Hyper-threading ",
  29, (char*)"tm Thermal limits temperature ",
  30, (char*)"ia64 processor emulating x86",
  31, (char*)"pbe Pending Break Enable",
};

struct cpuCapability ECXCapability[32]= {
  0, (char*)"pni Prescott SSE",
  1, (char*)"pclmulqdq PCLMULQDQ support",
  2, (char*)"64-bit debug store (edx bit 21)",
  3, (char*)"MONITOR and MWAIT instructions (SSE3)",
  4, (char*)"CPL qualified debug store",
  5, (char*)"vmx Virtual Machine eXtensions",
  6, (char*)"smx Safer Mode Extensions (LaGrande)",
  7, (char*)"est Enhanced SpeedStep",
  8, (char*)"tm2 Thermal Monitor 2",
  9, (char*)"ssse3 Suplemental SSE3 instructions",
  10, (char*)"cid Context ID",
  -11, (char*)"(reserved)",
  12, (char*)"Fused multiply-add (FMA3)",
  13, (char*)"cx16 CMPXCHG16B instruction",
  14, (char*)"xtpr Can disable sending task priority messages",
  15, (char*)"pdcm Perfmon & debug capability",
  -16, (char*)"(reserved)",
  17, (char*)"pcid Process context identifiers (CR4 bit 17)",
  18, (char*)"dca Direct cache access for DMA writes[8][9]",
  19, (char*)"sse4_1 SSE4.1 instructions",
  20, (char*)"sse4_2 SSE4.2 instructions",
  21, (char*)"x2apic x2APIC support",
  22, (char*)"movbe MOVBE instruction (big-endian, Intel Atom only)",
  23, (char*)"popcnt POPCNT instruction",
  24, (char*)"tscdeadline APIC supports one-shot operation ",
  25, (char*)"aes AES instruction set",
  26, (char*)"xsave XSAVE, XRESTOR, XSETBV, XGETBV",
  27, (char*)"osxsave XSAVE enabled by OS",
  28, (char*)"avx Advanced Vector Extensions",
  29, (char*)"f16c CVT16 instruction set",
  30, (char*)"rdrnd RDRAND (on-chip random number generator) support",
  31, (char*)"hypervisor",
};

struct cpuCapability EBX2Capability[32]= {
   0,   (char*)"fsgsbase",
   1,   (char*)"IA32_TSC_ADJUST",
   2,   (char*)"sgx",
   3,   (char*)"bmi1",
   4,   (char*)"hle",
   5,   (char*)"avx2",
   -6,  (char*)"",
   7,   (char*)"smep",
   8,   (char*)"bmi2",
   9,   (char*)"erms",
  10,   (char*)"invpcid",
  11,   (char*)"rtm ",
  12,   (char*)"pqm",
  -13,  (char*)"",
  14,   (char*)"mpx",
  15,   (char*)"pqe",
  16,   (char*)"avx512f",
  17,   (char*)"avx512dq ",
  18,   (char*)"rdseed",
  19,   (char*)"adx",
  20,   (char*)"smap",
  21,   (char*)"avx512ifma",
  22,   (char*)"pcommit",
  23,   (char*)"clflushopt",
  24,   (char*)"clwb ",
  25,   (char*)"intel_pt",
  26,   (char*)"avx512pf",
  27,   (char*)"avx512er",
  28,   (char*)"avx512cd",
  29,   (char*)"sha",
  30,   (char*)"avx512bw ",
  31,   (char*)"avx512vl",
};

struct cpuCapability ECX2Capability[32]= {
   0,   (char*)"prefetchwt1",
   1,   (char*)"avx512vbmi",
   2,   (char*)"umip",
   3,   (char*)"pku",
   4,   (char*)"ospke",
   -5,  (char*)"",
   -6,  (char*)"",
   -7,  (char*)"",
   8,   (char*)"gfni",
   9,   (char*)"vaes",
   10,  (char*)"vpclmulqdq ",
   11,  (char*)"avx512vnni ",
   12,  (char*)"avx512bitalg",
   -13, (char*)"",
   14,  (char*)"avx512vpopcntdq",
   -15, (char*)"",
   -16, (char*)"",
   -17, (char*)"",
   -18, (char*)"",
   -19, (char*)"",
   20, (char*)"smap",
   -21, (char*)"",
   22,  (char*)"rdpid",
   -23,  (char*)"",
   -24,  (char*)"",
   -25,  (char*)"",
   -26,  (char*)"",
   -27,  (char*)"",
   -28,  (char*)"",
   -29,  (char*)"",
   -30,  (char*)"",
   -31,  (char*)"",
};

struct cpuCapability EDX2Capability[32]= {
   0,   (char*)"",
   -1,   (char*)"",
   2,   (char*)"avx512_4vnniw",
   3,   (char*)"avx512_4fmaps",
   -4,   (char*)"",
   -5,  (char*)"",
   -6,  (char*)"",
   -7,  (char*)"",
   -8,   (char*)"",
   -9,   (char*)"",
   -10,  (char*)"",
   -11,  (char*)"",
   -12,  (char*)"",
   -13, (char*)"",
   -14,  (char*)"",
   -15, (char*)"",
   -16, (char*)"",
   -17, (char*)"",
   18, (char*)"pconfig",
   -19, (char*)"",
   -20, (char*)"",
   -21, (char*)"",
   -22,  (char*)"",
   -23,  (char*)"",
   -24,  (char*)"",
   -25,  (char*)"",
   26,  (char*)"spec_ctrl",
   27,  (char*)"IBC",
   -28,  (char*)"",
   29,  (char*)"IA32_ARCH_CAPABILITIES",
   -30,  (char*)"",
   31,  (char*)"SSBD",
};

void printFeatures(u32 capabilities, struct cpuCapability* rg)
{
  int i;

  for(i = 0; i < 32; i++) {
    if(rg[i].offset < 0)
        continue;
    if(((capabilities>>rg[i].offset)&1)!=0)
        printf("t");
    else
        printf("tNO ");
    printf("%sn", rg[i].feature);
  }
}


// ---------------------------------------------------------------------------------------------


// out[0]: eax
// out[1]: ebx
// out[2]: ecx
// out[3]: edx
void callcpuid(u32 a, u32 b, u32 c, u32 d, u32 out[4]) {
  u32   a1, a2, a3, a4;

  asm volatile(
    "tmovl    %[a], %%eax\n" \
    "tmovl    %[b], %%ebx\n" \
    "tmovl    %[c], %%ecx\n" \
    "tmovl    %[d], %%edx\n" \
    "tcpuid   \n" \
    "tmovl    %%eax, %[a1]\n" \
    "tmovl    %%ebx, %[a2]\n" \
    "tmovl    %%ecx, %[a3]\n" \
    "tmovl    %%edx, %[a4]\n" \
    : [a1] "=m"(a1), [a2] "=m"(a2), [a3] "=m"(a3), [a4] "=m"(a4)
    : [a] "m" (a), [b] "m" (b), [c] "m" (c), [d] "m" (d)
    : "%eax", "%ebx", "%ecx", "%edx");

    out[0]= a1;
    out[1]= a2;
    out[2]= a3;
    out[3]= a4;
}

/*
  AMD Families
    Zen 3 series CPUs and APUs (released 2020)
      Vermeer Ryzen 5000 series (desktop)
      Chagall Ryzen Threadripper 5000 series (desktop)
      Cezanne Ryzen 5000 series (desktop & laptop)
      Barceló Ryzen 5000 series (laptop)
      Barceló-R Ryzen 7030 series (laptop)
      Milan Epyc 7003 series (server)
      Milan-X Epyc 7003X series (server)

  Zen 3+ series CPUs and APUs (released 2022)
    Rembrandt Ryzen 6000 series (laptop)
    Rembrandt-R Ryzen 7035 series (laptop)

  Zen 4 series CPUs and APUs (released 2022)
    Raphael Ryzen 7000 series (desktop)
    Storm Peak Ryzen Threadripper 7000 series (desktop)
    Dragon Range Ryzen 7045 series (laptop)
    Phoenix Ryzen 8000 APU series (desktop) and Ryzen 7040 series (laptop)
    Hawk Point Ryzen 8040/8045 series (laptop)
    Genoa Epyc 9004 series (server)
    Genoa-X Epyc 9004X series (server)
    Bergamo Epyc 9704 series (server, Zen 4c cores)
    Siena Epyc 8004 series (server, Zen 4c cores)

  Zen 5 series CPUs and APUs (released 2024)
    Granite Ridge Ryzen 9000 series (desktop)
    Strix Point Ryzen AI 300 series (laptop)
    Turin Epyc 9005 series (server)
    Turin Dense Epyc (server, Zen 5c cores)
 */


int main(int an, char** av) {
  u32     a, b;
  u32     retValues[4];
  u32     maxArg= MAXCALL;
  char*   p;
  char*   pLabel;
  u32     ui;

  // Manufacturer info
  a= 0;
  printf("n");
  callcpuid(a, 0, 0, 0,retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  if (maxArg > MAXCALL)
    maxArg = MAXCALL;

  char m_name[14];
  printf("tmaximum input value: %d, ", maxArg);
  p=(char*) &retValues[1];
  printf("%c%c%c%c", *p,*(p+1), *(p+2), *(p+3));
  memcpy(&m_name[0], p, 4);
  p=(char*) &retValues[3];
  printf("%c%c%c%c", *p,*(p+1), *(p+2), *(p+3));
  memcpy(&m_name[4], p, 4);
  p=(char*) &retValues[2];
  printf("%c%c%c%c", *p,*(p+1), *(p+2), *(p+3));
  memcpy(&m_name[8], p, 4);
  printf("n\n");
  m_name[12] = 0;
  printf("manufacturer string: %sn", m_name);

  // AMD info
  if (strcmp("AuthenticAMD", m_name) == 0) {
    a= 0x80000000;
    printf("n");
    callcpuid(a, 0, 0, 0, retValues);
    printf("cpuid(0x%08x): %08x %08x %08x %08x   %sn", a,
            retValues[0], retValues[1], retValues[2], retValues[3],
            "AMD space");
  }

  // To detect if an AMD processor family supports and has enabled SEV-SNP capabilities,
  // hypervisors and operating systems probe CPUID extended leaf 0x8000001F
  if (strcmp("AuthenticAMD", m_name) == 0) {
    a= 0x8000001f;
    printf("n");
    callcpuid(a, 0, 0, 0, retValues);
    printf("cpuid(0x%08x): %08x %08x %08x %08x   %sn", a,
            retValues[0], retValues[1], retValues[2], retValues[3],
            "SEV info");
    if ((retValues[0]&0x1) != 0) {
      printf("        SMEn");
    } else {
      printf("        no SMEn");
    }
    if ((retValues[0]&0x2) != 0) {
      printf("        baseline virtualization supportn");
    } else {
      printf("        no baseline virtualization supportn");
    }
    if ((retValues[0]&0x4) != 0) {
      printf("        encrypted state supportn");
    } else {
      printf("        no encrypted state supportn");
    }
    if ((retValues[0]&0x8) != 0) {
      printf("        SNP supportn");
    } else {
      printf("        no SNP supportn");
    }
  }

  // Processor features
  a= 1;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  b= retValues[0];
  u32 step = b&0xf;
  u32 model = (b>>4)&0xf;
  u32 fam_id = (b>>8)&0xf;
  u32 proc_type = (b>>12)&0xf;
  u32 ex_model = (b>>16)&0xf;
  u32 ex_fam = (b>>20)&0xff;

  printf("tstepping: %x\n", step);
  printf("tmodel: %x\n", model);
  printf("textended model id: %x\n", ex_model);
  printf("tfamily id: %x\n", fam_id);
  printf("textended family id: %x\n", ex_fam);
  printf("tprocessor type: %x\n", proc_type);
  if (strcmp("AuthenticAMD", m_name) == 0) {
    printf("tAMD family group numbering: %d, 0x%02x\n", fam_id + ex_fam, fam_id + ex_fam);
  }

  if (strcmp("AuthenticAMD", m_name) == 0) {
    u32 gen = model + ex_model;
    switch(fam_id + ex_fam) {
      default:
        printf("tAMD unknown family\n");
        break;
      case 23:
        printf("tAMD zen 1/2 family (Ryzen, EPYC Naples\n");
        break;
      case 24:
        printf("tAMD hygon family\n");
        break;
      case 25:
        printf("tAMD zen 3/4 family (Ryzen, Milan), ");
        if (gen >=0 && gen < 0xf || gen >=0x30 && gen < 0x3f) {
          printf(" 3th genn");
        } else if (gen >=0x10 && gen < 0x1f) {
          printf(" 4th genn");
        } else {
          printf(" gen unknownn");
        }
        break;
      case 26:
        printf("tAMD zen 5/6 family (Turin), ");
        printf(" 5th genn");
        break;
    }
  }

  printf("nfeatures:\n");
  printFeatures(retValues[3], EDXCapability);
  printf("n");
  printFeatures(retValues[2], ECXCapability);
  printf("n");

  // cache and TLB
  a= 2;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // cache hierarchy
  a= 4;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // Monitor/mwait
  a= 5;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);
  if ((retValues[2]&0x1) != 0) {
    printf("        EMXn");
  } else {
    printf("        no EMXn");
  }
  if ((retValues[2]&0x2) != 0) {
    printf("        IBEn");
  } else {
    printf("        no IBEn");
  }

  // Thermal and Power
  a= 6;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x (eax) %08x (ebx) %08x (ecx) %08x (edx)  %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);
  if ((retValues[1]&0xf) != 0) {
    printf("        interrupt threshholds : %dn", retValues[1]&0xf);
  }

  // Extended features
  a= 7;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);
  printFeatures(retValues[1], EBX2Capability);
  printf("n");
  printFeatures(retValues[2], ECX2Capability);
  printf("n");
  printFeatures(retValues[3], EDX2Capability);
  printf("n");

  printf("n");
  ui= 0x80000006;
  pLabel= (char*)"extended cache features";
  callcpuid(ui, 0, 0, 0, retValues);
  printf("cpuid(0x%08x): %08x %08x %08x %08x   %sn", ui,
         retValues[0], retValues[1], retValues[2], retValues[3],
         pLabel);

  printf("n");
  ui= 0x80000007;
  pLabel= (char*)"Advanced Power Management";
  callcpuid(ui, 0, 0, 0, retValues);
  printf("cpuid(0x%08x): %08x %08x %08x %08x   %sn", ui,
         retValues[0], retValues[1], retValues[2], retValues[3],
         pLabel);

  printf("n");
  ui= 0x80000008;
  pLabel= (char*)"virtual and physical memory size";
  callcpuid(ui, 0, 0, 0, retValues);
  printf("cpuid(0x%08x): %08x %08x %08x %08x   %sn", ui,
         retValues[0], retValues[1], retValues[2], retValues[3],
         pLabel);

  // sgx
  printf("n");
  a= 0x12;
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);
  if ((retValues[0]&0x1) != 0) {
    printf("        SGX1n");
  } else {
    printf("        SGX2n");
  }
  if ((retValues[0]&0x1000) != 0) {
    printf("        256 Bit SGXn");
  } else {
    printf("        no 256 Bit SGXn");
  }

  // Processor trace
  a= 0x14;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // Bus and Core
  a= 0x15;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // Soc
  a= 0x17;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // TLB again
  a= 0x18;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // TDX
  a= 0x21;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(%d): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[a]);

  // SVM
  printf("n");
  a= 0x8000000a;
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(0x%x): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[0x30+0xa]);
  printf("        SVM revision %dn", retValues[0]&0xff);
  printf("        SVM number of ASIDs%dn", retValues[1]);
  if ((retValues[3]&0x20) != 0) {
    printf("        EMXn");
  } else {
    printf("        no EMXn");
  }

  // Encrypted Memory
  a= 0x8000001f;
  printf("n");
  callcpuid(a, 0, 0, 0, retValues);
  printf("cpuid(0x%x): %08x %08x %08x %08x   %sn", a,
          retValues[0], retValues[1], retValues[2], retValues[3],
          rgCallName[0x30+0x0b]);
  if ((retValues[0]&0x1) != 0) {
    printf("        SMEn");
  } else {
    printf("        no SMEn");
  }
  printf("        c-bit loc %dn", retValues[1]&0x3f);
  printf("        address reduction %dn", (retValues[1]>>6)&0x3f);
  printf("        number vmpls %dn", (retValues[1]>>12)&0x1f);

  return(0);
}


/* --------------------------------------------------------------------- */


