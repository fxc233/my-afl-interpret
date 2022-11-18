/*
   american fuzzy lop - wrapper for GCC and clang
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
static u8** cc_params;              /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
static u8   be_quiet,               /* Quiet mode                        */
            clang_mode;             /* Invoked as afl-clang*?            */


/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

static void find_as(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");       // 获取环境变量 AFL_PATH
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/as", afl_path); // 拼接，并为afl_path/as分配内存

    if (!access(tmp, X_OK)) {              // 判断tmp所指的是否存在
      as_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');              // 获取最后一个'/'

  if (slash) {

    u8 *dir;

    *slash = 0;                              // 最后一个'/'及之后的数据清空
    dir = ck_strdup(argv0);                  // 为最后一个'/'之前的路径分配内存
    *slash = '/';

    tmp = alloc_printf("%s/afl-as", dir);    // 拼接，并为dir/afl-as分配内存

    if (!access(tmp, X_OK)) {                // 判断tmp所指的是否存在
      as_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
 
}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0;
  u8 *name;

#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));      // 分配一大块内存，长度为 (argc + 128) * 8

  name = strrchr(argv[0], '/');                          // 获取 argv[0] 的最后一个 '/' 的位置，并且将其赋给 name
  if (!name) name = argv[0]; else name++;                // 如果没有获取到 '/'，那么 name = argv[0]，否则name++，使得 *name = '/'之后的字符串

  if (!strncmp(name, "afl-clang", 9)) {                  // 如果 strncmp(name, "afl-clang", 9) == 0

    clang_mode = 1;                                      // 设置 clang_mode = 1

    setenv(CLANG_ENV_VAR, "1", 1);                       // 设置环境变量 CLANG_ENV_VAR 为 1

    if (!strcmp(name, "afl-clang++")) {                  // 判断 *name 是否等于 "afl-clang++"
      u8* alt_cxx = getenv("AFL_CXX");                   // 获取环境变量 AFL_CXX
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++"; // 设置 cc_params[0]
    } else {
      u8* alt_cc = getenv("AFL_CC");                     // 获取环境变量 AFL_CC
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";     // 设置 cc_params[0]
    }

  } else {

    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh. */

#ifdef __APPLE__

    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX");
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ");
    else cc_params[0] = getenv("AFL_CC");

    if (!cc_params[0]) {                                // 如果 cc_params[0] == 0，抛出异常

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else

    if (!strcmp(name, "afl-g++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
    } else if (!strcmp(name, "afl-gcj")) {
      u8* alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
    }

#endif /* __APPLE__ */

  }

  while (--argc) {                                      // 遍历从 argv[1] 开始的参数
    u8* cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {                       // 跳过 -B

      if (!be_quiet) WARNF("-B is already set, overriding");

      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-integrated-as")) continue;       // 跳过 -integrated-as

    if (!strcmp(cur, "-pipe")) continue;                // 跳过 -pipe

#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1; // 如果存在 "-fsanitize=address" 或者 "-fsanitize=memory" 就设置 asan_set = 1

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;  // 如果存在 "FORTIFY_SOURCE" 就设置 fortify_set = 1

    cc_params[cc_par_cnt++] = cur;                       // 把参数加到数组里

  }

  cc_params[cc_par_cnt++] = "-B";                        // 加上 -B as_path
  cc_params[cc_par_cnt++] = as_path;

  if (clang_mode)                                        // 如果是 clang 模式，那么加上 -no-integrated-as
    cc_params[cc_par_cnt++] = "-no-integrated-as";

  if (getenv("AFL_HARDEN")) {                            // 如果存在 AFL_HARDEN 就加上 -fstack-protector-all

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (asan_set) {                                       // 如果 asan_set 被设置为 1，那么就设置环境变量 AFL_USE_ASAN 为 1

    /* Pass this on to afl-as to adjust map density. */

    setenv("AFL_USE_ASAN", "1", 1);

  } else if (getenv("AFL_USE_ASAN")) {                  // 如果存在环境变量 AFL_USE_ASAN 并且不存在环境变量 AFL_USE_MSAN 和 AFL_HARDEN
                                                        // 那么就添加 -U_FORTIFY_SOURCE -fsanitize=address
    if (getenv("AFL_USE_MSAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";

  } else if (getenv("AFL_USE_MSAN")) {                 // 如果存在环境变量 AFL_USE_MSAN 并且不存在环境变量 AFL_USE_ASAN 和 AFL_HARDEN
                                                       // 那么就添加 -U_FORTIFY_SOURCE -fsanitize=address
    if (getenv("AFL_USE_ASAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";


  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {                    // 如果不存在环境变量 AFL_DONT_OPTIMIZE
                                                         // 就设添加 -g -O3 -funroll-loops -D__AFL_COMPILER=1 -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
#if defined(__FreeBSD__) && defined(__x86_64__)

    /* On 64-bit FreeBSD systems, clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug. */

    if (!clang_mode || !m32_set)
      cc_params[cc_par_cnt++] = "-g";

#else

      cc_params[cc_par_cnt++] = "-g";

#endif

    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the other is shared with libfuzzer. */

    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  }

  if (getenv("AFL_NO_BUILTIN")) {                      // 如果存在环境变量 AFL_NO_BUILTIN，就添加以下编译选项

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

  cc_params[cc_par_cnt] = NULL;

}


/* Main entry point */

int main(int argc, char** argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc or clang, letting you recompile third-party code with the required\n"
         "runtime instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc ./configure\n"
         "  CXX=%s/afl-g++ ./configure\n\n"

         "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
         "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);

    exit(1);

  }

  find_as(argv[0]);                           // 获取使用的汇编器

  edit_params(argc, argv);                    // 编辑编译所用到的参数

  execvp(cc_params[0], (char**)cc_params);    // 调用 execvp 去执行编译

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
