#ifndef MRB_LIBSODIUM_H
#define MRB_LIBSODIUM_H

#include <errno.h>
#include <sodium.h>
#include <string.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/numeric.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <mruby/error.h>

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
  #define MRB_LIBSODIUM_GCC (__GNUC__ * 100 + __GNUC_MINOR__)
#else
  #define MRB_LIBSODIUM_GCC 0
#endif

#if (MRB_LIBSODIUM_GCC >= 302) || (__INTEL_COMPILER >= 800) || defined(__clang__)
#  define expect(expr,value)    (__builtin_expect ((expr),(value)) )
#else
#  define expect(expr,value)    (expr)
#endif

#define likely(expr)     expect((expr) != 0, 1)
#define unlikely(expr)   expect((expr) != 0, 0)

#endif
