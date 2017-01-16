#ifndef MRUBY_SODIUM_H
#define MRUBY_SODIUM_H

#include <mruby.h>

#ifdef MRB_INT16
# error MRB_INT16 is too small for mruby-libsodium.
#endif

MRB_BEGIN_DECL

#define E_SODIUM_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Sodium"), "Error"))
#define E_CRYPTO_ERROR (mrb_class_get_under(mrb, mrb_module_get(mrb, "Crypto"), "Error"))

MRB_END_DECL

#endif
