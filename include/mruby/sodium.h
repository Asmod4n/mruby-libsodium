#ifndef MRUBY_SODIUM_H
#define MRUBY_SODIUM_H

#include <mruby.h>

#ifdef __cplusplus
extern "C" {
#endif

#define E_SODIUM_ERROR mrb_class_get_under(mrb, mrb_module_get(mrb, "Sodium"), "Error")
#define E_CRYPTO_ERROR mrb_class_get_under(mrb, mrb_module_get(mrb, "Crypto"), "Error")

#ifdef __cplusplus
}
#endif

#endif
