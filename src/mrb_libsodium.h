#ifndef MRB_LIBSODIUM_H
#define MRB_LIBSODIUM_H

#include <assert.h>
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
#include <mruby/secure_compare.h>

static void
mrb_secure_buffer_destroy(mrb_state *mrb, void *p)
{
  sodium_free(p);
}

static const struct mrb_data_type secure_buffer_type = {
  "$mrb_i_secure_buffer", mrb_secure_buffer_destroy,
};

static const struct mrb_data_type generic_hash_type = {
  "$mrb_i_generic_hash_state", mrb_free,
};

#endif
