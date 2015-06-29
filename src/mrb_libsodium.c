#include "mruby/sodium.h"
#include "mrb_libsodium.h"

static mrb_value
mrb_sodium_bin2hex(mrb_state *mrb, mrb_value self)
{
  char *bin;
  mrb_int bin_len;

  mrb_get_args(mrb, "s", &bin, &bin_len);

  mrb_value hex = mrb_str_new(mrb, NULL, (size_t) bin_len * 2);

  char *h = sodium_bin2hex(RSTRING_PTR(hex), (size_t) RSTRING_LEN(hex) + 1,
    (const unsigned char *) bin, (size_t) bin_len);

  mrb_assert(h);

  return hex;
}

static mrb_value
mrb_sodium_hex2bin(mrb_state *mrb, mrb_value self)
{
  char *hex, *ignore = NULL;
  mrb_int hex_len, bin_maxlen;

  mrb_get_args(mrb, "si|z", &hex, &hex_len, &bin_maxlen, &ignore);

  if (bin_maxlen < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "bin_maxlen mustn't be negative");

  mrb_value bin = mrb_str_buf_new(mrb, (size_t) bin_maxlen);
  size_t bin_len;

  int rc = sodium_hex2bin((unsigned char *) RSTRING_PTR(bin), (size_t) bin_maxlen,
    (const char *) hex, (size_t) hex_len,
    (const char *) ignore,
    &bin_len,
    NULL);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_ARGUMENT_ERROR, "bin_maxlen is too small");
      break;
    case 0:
      return mrb_str_resize(mrb, bin, (mrb_int) bin_len);
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "sodium_hex2bin returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_sodium_hex2bin_dash(mrb_state *mrb, mrb_value self)
{
  mrb_value hex;
  char *ignore = NULL;

  mrb_get_args(mrb, "S|z", &hex, &ignore);

  mrb_str_modify(mrb, RSTRING(hex));
  size_t bin_len;

  int rc = sodium_hex2bin((unsigned char *) RSTRING_PTR(hex), (size_t) RSTRING_CAPA(hex),
   (const char *) RSTRING_PTR(hex), (size_t) RSTRING_LEN(hex),
   (const char *) ignore,
   &bin_len,
   NULL);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_ARGUMENT_ERROR, "bin_maxlen is too small");
      break;
    case 0:
      return mrb_str_resize(mrb, hex, (mrb_int) bin_len);
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "sodium_hex2bin returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_sodium_memcmp(mrb_state *mrb, mrb_value self)
{
  char *b1_, *b2_;
  mrb_int b1_len, b2_len;

  mrb_get_args(mrb, "ss", &b1_, &b1_len, &b2_, &b2_len);

  if (b1_len != b2_len)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "b1 and b2 size differ");

  int rc = sodium_memcmp(b1_, b2_, b1_len);

  switch(rc) {
    case -1:
      return mrb_false_value();
      break;
    case 0:
      return mrb_true_value();
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "sodium_memcmp returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static void
mrb_secure_buffer_free(mrb_state *mrb, void *p)
{
  sodium_free(p);
}

static const struct mrb_data_type secure_buffer_type = {
  "$mrb_i_secure_buffer", mrb_secure_buffer_free,
};

static mrb_value
mrb_secure_buffer_init(mrb_state *mrb, mrb_value self)
{
  void *buffer = NULL;
  mrb_int size;

  mrb_get_args(mrb, "i", &size);

  if (size < 0||size > SIZE_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "size is out of range");

  else {
    buffer = sodium_malloc((size_t) size);
    if (buffer == NULL) {
      mrb->out_of_memory = TRUE;
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    } else {
      mrb_data_init(self, buffer, &secure_buffer_type);
      mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "size"),
        mrb_fixnum_value(size));
    }
  }

  return self;
}

static mrb_value
mrb_secure_buffer_size(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "size"));
}

static mrb_value
mrb_secure_buffer_noaccess(mrb_state *mrb, mrb_value self)
{
  int rc = sodium_mprotect_noaccess(DATA_PTR(self));

  mrb_assert(rc == 0);

  return self;
}

static mrb_value
mrb_secure_buffer_readonly(mrb_state *mrb, mrb_value self)
{
  int rc = sodium_mprotect_readonly(DATA_PTR(self));

  mrb_assert(rc == 0);

  return self;
}

static mrb_value
mrb_secure_buffer_readwrite(mrb_state *mrb, mrb_value self)
{
  int rc = sodium_mprotect_readwrite(DATA_PTR(self));

  mrb_assert(rc == 0);

  return self;
}

static mrb_value
mrb_randombytes_random(mrb_state *mrb, mrb_value self)
{
  uint32_t ran = randombytes_random();
#if !defined(MRB_INT64)
  if (ran > MRB_INT_MAX)
    return mrb_float_value(mrb, ran);
  else
#endif
    return mrb_fixnum_value(ran);
}

static mrb_value
mrb_randombytes_uniform(mrb_state *mrb, mrb_value self)
{
  mrb_float upper_bound;

  mrb_get_args(mrb, "f", &upper_bound);

  if (upper_bound >= 0 && upper_bound <= UINT32_MAX) {
    uint32_t ran = randombytes_uniform((uint32_t) upper_bound);
#if !defined(MRB_INT64)
    if (ran > MRB_INT_MAX)
      return mrb_float_value(mrb, ran);
    else
#endif
      return mrb_fixnum_value(ran);
  }
  else
    mrb_raise(mrb, E_RANGE_ERROR, "upper_bound is out of range");
}

static mrb_value
mrb_randombytes_buf(mrb_state *mrb, mrb_value self)
{
  mrb_value buf_obj;

  mrb_get_args(mrb, "o", &buf_obj);

  switch(mrb_type(buf_obj)) {
    case MRB_TT_STRING:
      mrb_str_modify(mrb, RSTRING(buf_obj));
      randombytes_buf(RSTRING_PTR(buf_obj), (size_t) RSTRING_LEN(buf_obj));
      break;
    case MRB_TT_DATA: {
      mrb_int _size = mrb_int(mrb, mrb_funcall(mrb, buf_obj, "size", 0));
      if (_size < 0||_size > SIZE_MAX)
        mrb_raise(mrb, E_RANGE_ERROR, "size is out of range");

      randombytes_buf(DATA_PTR(buf_obj), (size_t) _size);
      break;
    }
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "only works with Strings or Data Types");
  }

  return buf_obj;
}

static inline void
mrb_sodium_check_length(mrb_state *mrb, mrb_value data_obj, size_t sodium_const, const char *reason)
{
  mrb_int obj_size;

  if (mrb_respond_to(mrb, data_obj, mrb_intern_lit(mrb, "bytesize")))
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "bytesize", 0));
  else
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "size", 0));

  if (obj_size != sodium_const) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "expected a length == %S bytes %S, got %S bytes",
      mrb_fixnum_value(sodium_const),
      mrb_str_new_static(mrb, reason, strlen(reason)),
      mrb_fixnum_value(obj_size));
  }
}

static inline mrb_int
mrb_sodium_check_length_between(mrb_state *mrb, mrb_value data_obj, size_t min, size_t max, const char *reason)
{
  mrb_int obj_size;

  if (mrb_respond_to(mrb, data_obj, mrb_intern_lit(mrb, "bytesize")))
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "bytesize", 0));
  else
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "size", 0));

  if (obj_size < min||obj_size > max) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "expected a length between %S and %S (inclusive) bytes %S, got %S bytes",
      mrb_fixnum_value(min),
      mrb_fixnum_value(max),
      mrb_str_new_static(mrb, reason, strlen(reason)),
      mrb_fixnum_value(obj_size));
  }

  return obj_size;
}

static inline void *
mrb_sodium_get_ptr(mrb_state *mrb, mrb_value obj, const char *reason)
{
  switch(mrb_type(obj)) {
    case MRB_TT_DATA:
      return DATA_PTR(obj);
      break;
    case MRB_TT_STRING:
      return RSTRING_PTR(obj);
      break;
    default:
      mrb_raisef(mrb, E_TYPE_ERROR, "%S can only be a Data or String Type", mrb_str_new_static(mrb, reason, strlen(reason)));
  }
}

static mrb_value
mrb_crypto_secretbox_easy(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value nonce, key_obj;

  mrb_get_args(mrb, "sSo", &message, &message_len, &nonce, &key_obj);

  mrb_sodium_check_length(mrb, nonce, crypto_secretbox_NONCEBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_secretbox_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  mrb_value ciphertext = mrb_str_new(mrb, NULL,
    (size_t) message_len + crypto_secretbox_MACBYTES);

  int rc = crypto_secretbox_easy((unsigned char *) RSTRING_PTR(ciphertext),
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    key);

  mrb_assert(rc == 0);

  return ciphertext;
}

static mrb_value
mrb_crypto_secretbox_open_easy(mrb_state *mrb, mrb_value self)
{
  char *ciphertext;
  mrb_int ciphertext_len;
  mrb_value nonce, key_obj;

  mrb_get_args(mrb, "sSo", &ciphertext, &ciphertext_len, &nonce, &key_obj);

  if (ciphertext_len - crypto_secretbox_MACBYTES < 0)
    mrb_raise(mrb, E_RANGE_ERROR, "ciphertext is too short");

  mrb_sodium_check_length(mrb, nonce, crypto_secretbox_NONCEBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_secretbox_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  mrb_value message = mrb_str_new(mrb, NULL,
    (size_t) ciphertext_len - crypto_secretbox_MACBYTES);

  int rc = crypto_secretbox_open_easy((unsigned char *) RSTRING_PTR(message),
    (const unsigned char *) ciphertext, (unsigned long long) ciphertext_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "message forged!");
      break;
    case 0:
      return message;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_secretbox_open_easy returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_auth(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value key_obj;

  mrb_get_args(mrb, "so", &message, &message_len, &key_obj);

  mrb_sodium_check_length(mrb, key_obj, crypto_auth_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  mrb_value mac = mrb_str_new(mrb, NULL, crypto_auth_BYTES);

  int rc = crypto_auth((unsigned char *) RSTRING_PTR(mac),
    (const unsigned char *) message, (unsigned long long) message_len,
    key);

  mrb_assert(rc == 0);

  return mac;
}

static mrb_value
mrb_crypto_auth_verify(mrb_state *mrb, mrb_value self)
{
  mrb_value mac;
  char *message;
  mrb_int message_len;
  mrb_value key_obj;

  mrb_get_args(mrb, "Sso", &mac, &message, &message_len, &key_obj);

  mrb_sodium_check_length(mrb, mac, crypto_auth_BYTES, "mac");
  mrb_sodium_check_length(mrb, key_obj, crypto_auth_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");

  int rc = crypto_auth_verify((const unsigned char *) RSTRING_PTR(mac),
    (const unsigned char *) message, (unsigned long long) message_len,
    key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "message forged!");
      break;
    case 0:
      return self;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_auth_verify returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_aead_chacha20poly1305_encrypt(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value nonce, key_obj;
  char *additional_data = NULL;
  mrb_int additional_data_len = 0;

  mrb_get_args(mrb, "sSo|s", &message, &message_len, &nonce, &key_obj, &additional_data, &additional_data_len);

  mrb_int sum;
  if (mrb_int_add_overflow(message_len, crypto_aead_chacha20poly1305_ABYTES, &sum))
    mrb_raise(mrb, E_RANGE_ERROR, "message_len is too large");

  mrb_sodium_check_length(mrb, nonce, crypto_aead_chacha20poly1305_NPUBBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_aead_chacha20poly1305_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  mrb_value ciphertext = mrb_str_buf_new(mrb,
    (size_t) sum);
  unsigned long long ciphertext_len;

  int rc = crypto_aead_chacha20poly1305_encrypt((unsigned char *) RSTRING_PTR(ciphertext), &ciphertext_len,
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) additional_data, (unsigned long long) additional_data_len,
    NULL, (const unsigned char *) RSTRING_PTR(nonce),
    key);

  mrb_assert(rc == 0);

  return mrb_str_resize(mrb, ciphertext, (mrb_int) ciphertext_len);
}

static mrb_value
mrb_crypto_aead_chacha20poly1305_decrypt(mrb_state *mrb, mrb_value self)
{
  char *ciphertext;
  mrb_int ciphertext_len;
  mrb_value nonce, key_obj;
  char *additional_data = NULL;
  mrb_int additional_data_len = 0;

  mrb_get_args(mrb, "sSo|s", &ciphertext, &ciphertext_len, &nonce, &key_obj, &additional_data, &additional_data_len);

  mrb_sodium_check_length(mrb, nonce, crypto_aead_chacha20poly1305_NPUBBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_aead_chacha20poly1305_KEYBYTES, "key");

  const unsigned char *key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  mrb_value message = mrb_str_buf_new(mrb, (size_t) ciphertext_len);
  unsigned long long message_len;

  int rc = crypto_aead_chacha20poly1305_decrypt((unsigned char *) RSTRING_PTR(message), &message_len, NULL,
    (const unsigned char *) ciphertext, (unsigned long long) ciphertext_len,
    (const unsigned char *) additional_data, (unsigned long long) additional_data_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "message forged!");
      break;
    case 0:
      return mrb_str_resize(mrb, message, (mrb_int) message_len);
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_aead_chacha20poly1305_decrypt returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_box_keypair(mrb_state *mrb, mrb_value self)
{
  mrb_value secret_key_obj;

  mrb_get_args(mrb, "o", &secret_key_obj);

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_box_SECRETKEYBYTES, "secret_key");

  if (mrb_string_p(secret_key_obj))
    mrb_str_modify(mrb, RSTRING(secret_key_obj));

  unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value public_key = mrb_str_new(mrb, NULL, crypto_box_PUBLICKEYBYTES);

  int rc = crypto_box_keypair((unsigned char *) RSTRING_PTR(public_key), secret_key);

  mrb_assert(rc == 0);

  return public_key;
}

static mrb_value
mrb_crypto_box_seed_keypair(mrb_state *mrb, mrb_value self)
{
  mrb_value secret_key_obj, seed_obj;

  mrb_get_args(mrb, "oo", &secret_key_obj, &seed_obj);

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_box_SECRETKEYBYTES, "secret_key");
  mrb_sodium_check_length(mrb, seed_obj, crypto_box_SEEDBYTES, "seed");

  if (mrb_string_p(secret_key_obj))
    mrb_str_modify(mrb, RSTRING(secret_key_obj));

  unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  const unsigned char *seed = mrb_sodium_get_ptr(mrb, seed_obj, "seed");
  mrb_value public_key = mrb_str_new(mrb, NULL, crypto_box_PUBLICKEYBYTES);

  int rc = crypto_box_seed_keypair((unsigned char *) RSTRING_PTR(public_key), secret_key, seed);

  mrb_assert(rc == 0);

  return public_key;
}

static mrb_value
mrb_crypto_box_easy(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value nonce, public_key, secret_key_obj;

  mrb_get_args(mrb, "sSSo", &message, &message_len, &nonce, &public_key, &secret_key_obj);

  mrb_int sum;
  if (mrb_int_add_overflow(message_len, crypto_box_MACBYTES, &sum))
    mrb_raise(mrb, E_RANGE_ERROR, "message_len is too large");

  mrb_sodium_check_length(mrb, nonce, crypto_box_NONCEBYTES, "nonce");
  mrb_sodium_check_length(mrb, public_key, crypto_box_PUBLICKEYBYTES, "public_key");
  mrb_sodium_check_length(mrb, secret_key_obj, crypto_box_SECRETKEYBYTES, "secret_key");

  const unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value ciphertext = mrb_str_new(mrb, NULL, sum);

  int rc = crypto_box_easy((unsigned char *) RSTRING_PTR(ciphertext),
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    (const unsigned char *) RSTRING_PTR(public_key),
    secret_key);

  mrb_assert(rc == 0);

  return ciphertext;
}

static mrb_value
mrb_crypto_box_open_easy(mrb_state *mrb, mrb_value self)
{
  char *ciphertext;
  mrb_int ciphertext_len;
  mrb_value nonce, public_key, secret_key_obj;

  mrb_get_args(mrb, "sSSo", &ciphertext, &ciphertext_len, &nonce, &public_key, &secret_key_obj);

  if (ciphertext_len - crypto_box_MACBYTES < 0)
    mrb_raise(mrb, E_RANGE_ERROR, "ciphertext is too short");

  mrb_sodium_check_length(mrb, nonce, crypto_box_NONCEBYTES, "nonce");
  mrb_sodium_check_length(mrb, public_key, crypto_box_PUBLICKEYBYTES, "public_key");
  mrb_sodium_check_length(mrb, secret_key_obj, crypto_box_SECRETKEYBYTES, "secret_key");

  const unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value message = mrb_str_new(mrb, NULL, (size_t) ciphertext_len - crypto_box_MACBYTES);

  int rc = crypto_box_open_easy((unsigned char *) RSTRING_PTR(message),
    (const unsigned char *) ciphertext, (unsigned long long) ciphertext_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    (const unsigned char *) RSTRING_PTR(public_key),
    secret_key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "message forged!");
      break;
    case 0:
      return message;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_box_open_easy returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_sign_keypair(mrb_state *mrb, mrb_value self)
{
  mrb_value secret_key_obj;

  mrb_get_args(mrb, "o", &secret_key_obj);

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_sign_SECRETKEYBYTES, "secret_key");

  if (mrb_string_p(secret_key_obj))
    mrb_str_modify(mrb, RSTRING(secret_key_obj));

  unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value public_key = mrb_str_new(mrb, NULL, crypto_sign_PUBLICKEYBYTES);

  int rc = crypto_sign_keypair((unsigned char *) RSTRING_PTR(public_key), secret_key);

  mrb_assert(rc == 0);

  return public_key;
}

static mrb_value
mrb_crypto_sign_seed_keypair(mrb_state *mrb, mrb_value self)
{
  mrb_value secret_key_obj, seed_obj;

  mrb_get_args(mrb, "oo", &secret_key_obj, &seed_obj);

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_sign_SECRETKEYBYTES, "secret_key");
  mrb_sodium_check_length(mrb, seed_obj, crypto_sign_SEEDBYTES, "seed");

  if (mrb_string_p(secret_key_obj))
    mrb_str_modify(mrb, RSTRING(secret_key_obj));

  unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  const unsigned char *seed = mrb_sodium_get_ptr(mrb, seed_obj, "seed");
  mrb_value public_key = mrb_str_new(mrb, NULL, crypto_sign_PUBLICKEYBYTES);

  int rc = crypto_sign_seed_keypair((unsigned char *) RSTRING_PTR(public_key), secret_key, seed);

  mrb_assert(rc == 0);

  return public_key;
}

static mrb_value
mrb_crypto_sign(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value secret_key_obj;

  mrb_get_args(mrb, "so", &message, &message_len, &secret_key_obj);

  mrb_int sum;
  if(mrb_int_add_overflow(message_len, crypto_sign_BYTES, &sum))
    mrb_raise(mrb, E_RANGE_ERROR, "message_len is too large");

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_sign_SECRETKEYBYTES, "secret_key");

  const unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value signed_message = mrb_str_buf_new(mrb, sum);
  unsigned long long signed_message_len;

  int rc = crypto_sign((unsigned char *) RSTRING_PTR(signed_message), &signed_message_len,
    (const unsigned char *) message, (unsigned long long) message_len,
    secret_key);

  mrb_assert(rc == 0);

  return mrb_str_resize(mrb, signed_message, (mrb_int) signed_message_len);
}

static mrb_value
mrb_crypto_sign_open(mrb_state *mrb, mrb_value self)
{
  char *signed_message;
  mrb_int signed_message_len;
  mrb_value public_key_obj;

  mrb_get_args(mrb, "so", &signed_message, &signed_message_len, &public_key_obj);

  mrb_sodium_check_length(mrb, public_key_obj, crypto_sign_PUBLICKEYBYTES, "public_key");

  const unsigned char *public_key = mrb_sodium_get_ptr(mrb, public_key_obj, "public_key");
  mrb_value message = mrb_str_buf_new(mrb, signed_message_len);
  unsigned long long message_len;

  int rc = crypto_sign_open((unsigned char *) RSTRING_PTR(message), &message_len,
    (const unsigned char *) signed_message, (unsigned long long) signed_message_len,
    public_key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "signed message forged!");
      break;
    case 0:
      return mrb_str_resize(mrb, message, (mrb_int) message_len);
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_sign_open returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_sign_detached(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value secret_key_obj;

  mrb_get_args(mrb, "so", &message, &message_len, &secret_key_obj);

  mrb_sodium_check_length(mrb, secret_key_obj, crypto_sign_SECRETKEYBYTES, "secret_key");

  const unsigned char *secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");
  mrb_value signature = mrb_str_buf_new(mrb, crypto_sign_BYTES);
  unsigned long long signature_len;

  int rc = crypto_sign_detached((unsigned char *) RSTRING_PTR(signature), &signature_len,
    (const unsigned char *) message, (unsigned long long) message_len,
    secret_key);

  mrb_assert(rc == 0);

  return mrb_str_resize(mrb, signature, (mrb_int) signature_len);
}

static mrb_value
mrb_crypto_sign_verify_detached(mrb_state *mrb, mrb_value self)
{
  mrb_value signature;
  char *message;
  mrb_int message_len;
  mrb_value public_key_obj;

  mrb_get_args(mrb, "Sso", &signature, &message, &message_len, &public_key_obj);

  mrb_sodium_check_length(mrb, signature, crypto_sign_BYTES, "signature");
  mrb_sodium_check_length(mrb, public_key_obj, crypto_sign_PUBLICKEYBYTES, "public_key");

  const unsigned char *public_key = mrb_sodium_get_ptr(mrb, public_key_obj, "public_key");

  int rc = crypto_sign_verify_detached((const unsigned char *) RSTRING_PTR(signature),
    (const unsigned char *) message, (unsigned long long) message_len,
    public_key);

  switch(rc) {
    case -1:
      mrb_raise(mrb, E_CRYPTO_ERROR, "signature forged!");
      break;
    case 0:
      return self;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_sign_open returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_generichash(mrb_state *mrb, mrb_value self)
{
  mrb_value hash;
  char *in;
  mrb_int inlen, outlen = (mrb_int) crypto_generichash_BYTES;
  mrb_value key_obj = mrb_nil_value();
  unsigned char *key = NULL;
  size_t keylen = 0;

  mrb_get_args(mrb, "s|io", &in, &inlen, &outlen, &key_obj);

  if (outlen < crypto_generichash_BYTES_MIN||outlen > crypto_generichash_BYTES_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "outlen is out of range");

  if (!mrb_nil_p(key_obj)) {
    keylen = (size_t) mrb_sodium_check_length_between(mrb, key_obj,
      crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MAX, "key");
    key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  }

  hash = mrb_str_new(mrb, NULL, (size_t) outlen);

  int rc = crypto_generichash((unsigned char *) RSTRING_PTR(hash), (size_t) RSTRING_LEN(hash),
    (const unsigned char *) in, (unsigned long long) inlen,
    (const unsigned char *) key, keylen);

  mrb_assert(rc == 0);

  return hash;
}

static mrb_value
mrb_crypto_generichash_init(mrb_state *mrb, mrb_value self)
{
  crypto_generichash_state *state;
  unsigned char *key = NULL;
  size_t keylen = 0;
  mrb_int outlen = (mrb_int) crypto_generichash_BYTES;
  mrb_value key_obj = mrb_nil_value();

  mrb_get_args(mrb, "|io", &outlen, &key_obj);

  if (outlen < crypto_generichash_BYTES_MIN||outlen > crypto_generichash_BYTES_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "outlen is out of range");

  if (!mrb_nil_p(key_obj)) {
    keylen = (size_t) mrb_sodium_check_length_between(mrb, key_obj,
      crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MAX, "key");
    key = mrb_sodium_get_ptr(mrb, key_obj, "key");
  }

   state = sodium_malloc((sizeof(crypto_generichash_state)
    + (size_t) 63U) & ~(size_t) 63U);

  if (state) {
    mrb_data_init(self, state, &secure_buffer_type);

    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "hash"),
      mrb_str_new(mrb, NULL, (size_t) outlen));

    int rc = crypto_generichash_init(state,
      (const unsigned char *) key, keylen,
      (size_t) outlen);

    sodium_mprotect_noaccess(state);
    mrb_assert(rc == 0);

    return self;
  } else {
    mrb->out_of_memory = TRUE;
    mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
  }
}

static mrb_value
mrb_crypto_generichash_update(mrb_state *mrb, mrb_value self)
{
  char *in;
  mrb_int inlen;

  mrb_get_args(mrb, "s", &in, &inlen);

  crypto_generichash_state *state = (crypto_generichash_state *) DATA_PTR(self);

  sodium_mprotect_readwrite(state);
  int rc = crypto_generichash_update(state,
    (const unsigned char *) in, (unsigned long long) inlen);
  sodium_mprotect_noaccess(state);

  mrb_assert(rc == 0);

  return self;
}

static mrb_value
mrb_crypto_generichash_final(mrb_state *mrb, mrb_value self)
{
  crypto_generichash_state *state = (crypto_generichash_state *) DATA_PTR(self);
  mrb_value hash = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "hash"));

  sodium_mprotect_readwrite(state);
  int rc = crypto_generichash_final(state,
    (unsigned char *) RSTRING_PTR(hash), (size_t) RSTRING_LEN(hash));
  sodium_mprotect_noaccess(state);

  mrb_assert(rc == 0);

  return hash;
}

static mrb_value
mrb_crypto_pwhash_scryptsalsa208sha256(mrb_state *mrb, mrb_value self)
{
  mrb_value outlen;
  char *passwd;
  mrb_int passwdlen;
  mrb_value salt_obj;
  mrb_int opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
  mrb_int memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

  mrb_get_args(mrb, "oso|ii", &outlen, &passwd, &passwdlen, &salt_obj, &opslimit, &memlimit);

  if (mrb_int(mrb, outlen) < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "outlen mustn't be negative");
  mrb_sodium_check_length(mrb, salt_obj, crypto_pwhash_scryptsalsa208sha256_SALTBYTES, "salt");
  if (opslimit < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "opslimit mustn't be negative");
  if (memlimit < 0||memlimit > SIZE_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "memlimit is out of range");

  const unsigned char * const salt = mrb_sodium_get_ptr(mrb, salt_obj, "salt");
  mrb_value secret_key_obj = mrb_obj_new(mrb,
    mrb_class_get_under(mrb, mrb_module_get(mrb, "Sodium"), "SecureBuffer"), 1, &outlen);
  unsigned char * const secret_key = mrb_sodium_get_ptr(mrb, secret_key_obj, "secret_key");

  errno = 0;
  int rc = crypto_pwhash_scryptsalsa208sha256(secret_key, (unsigned long long) mrb_int(mrb, outlen),
    (const char * const) passwd, (unsigned long long) passwdlen,
    salt,
    (unsigned long long) opslimit,
    (size_t) memlimit);

  switch(rc) {
    case -1: {
      if (errno == ENOMEM) {
        mrb->out_of_memory = TRUE;
        mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
      }
      else
        mrb_raise(mrb, E_SODIUM_ERROR, strerror(errno));
    }
      break;
    case 0:
      return secret_key_obj;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_pwhash_scryptsalsa208sha256 returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_pwhash_scryptsalsa208sha256_str(mrb_state *mrb, mrb_value self)
{
  char *passwd;
  mrb_int passwdlen;
  mrb_int opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
  mrb_int memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

  mrb_get_args(mrb, "s|ii", &passwd, &passwdlen, &opslimit, &memlimit);

  if (opslimit < 0)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "opslimit mustn't be negative");
  if (memlimit < 0||memlimit > SIZE_MAX)
    mrb_raise(mrb, E_RANGE_ERROR, "memlimit is out of range");

  mrb_value out = mrb_str_new(mrb, NULL, crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1);

  errno = 0;
  int rc = crypto_pwhash_scryptsalsa208sha256_str(RSTRING_PTR(out),
    (const char * const) passwd, (unsigned long long) passwdlen,
    (unsigned long long) opslimit,
    (size_t) memlimit);

  switch(rc) {
    case -1: {
      if (errno == ENOMEM) {
        mrb->out_of_memory = TRUE;
        mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
      }
      else
        mrb_raise(mrb, E_SODIUM_ERROR, strerror(errno));
    }
      break;
    case 0:
      return out;
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_pwhash_scryptsalsa208sha256_str returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_pwhash_scryptsalsa208sha256_str_verify(mrb_state *mrb, mrb_value self)
{
  mrb_value str_obj;
  char *passwd;
  mrb_int passwdlen;

  mrb_get_args(mrb, "Ss", &str_obj, &passwd, &passwdlen);

  mrb_sodium_check_length(mrb, str_obj, crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1, "str");

  int rc = crypto_pwhash_scryptsalsa208sha256_str_verify(RSTRING_PTR(str_obj),
    (const char * const) passwd, (unsigned long long) passwdlen);

  switch(rc) {
    case -1:
      return mrb_false_value();
      break;
    case 0:
      return mrb_true_value();
      break;
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_pwhash_scryptsalsa208sha256_str_verify returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

void
mrb_mruby_libsodium_gem_init(mrb_state* mrb) {
  struct RClass *sodium_mod, *secure_buffer_cl, *randombytes_mod, *crypto_mod,
    *crypto_secretbox_mod, *crypto_auth_mod, *crypto_aead_mod,
    *crypto_aead_chacha20poly1305_mod, *crypto_box_mod, *crypto_sign_mod, *crypto_generichash_cl,
    *crypto_pwhash_mod, *crypto_pwhash_scryptsalsa208sha256_mod;

  sodium_mod = mrb_define_module(mrb, "Sodium");
  mrb_define_class_under(mrb, sodium_mod, "Error", E_RUNTIME_ERROR);
  mrb_define_module_function(mrb, sodium_mod, "bin2hex",  mrb_sodium_bin2hex,       MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, sodium_mod, "hex2bin",  mrb_sodium_hex2bin,       MRB_ARGS_ARG(2, 1));
  mrb_define_module_function(mrb, sodium_mod, "hex2bin!", mrb_sodium_hex2bin_dash,  MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, sodium_mod, "memcmp",   mrb_sodium_memcmp,        MRB_ARGS_REQ(2));

  secure_buffer_cl = mrb_define_class_under(mrb, sodium_mod, "SecureBuffer", mrb->object_class);
  MRB_SET_INSTANCE_TT(secure_buffer_cl, MRB_TT_DATA);
  mrb_define_method(mrb, secure_buffer_cl, "initialize",  mrb_secure_buffer_init,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, secure_buffer_cl, "size",        mrb_secure_buffer_size,       MRB_ARGS_NONE());
  mrb_define_method(mrb, secure_buffer_cl, "noaccess",    mrb_secure_buffer_noaccess,   MRB_ARGS_NONE());
  mrb_define_method(mrb, secure_buffer_cl, "readonly",    mrb_secure_buffer_readonly,   MRB_ARGS_NONE());
  mrb_define_method(mrb, secure_buffer_cl, "readwrite",   mrb_secure_buffer_readwrite,  MRB_ARGS_NONE());

  randombytes_mod = mrb_define_module(mrb, "RandomBytes");
  mrb_define_module_function(mrb, randombytes_mod, "random",  mrb_randombytes_random,   MRB_ARGS_NONE());
  mrb_define_module_function(mrb, randombytes_mod, "uniform", mrb_randombytes_uniform,  MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, randombytes_mod, "buf",     mrb_randombytes_buf,      MRB_ARGS_REQ(1));

  crypto_mod = mrb_define_module(mrb, "Crypto");
  mrb_define_class_under(mrb, crypto_mod, "Error", E_RUNTIME_ERROR);
  crypto_secretbox_mod = mrb_define_module_under(mrb, crypto_mod, "SecretBox");
  mrb_define_const(mrb, crypto_secretbox_mod, "KEYBYTES",   mrb_fixnum_value(crypto_secretbox_KEYBYTES));
  mrb_define_const(mrb, crypto_secretbox_mod, "MACBYTES",   mrb_fixnum_value(crypto_secretbox_MACBYTES));
  mrb_define_const(mrb, crypto_secretbox_mod, "NONCEBYTES", mrb_fixnum_value(crypto_secretbox_NONCEBYTES));
  mrb_define_const(mrb, crypto_secretbox_mod, "PRIMITIVE",  mrb_str_new_static(mrb, crypto_secretbox_PRIMITIVE, strlen(crypto_secretbox_PRIMITIVE)));
  mrb_define_module_function(mrb, crypto_mod, "secretbox",      mrb_crypto_secretbox_easy,      MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_secretbox_mod, "open", mrb_crypto_secretbox_open_easy, MRB_ARGS_REQ(2));

  crypto_auth_mod = mrb_define_module_under(mrb, crypto_mod, "Auth");
  mrb_define_const(mrb, crypto_auth_mod, "BYTES",     mrb_fixnum_value(crypto_auth_BYTES));
  mrb_define_const(mrb, crypto_auth_mod, "KEYBYTES",  mrb_fixnum_value(crypto_auth_KEYBYTES));
  mrb_define_module_function(mrb, crypto_mod, "auth",         mrb_crypto_auth,        MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_auth_mod, "verify",  mrb_crypto_auth_verify, MRB_ARGS_REQ(3));

  crypto_aead_mod = mrb_define_module_under(mrb, crypto_mod, "AEAD");
  crypto_aead_chacha20poly1305_mod = mrb_define_module_under(mrb, crypto_aead_mod, "Chacha20Poly1305");
  mrb_define_const(mrb, crypto_aead_chacha20poly1305_mod, "KEYBYTES",   mrb_fixnum_value(crypto_aead_chacha20poly1305_KEYBYTES));
  mrb_define_const(mrb, crypto_aead_chacha20poly1305_mod, "NPUBBYTES",  mrb_fixnum_value(crypto_aead_chacha20poly1305_NPUBBYTES));
  mrb_define_const(mrb, crypto_aead_chacha20poly1305_mod, "ABYTES",     mrb_fixnum_value(crypto_aead_chacha20poly1305_ABYTES));
  mrb_define_module_function(mrb, crypto_aead_chacha20poly1305_mod, "encrypt", mrb_crypto_aead_chacha20poly1305_encrypt, MRB_ARGS_ARG(3, 1));
  mrb_define_module_function(mrb, crypto_aead_chacha20poly1305_mod, "decrypt", mrb_crypto_aead_chacha20poly1305_decrypt, MRB_ARGS_ARG(3, 1));

  crypto_box_mod = mrb_define_module_under(mrb, crypto_mod, "Box");
  mrb_define_const(mrb, crypto_box_mod, "PUBLICKEYBYTES", mrb_fixnum_value(crypto_box_PUBLICKEYBYTES));
  mrb_define_const(mrb, crypto_box_mod, "SECRETKEYBYTES", mrb_fixnum_value(crypto_box_SECRETKEYBYTES));
  mrb_define_const(mrb, crypto_box_mod, "MACBYTES",       mrb_fixnum_value(crypto_box_MACBYTES));
  mrb_define_const(mrb, crypto_box_mod, "NONCEBYTES",     mrb_fixnum_value(crypto_box_NONCEBYTES));
  mrb_define_const(mrb, crypto_box_mod, "SEEDBYTES",      mrb_fixnum_value(crypto_box_SEEDBYTES));
  mrb_define_const(mrb, crypto_box_mod, "BEFORENMBYTES",  mrb_fixnum_value(crypto_box_BEFORENMBYTES));
  mrb_define_const(mrb, crypto_box_mod, "PRIMITIVE",      mrb_str_new_static(mrb, crypto_box_PRIMITIVE, strlen(crypto_box_PRIMITIVE)));
  mrb_define_module_function(mrb, crypto_box_mod, "keypair",      mrb_crypto_box_keypair,       MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, crypto_box_mod, "seed_keypair", mrb_crypto_box_seed_keypair,  MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, crypto_mod,     "box",          mrb_crypto_box_easy,          MRB_ARGS_REQ(4));
  mrb_define_module_function(mrb, crypto_box_mod, "open",         mrb_crypto_box_open_easy,     MRB_ARGS_REQ(4));

  crypto_sign_mod = mrb_define_module_under(mrb, crypto_mod, "Sign");
  mrb_define_const(mrb, crypto_sign_mod, "PUBLICKEYBYTES",  mrb_fixnum_value(crypto_sign_PUBLICKEYBYTES));
  mrb_define_const(mrb, crypto_sign_mod, "SECRETKEYBYTES",  mrb_fixnum_value(crypto_sign_SECRETKEYBYTES));
  mrb_define_const(mrb, crypto_sign_mod, "BYTES",           mrb_fixnum_value(crypto_sign_BYTES));
  mrb_define_const(mrb, crypto_sign_mod, "SEEDBYTES",       mrb_fixnum_value(crypto_sign_SEEDBYTES));
  mrb_define_const(mrb, crypto_sign_mod, "PRIMITIVE",       mrb_str_new_static(mrb, crypto_sign_PRIMITIVE, strlen(crypto_sign_PRIMITIVE)));
  mrb_define_module_function(mrb, crypto_sign_mod,  "keypair",          mrb_crypto_sign_keypair,          MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, crypto_sign_mod,  "seed_keypair",     mrb_crypto_sign_seed_keypair,     MRB_ARGS_ARG(1, 1));
  mrb_define_module_function(mrb, crypto_mod,       "sign",             mrb_crypto_sign,                  MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_sign_mod,  "open",             mrb_crypto_sign_open,             MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_sign_mod,  "detached",         mrb_crypto_sign_detached,         MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_sign_mod,  "verify_detached",  mrb_crypto_sign_verify_detached,  MRB_ARGS_REQ(3));

  crypto_generichash_cl = mrb_define_class_under(mrb, crypto_mod, "GenericHash", mrb->object_class);
  MRB_SET_INSTANCE_TT(crypto_generichash_cl, MRB_TT_DATA);
  mrb_define_const(mrb, crypto_generichash_cl,  "BYTES",        mrb_fixnum_value(crypto_generichash_BYTES));
  mrb_define_const(mrb, crypto_generichash_cl,  "BYTES_MIN",    mrb_fixnum_value(crypto_generichash_BYTES_MIN));
  mrb_define_const(mrb, crypto_generichash_cl,  "BYTES_MAX",    mrb_fixnum_value(crypto_generichash_BYTES_MAX));
  mrb_define_const(mrb, crypto_generichash_cl,  "KEYBYTES",     mrb_fixnum_value(crypto_generichash_KEYBYTES));
  mrb_define_const(mrb, crypto_generichash_cl,  "KEYBYTES_MIN", mrb_fixnum_value(crypto_generichash_KEYBYTES_MIN));
  mrb_define_const(mrb, crypto_generichash_cl,  "KEYBYTES_MAX", mrb_fixnum_value(crypto_generichash_KEYBYTES_MAX));
  mrb_define_const(mrb, crypto_generichash_cl,  "PRIMITIVE",    mrb_str_new_static(mrb,
    crypto_generichash_PRIMITIVE, strlen(crypto_generichash_PRIMITIVE)));
  mrb_define_module_function(mrb, crypto_mod,   "generichash",  mrb_crypto_generichash, MRB_ARGS_ARG(1, 2));
  mrb_define_method(mrb, crypto_generichash_cl, "initialize",   mrb_crypto_generichash_init, MRB_ARGS_OPT(2));
  mrb_define_method(mrb, crypto_generichash_cl, "update",       mrb_crypto_generichash_update, MRB_ARGS_REQ(1));
  mrb_define_alias (mrb, crypto_generichash_cl, "<<", "update");
  mrb_define_method(mrb, crypto_generichash_cl, "final",        mrb_crypto_generichash_final, MRB_ARGS_NONE());

  crypto_pwhash_mod = mrb_define_module_under(mrb, crypto_mod, "PwHash");
  mrb_define_module_function(mrb, crypto_pwhash_mod,  "scryptsalsa208sha256", mrb_crypto_pwhash_scryptsalsa208sha256, MRB_ARGS_ARG(3, 2));
  crypto_pwhash_scryptsalsa208sha256_mod = mrb_define_module_under(mrb, crypto_pwhash_mod, "ScryptSalsa208SHA256");
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "SALTBYTES", mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_SALTBYTES));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "STRBYTES", mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_STRBYTES));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "STRPREFIX",
    mrb_str_new_static(mrb, crypto_pwhash_scryptsalsa208sha256_STRPREFIX, strlen(crypto_pwhash_scryptsalsa208sha256_STRPREFIX)));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "OPSLIMIT_INTERACTIVE",
    mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "MEMLIMIT_INTERACTIVE",
    mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "OPSLIMIT_SENSITIVE",
    mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE));
  mrb_define_const(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "MEMLIMIT_SENSITIVE",
    mrb_fixnum_value(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE));
  mrb_define_module_function(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "str", mrb_crypto_pwhash_scryptsalsa208sha256_str, MRB_ARGS_ARG(1, 2));
  mrb_define_module_function(mrb, crypto_pwhash_scryptsalsa208sha256_mod, "str_verify", mrb_crypto_pwhash_scryptsalsa208sha256_str_verify,
    MRB_ARGS_REQ(2));

  if (sodium_init() == -1)
    mrb_raise(mrb, E_SODIUM_ERROR, "cannot initialize libsodium");
}

void
mrb_mruby_libsodium_gem_final(mrb_state* mrb) {
  /* finalizer */
}

