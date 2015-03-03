#include "mruby/sodium.h"
#include "mrb_libsodium.h"

static mrb_value
mrb_sodium_bin2hex(mrb_state *mrb, mrb_value self)
{
  char *bin;
  mrb_int bin_len;

  mrb_get_args(mrb, "s", &bin, &bin_len);
  char hex[bin_len * 2 + 1];
  sodium_bin2hex(hex, sizeof(hex), (const unsigned char *) bin, (size_t) bin_len);
  return mrb_str_new_cstr(mrb, hex);
}

static mrb_value
mrb_sodium_hex2bin(mrb_state *mrb, mrb_value self)
{
  char *hex, *ignore = NULL;
  mrb_int hex_len, bin_maxlen;
  size_t bin_len;
  int rc;

  mrb_get_args(mrb, "si|z", &hex, &hex_len, &bin_maxlen, &ignore);
  if(bin_maxlen < 0)
    mrb_raise(mrb, E_RANGE_ERROR, "bin_maxlen is too small");

  unsigned char bin[bin_maxlen];
  rc = sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ignore, &bin_len, NULL);
  if(rc == -1)
    mrb_raise(mrb, E_RANGE_ERROR, "bin_maxlen is too small");

  else
    return mrb_str_new(mrb, (const char *) bin, bin_len);
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
  void *buffer;
  mrb_int size;

  buffer = DATA_PTR(self);
  if(buffer)
    mrb_free(mrb, buffer);

  mrb_data_init(self, NULL, &secure_buffer_type);

  mrb_get_args(mrb, "i", &size);
  if (size < 0)
    mrb_raise(mrb, E_RANGE_ERROR, "size mustn't be negative");

  else {
    buffer = sodium_malloc((size_t)size);
    if (buffer == NULL) {
      mrb->out_of_memory = TRUE;
      mrb_exc_raise(mrb, mrb_obj_value(mrb->nomem_err));
    } else {
      mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "size"),
        mrb_fixnum_value(size));
      mrb_data_init(self, buffer, &secure_buffer_type);
    }
  }

  return self;
}

static mrb_value
mrb_secure_buffer_size(mrb_state *mrb, mrb_value self)
{
  return mrb_iv_get(mrb, self,
    mrb_intern_lit(mrb, "size"));
}

static mrb_value
mrb_secure_buffer_noaccess(mrb_state *mrb, mrb_value self)
{
  if (sodium_mprotect_noaccess(DATA_PTR(self)) == -1)
    return mrb_false_value();
  else
    return self;
}

static mrb_value
mrb_secure_buffer_readonly(mrb_state *mrb, mrb_value self)
{
  if (sodium_mprotect_readonly(DATA_PTR(self)) == -1)
    return mrb_false_value();
  else
    return self;
}

static mrb_value
mrb_secure_buffer_readwrite(mrb_state *mrb, mrb_value self)
{
  if (sodium_mprotect_readwrite(DATA_PTR(self)) == -1)
    return mrb_false_value();
  else
    return self;
}

static mrb_value
mrb_randombytes_random(mrb_state *mrb, mrb_value self)
{
  uint32_t ran;

  ran = randombytes_random();
  if (ran > MRB_INT_MAX)
    return mrb_float_value(mrb, ran);
  else
    return mrb_fixnum_value(ran);
}

static mrb_value
mrb_randombytes_uniform(mrb_state *mrb, mrb_value self)
{
  mrb_float upper_bound;
  uint32_t ran;

  mrb_get_args(mrb, "f", &upper_bound);
  if (upper_bound >= 0 && upper_bound <= UINT32_MAX) {
    ran = randombytes_uniform((uint32_t)upper_bound);
    if (ran > MRB_INT_MAX)
      return mrb_float_value(mrb, ran);
    else
      return mrb_fixnum_value(ran);
  } else {
    mrb_raise(mrb, E_RANGE_ERROR, "upper_bound is out of range");
  }
}

static mrb_value
mrb_randombytes_buf(mrb_state *mrb, mrb_value self)
{
  mrb_value buf_obj;

  mrb_get_args(mrb, "o", &buf_obj);

  switch(mrb_type(buf_obj)) {
    case MRB_TT_STRING:
      mrb_str_modify(mrb, RSTRING(buf_obj));
      randombytes_buf(RSTRING_PTR(buf_obj), RSTRING_LEN(buf_obj));
      break;
    case MRB_TT_DATA: {
      int _size = mrb_int(mrb, mrb_funcall(mrb, buf_obj, "size", 0));
      if(_size < 0)
        mrb_raise(mrb, E_RANGE_ERROR, "size mustn't be negative");

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

  if (mrb_respond_to(mrb, data_obj, mrb_intern_lit(mrb, "bytesize")) == TRUE)
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "bytesize", 0));
  else
    obj_size = mrb_int(mrb, mrb_funcall(mrb, data_obj, "size", 0));

  if(obj_size < sodium_const) {
    mrb_raisef(mrb, E_SODIUM_ERROR, "Expected a length >=%S bytes %S, got %S bytes",
      mrb_fixnum_value(sodium_const),
      mrb_str_new_cstr(mrb, reason),
      mrb_fixnum_value(obj_size));
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

  const char *key;

  switch(mrb_type(key_obj)) {
    case MRB_TT_DATA:
      key = DATA_PTR(key_obj);
      break;
    default:
      key = mrb_string_value_ptr(mrb, key_obj);
  }

  mrb_value ciphertext = mrb_str_buf_new(mrb, crypto_secretbox_MACBYTES + message_len);
  mrb_str_modify(mrb, RSTRING(ciphertext));
  crypto_secretbox_easy((unsigned char *) RSTRING_PTR(ciphertext),
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    (const unsigned char *) key);
  mrb_str_resize(mrb, ciphertext, crypto_secretbox_MACBYTES + message_len);

  return ciphertext;
}

static mrb_value
mrb_crypto_secretbox_open_easy(mrb_state *mrb, mrb_value self)
{
  char *ciphertext;
  mrb_int ciphertext_len;
  mrb_value nonce, key_obj;

  mrb_get_args(mrb, "sSo", &ciphertext, &ciphertext_len, &nonce, &key_obj);
  mrb_sodium_check_length(mrb, nonce, crypto_secretbox_NONCEBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_secretbox_KEYBYTES, "key");

  const char *key;

  switch(mrb_type(key_obj)) {
    case MRB_TT_DATA:
      key = DATA_PTR(key_obj);
      break;
    default:
      key = mrb_string_value_ptr(mrb, key_obj);
  }

  unsigned char decrypted[ciphertext_len - crypto_secretbox_MACBYTES];
  int rc = crypto_secretbox_open_easy(decrypted,
    (const unsigned char *) ciphertext, (unsigned long long) ciphertext_len,
    (const unsigned char *) RSTRING_PTR(nonce),
    (const unsigned char *) key);

  if(rc == -1)
    mrb_raise(mrb, E_SODIUM_ERROR, "Message forged!");

  return mrb_str_new(mrb, (char *) decrypted, sizeof(decrypted));
}

static mrb_value
mrb_crypto_auth(mrb_state *mrb, mrb_value self)
{
  char *message;
  mrb_int message_len;
  mrb_value key_obj;

  mrb_get_args(mrb, "so", &message, &message_len, &key_obj);

  mrb_sodium_check_length(mrb, key_obj, crypto_auth_KEYBYTES, "key");

  const char *key;

  switch(mrb_type(key_obj)) {
    case MRB_TT_DATA:
      key = DATA_PTR(key_obj);
      break;
    default:
      key = mrb_string_value_ptr(mrb, key_obj);
  }

  mrb_value mac = mrb_str_buf_new(mrb, crypto_auth_BYTES);
  mrb_str_modify(mrb, RSTRING(mac));
  crypto_auth((unsigned char *) RSTRING_PTR(mac),
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) key);
  mrb_str_resize(mrb, mac, crypto_auth_BYTES);

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

  const char *key;

  switch(mrb_type(key_obj)) {
    case MRB_TT_DATA:
      key = DATA_PTR(key_obj);
      break;
    default:
      key = mrb_string_value_ptr(mrb, key_obj);
  }

  int rc = crypto_auth_verify((const unsigned char *) RSTRING_PTR(mac),
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) key);

  switch(rc) {
    case -1:
      return mrb_false_value();
    case 0:
      return mrb_true_value();
    default:
      mrb_raisef(mrb, E_SODIUM_ERROR, "crypto_auth_verify returned erroneous value %S", mrb_fixnum_value(rc));
  }
}

static mrb_value
mrb_crypto_aead_chacha20poly1305_encrypt(mrb_state *mrb, mrb_value self)
{
  char *message, *additional_data = NULL;
  mrb_int message_len, additional_data_len = 0;
  mrb_value nonce, key_obj;

  mrb_get_args(mrb, "sSo|s", &message, &message_len, &nonce, &key_obj, &additional_data, &additional_data_len);

  mrb_sodium_check_length(mrb, nonce, crypto_aead_chacha20poly1305_NPUBBYTES, "nonce");
  mrb_sodium_check_length(mrb, key_obj, crypto_aead_chacha20poly1305_KEYBYTES, "key");

  const char *key;

  switch(mrb_type(key_obj)) {
    case MRB_TT_DATA:
      key = DATA_PTR(key_obj);
      break;
    default:
      key = mrb_string_value_ptr(mrb, key_obj);
  }

  unsigned char ciphertext[message_len + crypto_aead_chacha20poly1305_ABYTES];
  unsigned long long ciphertext_len;

  crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
    (const unsigned char *) message, (unsigned long long) message_len,
    (const unsigned char *) additional_data, (unsigned long long) additional_data_len,
    NULL, (const unsigned char *) RSTRING_PTR(nonce),
    (const unsigned char *) key);

  return mrb_str_new(mrb, (const char *) ciphertext, (size_t) ciphertext_len);
}

void
mrb_mruby_libsodium_gem_init(mrb_state* mrb) {
  struct RClass *sodium_mod, *secure_buffer_cl, *randombytes_mod, *crypto_mod, *crypto_aead_mod, *crypto_aead_chacha20poly1305_mod;

  sodium_mod = mrb_define_module(mrb, "Sodium");
  mrb_define_class_under(mrb, sodium_mod, "Error", E_RUNTIME_ERROR);
  mrb_define_module_function(mrb, sodium_mod, "bin2hex", mrb_sodium_bin2hex, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, sodium_mod, "hex2bin", mrb_sodium_hex2bin, MRB_ARGS_ARG(2, 1));

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
  mrb_define_module_function(mrb, crypto_mod, "secretbox",      mrb_crypto_secretbox_easy,      MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_mod, "secretbox_open", mrb_crypto_secretbox_open_easy, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_mod, "auth",           mrb_crypto_auth,                MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, crypto_mod, "auth_verify",    mrb_crypto_auth_verify,         MRB_ARGS_REQ(3));
  crypto_aead_mod = mrb_define_module_under(mrb, crypto_mod, "AEAD");
  crypto_aead_chacha20poly1305_mod = mrb_define_module_under(mrb, crypto_aead_mod, "Chacha20Poly1305");
  mrb_define_module_function(mrb, crypto_aead_chacha20poly1305_mod, "encrypt", mrb_crypto_aead_chacha20poly1305_encrypt, MRB_ARGS_ARG(3, 1));
  //mrb_define_module_function(mrb, crypto_aead_chacha20poly1305_mod, "decrypt", mrb_crypto_aead_chacha20poly1305_decrypt, MRB_ARGS_ARG(3, 1));

  if (sodium_init() == -1)
    mrb_raise(mrb, E_SODIUM_ERROR, "Cannot initialize libsodium");
}

void
mrb_mruby_libsodium_gem_final(mrb_state* mrb) {
  /* finalizer */
}

