module Crypto
  module SecretBox
    def self.nonce
      RandomBytes.buf "\0" * NONCEBYTES
    end
  end
end
