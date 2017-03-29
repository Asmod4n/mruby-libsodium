module Crypto
  module SecretBox
    def self.nonce
      RandomBytes.buf NONCEBYTES
    end

    def self.key
      key = Sodium::SecureBuffer.new KEYBYTES
      {primitive: PRIMITIVE, key: RandomBytes.buf(key)}
    end
  end
end
