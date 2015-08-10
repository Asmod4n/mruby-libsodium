module Crypto
  module SecretBox
    class << self
      def nonce
        RandomBytes.buf NONCEBYTES
      end

      def key
        key = Sodium::SecureBuffer.new KEYBYTES
        {primitive: PRIMITIVE, key: RandomBytes.buf(key)}
      end
    end
  end
end
