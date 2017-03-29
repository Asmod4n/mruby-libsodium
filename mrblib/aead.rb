module Crypto
  module AEAD
    module Chacha20Poly1305
      def self.nonce
        RandomBytes.buf NPUBBYTES
      end

      def self.key
        key = Sodium::SecureBuffer.new KEYBYTES
        {primitive: "chacha20poly1305", key: RandomBytes.buf(key)}
      end
    end
  end
end
