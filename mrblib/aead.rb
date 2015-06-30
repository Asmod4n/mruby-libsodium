module Crypto
  module AEAD
    module Chacha20Poly1305
      def self.nonce
        RandomBytes.buf "\0" * NPUBBYTES
      end
    end
  end
end
