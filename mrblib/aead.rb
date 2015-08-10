module Crypto
  module AEAD
    module Chacha20Poly1305
      class << self
        def nonce
          RandomBytes.buf NPUBBYTES
        end

        def key
          key = Sodium::SecureBuffer.new KEYBYTES
          {primitive: "chacha20poly1305", key: RandomBytes.buf(key)}
        end
      end
    end
  end
end
