module Crypto
  module AEAD
    def self.nonce
      RandomBytes.buf "\0" * NPUBBYTES
    end
  end
end
