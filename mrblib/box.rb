module Crypto
  module Box
    def self.nonce
      RandomBytes.buf "\0" * NONCEBYTES
    end
  end
end
