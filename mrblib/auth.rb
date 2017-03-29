module Crypto
  module Auth
    def self.key
      key = Sodium::SecureBuffer.new KEYBYTES
      {primitive: PRIMITIVE, key: RandomBytes.buf(key)}
    end
  end
end
