module Crypto
  module Auth
    class << self
      def key
        key = Sodium::SecureBuffer.new KEYBYTES
        {primitive: PRIMITIVE, key: RandomBytes.buf(key)}
      end
    end
  end
end
