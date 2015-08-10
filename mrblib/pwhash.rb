module Crypto
  module PwHash
    module ScryptSalsa208SHA256
      def self.salt
        RandomBytes.buf SALTBYTES
      end
    end
  end
end
