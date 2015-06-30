module Crypto
  module PwHash
    module ScryptSalsa208SHA256
      def self.salt
        RandomBytes.buf "\0" * SALTBYTES
      end
    end
  end
end
