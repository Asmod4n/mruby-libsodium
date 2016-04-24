module Crypto
  module PwHash
    def self.salt
      RandomBytes.buf SALTBYTES
    end

    module ScryptSalsa208SHA256
      def self.salt
        RandomBytes.buf SALTBYTES
      end
    end
  end
end
