module Crypto
  module Sign
    class << self
      alias :_keypair :keypair

      def keypair(seed = nil)
        sk = Sodium::SecureBuffer.new SECRETKEYBYTES
        pk = nil
        if seed
          pk = seed_keypair(sk, seed)
        else
          pk = _keypair(sk)
        end
        {primitive: PRIMITIVE, public_key: pk, secret_key: sk}
      end
    end
  end
end