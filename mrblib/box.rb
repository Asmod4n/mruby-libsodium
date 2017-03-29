module Crypto
  module Box
    def self.keypair(seed = nil)
      sk = Sodium::SecureBuffer.new SECRETKEYBYTES
      pk = nil
      if seed
        pk = seed_keypair(sk, seed)
      else
        pk = _keypair(sk)
      end
      {primitive: PRIMITIVE, public_key: pk, secret_key: sk}
    end

    def self.nonce
      RandomBytes.buf NONCEBYTES
    end
  end
end
