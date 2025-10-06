module BetterAuth
  module CryptoInterfaces
    module Verifier
      def verify(signature, public_key, message)
        raise NotImplementedError
      end
    end
  end
end
