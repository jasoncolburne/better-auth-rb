module BetterAuth
  module CryptoInterfaces
    module Verifier
      def signature_length
        raise NotImplementedError
      end

      def verify(signature, public_key, message)
        raise NotImplementedError
      end
    end
  end
end
