module BetterAuth
  module CryptoInterfaces
    module VerificationKey
      def verifier
        raise NotImplementedError
      end

      def public
        raise NotImplementedError
      end
    end
  end
end
