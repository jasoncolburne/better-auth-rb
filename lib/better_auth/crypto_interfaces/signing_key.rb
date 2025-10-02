require_relative 'verification_key'

module BetterAuth
  module CryptoInterfaces
    module SigningKey
      include VerificationKey

      def sign(message)
        raise NotImplementedError
      end
    end
  end
end
