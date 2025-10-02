require_relative '../crypto/nonce'

module Examples
  module Storage
    class InMemoryAuthenticationNonceStore
      def initialize(nonce_lifetime)
        @data_by_nonce = {}
        @lifetime = nonce_lifetime
        @nonce_expirations = {}
        @noncer = Crypto::Noncer.new
      end

      def generate(identity)
        nonce = @noncer.generate128
        @data_by_nonce[nonce] = identity
        @nonce_expirations[nonce] = Time.now + @lifetime

        nonce
      end

      def verify(nonce)
        identity = @data_by_nonce[nonce]
        raise 'nonce not found' unless identity

        expiration = @nonce_expirations[nonce]
        raise 'expiration not found' unless expiration

        raise 'expired nonce' if Time.now > expiration

        identity
      end
    end
  end
end
