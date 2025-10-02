require 'json'
require_relative '../messages/access'

module BetterAuth
  module API
    class AccessVerifier
      attr_reader :crypto, :encoding, :store

      def initialize(crypto:, encoding:, store:)
        @crypto = crypto
        @encoding = encoding
        @store = store
      end

      def verify(message, attributes)
        request = Messages::AccessRequest.parse(message)

        access_public_key = @crypto.public_key.public

        identity, attributes = request.verify_access(
          @store.access_nonce,
          @crypto.verifier,
          @crypto.public_key.verifier,
          access_public_key,
          @encoding.token_encoder,
          @encoding.timestamper,
          attributes
        )

        [identity, attributes]
      end
    end

    class VerifierCryptoContainer
      attr_accessor :public_key, :verifier

      def initialize(public_key:, verifier:)
        @public_key = public_key
        @verifier = verifier
      end
    end

    class VerifierEncodingContainer
      attr_accessor :token_encoder, :timestamper

      def initialize(token_encoder:, timestamper:)
        @token_encoder = token_encoder
        @timestamper = timestamper
      end
    end

    class VerifierStoreContainer
      attr_accessor :access_nonce

      def initialize(access_nonce:)
        @access_nonce = access_nonce
      end
    end
  end
end
