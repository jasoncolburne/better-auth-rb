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

        token = request.verify_access(
          @store.access_nonce,
          @crypto.verifier,
          @store.access_key_store,
          @encoding.token_encoder,
          @encoding.timestamper,
          attributes
        )

        [request.payload.request, token]
      end
    end

    class VerifierCryptoContainer
      attr_accessor :verifier

      def initialize(verifier:)
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
      attr_accessor :access_nonce, :access_key_store

      def initialize(access_nonce:, access_key_store:)
        @access_nonce = access_nonce
        @access_key_store = access_key_store
      end
    end
  end
end
