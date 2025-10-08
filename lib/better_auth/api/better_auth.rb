require_relative '../messages/access'
require_relative '../messages/account'
require_relative '../messages/device'
require_relative '../messages/session'

module BetterAuth
  module API
    class BetterAuthServer
      attr_reader :crypto, :encoding, :expiry, :store

      def initialize(crypto:, encoding:, expiry:, store:)
        @crypto = crypto
        @encoding = encoding
        @expiry = expiry
        @store = store
      end
    end

    class CryptoContainer
      attr_accessor :hasher, :key_pair, :noncer, :verifier

      def initialize(hasher:, key_pair:, noncer:, verifier:)
        @hasher = hasher
        @key_pair = key_pair
        @noncer = noncer
        @verifier = verifier
      end
    end

    class ExpiryContainer
      attr_accessor :access, :refresh

      def initialize(access:, refresh:)
        @access = access
        @refresh = refresh
      end
    end

    class KeyPairContainer
      attr_accessor :access, :response

      def initialize(access:, response:)
        @access = access
        @response = response
      end
    end

    class EncodingContainer
      attr_accessor :identity_verifier, :timestamper, :token_encoder

      def initialize(identity_verifier:, timestamper:, token_encoder:)
        @identity_verifier = identity_verifier
        @timestamper = timestamper
        @token_encoder = token_encoder
      end
    end

    class StoresContainer
      attr_accessor :access, :authentication, :recovery

      def initialize(access:, authentication:, recovery:)
        @access = access
        @authentication = authentication
        @recovery = recovery
      end
    end

    class AccessStoreContainer
      attr_accessor :key_hash

      def initialize(key_hash:)
        @key_hash = key_hash
      end
    end

    class AuthenticationStoreContainer
      attr_accessor :key, :nonce

      def initialize(key:, nonce:)
        @key = key
        @nonce = nonce
      end
    end

    class RecoveryStoreContainer
      attr_accessor :hash

      def initialize(hash:)
        @hash = hash
      end
    end
  end
end
