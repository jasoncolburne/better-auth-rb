# frozen_string_literal: true

module BetterAuth
  module Messages
    # Request to change recovery key
    class ChangeRecoveryKeyRequest < ClientRequest
      def self.payload_class
        ChangeRecoveryKeyRequestPayload
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        auth_data = payload_data[:request][:authentication]
        authentication = ChangeRecoveryKeyRequestAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          recovery_hash: auth_data[:recoveryHash],
          rotation_hash: auth_data[:rotationHash]
        )
        request = ChangeRecoveryKeyRequestPayload.new(authentication: authentication)

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end
    end

    # Payload for change recovery key request
    class ChangeRecoveryKeyRequestPayload
      attr_accessor :authentication

      def initialize(authentication:)
        @authentication = authentication
      end

      def to_h
        {
          authentication: @authentication.to_h
        }
      end

      def self.from_h(hash)
        new(
          authentication: ChangeRecoveryKeyRequestAuthentication.from_h(hash[:authentication])
        )
      end
    end

    # Authentication data for change recovery key request
    class ChangeRecoveryKeyRequestAuthentication
      attr_accessor :device, :identity, :public_key, :recovery_hash, :rotation_hash

      def initialize(device:, identity:, public_key:, recovery_hash:, rotation_hash:)
        @device = device
        @identity = identity
        @public_key = public_key
        @recovery_hash = recovery_hash
        @rotation_hash = rotation_hash
      end

      def to_h
        {
          device: @device,
          identity: @identity,
          publicKey: @public_key,
          recoveryHash: @recovery_hash,
          rotationHash: @rotation_hash
        }
      end

      def self.from_h(hash)
        new(
          device: hash[:device],
          identity: hash[:identity],
          public_key: hash[:publicKey],
          recovery_hash: hash[:recoveryHash],
          rotation_hash: hash[:rotationHash]
        )
      end
    end

    # Response to change recovery key request
    class ChangeRecoveryKeyResponse < ServerResponse
      def self.payload_class
        ChangeRecoveryKeyResponsePayload
      end
    end

    # Payload for change recovery key response
    class ChangeRecoveryKeyResponsePayload
      def to_h
        {}
      end

      def self.from_h(_hash)
        new
      end
    end
  end
end
