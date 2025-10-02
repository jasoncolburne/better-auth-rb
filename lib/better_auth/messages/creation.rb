require 'json'
require_relative 'common'

module BetterAuth
  module Messages
    # Create Account Request
    class CreateAccountRequestAuthentication
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

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class CreateAccountRequestPayload
      attr_accessor :authentication

      def initialize(authentication:)
        @authentication = authentication
      end

      def to_h
        { authentication: @authentication.to_h }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class CreateAccountRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        auth_data = payload_data[:request][:authentication]
        authentication = CreateAccountRequestAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          recovery_hash: auth_data[:recoveryHash],
          rotation_hash: auth_data[:rotationHash]
        )
        request = CreateAccountRequestPayload.new(authentication: authentication)

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end
    end

    # Create Account Response
    class CreateAccountResponsePayload
      def to_h
        {}
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class CreateAccountResponse < ServerResponse
      def self.new_response(payload, response_key_hash, nonce)
        ServerResponse.new_response(payload, response_key_hash, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ServerAccess.new(
          nonce: payload_data[:access][:nonce],
          response_key_hash: payload_data[:access][:responseKeyHash]
        )
        response = CreateAccountResponsePayload.new

        new(
          payload: ServerPayload.new(access: access, response: response),
          signature: data[:signature]
        )
      end
    end
  end
end
