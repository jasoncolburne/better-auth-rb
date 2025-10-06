require 'json'
require_relative 'common'

module BetterAuth
  module Messages
    # Rotate Authentication Key Request
    class RotateAuthenticationKeyRequestAuthentication
      attr_accessor :device, :identity, :public_key, :rotation_hash

      def initialize(device:, identity:, public_key:, rotation_hash:)
        @device = device
        @identity = identity
        @public_key = public_key
        @rotation_hash = rotation_hash
      end

      def to_h
        {
          device: @device,
          identity: @identity,
          publicKey: @public_key,
          rotationHash: @rotation_hash
        }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RotateAuthenticationKeyRequestPayload
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

    class RotateAuthenticationKeyRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        auth_data = payload_data[:request][:authentication]
        authentication = RotateAuthenticationKeyRequestAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          rotation_hash: auth_data[:rotationHash]
        )
        request = RotateAuthenticationKeyRequestPayload.new(authentication: authentication)

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end
    end

    # Rotate Authentication Key Response
    class RotateAuthenticationKeyResponsePayload
      def to_h
        {}
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RotateAuthenticationKeyResponse < ServerResponse
      def self.new_response(payload, server_identity, nonce)
        ServerResponse.new_response(payload, server_identity, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ServerAccess.new(
          nonce: payload_data[:access][:nonce],
          server_identity: payload_data[:access][:serverIdentity]
        )
        response = RotateAuthenticationKeyResponsePayload.new

        new(
          payload: ServerPayload.new(access: access, response: response),
          signature: data[:signature]
        )
      end
    end
  end
end
