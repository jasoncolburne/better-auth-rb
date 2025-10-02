require 'json'
require_relative 'common'

module BetterAuth
  module Messages
    # Refresh Access Token Request
    class RefreshAccessTokenRequestAccess
      attr_accessor :public_key, :rotation_hash, :token

      def initialize(public_key:, rotation_hash:, token:)
        @public_key = public_key
        @rotation_hash = rotation_hash
        @token = token
      end

      def to_h
        {
          publicKey: @public_key,
          rotationHash: @rotation_hash,
          token: @token
        }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RefreshAccessTokenRequestPayload
      attr_accessor :access

      def initialize(access:)
        @access = access
      end

      def to_h
        { access: @access.to_h }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RefreshAccessTokenRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access_obj = ClientAccess.new(nonce: payload_data[:access][:nonce])
        request_access = RefreshAccessTokenRequestAccess.new(
          public_key: payload_data[:request][:access][:publicKey],
          rotation_hash: payload_data[:request][:access][:rotationHash],
          token: payload_data[:request][:access][:token]
        )
        request = RefreshAccessTokenRequestPayload.new(access: request_access)

        new(
          payload: ClientPayload.new(access: access_obj, request: request),
          signature: data[:signature]
        )
      end
    end

    # Refresh Access Token Response
    class RefreshAccessTokenResponseAccess
      attr_accessor :token

      def initialize(token:)
        @token = token
      end

      def to_h
        { token: @token }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RefreshAccessTokenResponsePayload
      attr_accessor :access

      def initialize(access:)
        @access = access
      end

      def to_h
        { access: @access.to_h }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class RefreshAccessTokenResponse < ServerResponse
      def self.new_response(payload, response_key_hash, nonce)
        ServerResponse.new_response(payload, response_key_hash, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access_obj = ServerAccess.new(
          nonce: payload_data[:access][:nonce],
          response_key_hash: payload_data[:access][:responseKeyHash]
        )
        response_access = RefreshAccessTokenResponseAccess.new(
          token: payload_data[:response][:access][:token]
        )
        response = RefreshAccessTokenResponsePayload.new(access: response_access)

        new(
          payload: ServerPayload.new(access: access_obj, response: response),
          signature: data[:signature]
        )
      end
    end
  end
end
