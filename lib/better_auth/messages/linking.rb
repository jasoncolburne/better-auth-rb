require 'json'
require_relative 'common'

module BetterAuth
  module Messages
    # Link Container
    class LinkContainerAuthentication
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

    class LinkContainerPayload
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

    class LinkContainer < SignableMessage
      def self.new_container(payload, signature = nil)
        new(payload: payload, signature: signature)
      end

      def self.parse(data)
        auth_data = data[:payload][:authentication]
        authentication = LinkContainerAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          rotation_hash: auth_data[:rotationHash]
        )
        payload = LinkContainerPayload.new(authentication: authentication)

        new(payload: payload, signature: data[:signature])
      end
    end

    # Link Device Request
    class LinkDeviceRequestAuthentication
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

    class LinkDeviceRequestPayload
      attr_accessor :authentication, :link

      def initialize(authentication:, link:)
        @authentication = authentication
        @link = link
      end

      def to_h
        {
          authentication: @authentication.to_h,
          link: JSON.parse(@link.serialize)
        }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class LinkDeviceRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        auth_data = payload_data[:request][:authentication]
        authentication = LinkDeviceRequestAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          rotation_hash: auth_data[:rotationHash]
        )
        link = LinkContainer.parse(payload_data[:request][:link])
        request = LinkDeviceRequestPayload.new(authentication: authentication, link: link)

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end
    end

    # Link Device Response
    class LinkDeviceResponsePayload
      def to_h
        {}
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class LinkDeviceResponse < ServerResponse
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
        response = LinkDeviceResponsePayload.new

        new(
          payload: ServerPayload.new(access: access, response: response),
          signature: data[:signature]
        )
      end
    end

    # Unlink Device Request
    class UnlinkDeviceRequestAuthentication
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

    class UnlinkDeviceRequestLink
      attr_accessor :device

      def initialize(device:)
        @device = device
      end

      def to_h
        { device: @device }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class UnlinkDeviceRequestPayload
      attr_accessor :authentication, :link

      def initialize(authentication:, link:)
        @authentication = authentication
        @link = link
      end

      def to_h
        {
          authentication: @authentication.to_h,
          link: @link.to_h
        }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class UnlinkDeviceRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        auth_data = payload_data[:request][:authentication]
        authentication = UnlinkDeviceRequestAuthentication.new(
          device: auth_data[:device],
          identity: auth_data[:identity],
          public_key: auth_data[:publicKey],
          rotation_hash: auth_data[:rotationHash]
        )
        link_data = payload_data[:request][:link]
        link = UnlinkDeviceRequestLink.new(device: link_data[:device])
        request = UnlinkDeviceRequestPayload.new(authentication: authentication, link: link)

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end
    end

    # Unlink Device Response
    class UnlinkDeviceResponsePayload
      def to_h
        {}
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class UnlinkDeviceResponse < ServerResponse
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
        response = UnlinkDeviceResponsePayload.new

        new(
          payload: ServerPayload.new(access: access, response: response),
          signature: data[:signature]
        )
      end
    end
  end
end
