require_relative 'common'

module BetterAuth
  module Messages
    # Request Session Request

    class RequestSessionRequestAuthentication
      attr_accessor :identity

      def initialize(identity:)
        @identity = identity
      end

      def to_h
        { identity: @identity }
      end

      def self.from_hash(data)
        new(identity: data[:identity])
      end
    end

    class RequestSessionRequestPayload
      attr_accessor :authentication

      def initialize(authentication:)
        @authentication = authentication
      end

      def to_h
        { authentication: @authentication.to_h }
      end

      def self.from_hash(data)
        new(authentication: RequestSessionRequestAuthentication.from_hash(data[:authentication]))
      end
    end

    class RequestSessionRequest < ClientRequest
      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        instance = allocate
        instance.from_hash(data)
        instance
      end

      def from_hash(data)
        @signature = data[:signature]
        request_data = data[:payload][:request]
        access_data = data[:payload][:access]

        auth = RequestSessionRequestAuthentication.new(identity: request_data[:authentication][:identity])
        @payload = ClientPayload.new(
          access: ClientAccess.new(nonce: access_data[:nonce]),
          request: RequestSessionRequestPayload.new(authentication: auth)
        )
      end
    end

    # Request Session Response

    class RequestSessionResponseAuthentication
      attr_accessor :nonce

      def initialize(nonce:)
        @nonce = nonce
      end

      def to_h
        { nonce: @nonce }
      end

      def to_json(*)
        to_h.to_json(*)
      end

      def self.from_hash(data)
        new(nonce: data[:nonce])
      end
    end

    class RequestSessionResponsePayload
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

      def self.from_hash(data)
        new(authentication: RequestSessionResponseAuthentication.from_hash(data[:authentication]))
      end
    end

    class RequestSessionResponse < ServerResponse
      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        instance = allocate
        instance.from_hash(data)
        instance
      end

      def from_hash(data)
        @signature = data[:signature]
        response_data = data[:payload][:response]
        access_data = data[:payload][:access]

        @payload = ServerPayload.new(
          access: ServerAccess.new(
            nonce: access_data[:nonce],
            server_identity: access_data[:serverIdentity]
          ),
          response: RequestSessionResponsePayload.from_hash(response_data)
        )
      end
    end

    # Create Session Request

    class CreateSessionRequestAccess
      attr_accessor :public_key, :rotation_hash

      def initialize(public_key:, rotation_hash:)
        @public_key = public_key
        @rotation_hash = rotation_hash
      end

      def to_h
        { publicKey: @public_key, rotationHash: @rotation_hash }
      end

      def self.from_hash(data)
        new(public_key: data[:publicKey], rotation_hash: data[:rotationHash])
      end
    end

    class CreateSessionRequestAuthentication
      attr_accessor :device, :nonce

      def initialize(device:, nonce:)
        @device = device
        @nonce = nonce
      end

      def to_h
        { device: @device, nonce: @nonce }
      end

      def self.from_hash(data)
        new(device: data[:device], nonce: data[:nonce])
      end
    end

    class CreateSessionRequestPayload
      attr_accessor :access, :authentication

      def initialize(access:, authentication:)
        @access = access
        @authentication = authentication
      end

      def to_h
        { access: @access.to_h, authentication: @authentication.to_h }
      end

      def self.from_hash(data)
        new(
          access: CreateSessionRequestAccess.from_hash(data[:access]),
          authentication: CreateSessionRequestAuthentication.from_hash(data[:authentication])
        )
      end
    end

    class CreateSessionRequest < ClientRequest
      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        instance = allocate
        instance.from_hash(data)
        instance
      end

      def from_hash(data)
        @signature = data[:signature]
        request_data = data[:payload][:request]
        access_data = data[:payload][:access]

        @payload = ClientPayload.new(
          access: ClientAccess.new(nonce: access_data[:nonce]),
          request: CreateSessionRequestPayload.from_hash(request_data)
        )
      end
    end

    # Create Session Response

    class CreateSessionResponseAccess
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

      def self.from_hash(data)
        new(token: data[:token])
      end
    end

    class CreateSessionResponsePayload
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

      def self.from_hash(data)
        new(access: CreateSessionResponseAccess.from_hash(data[:access]))
      end
    end

    class CreateSessionResponse < ServerResponse
      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        instance = allocate
        instance.from_hash(data)
        instance
      end

      def from_hash(data)
        @signature = data[:signature]
        response_data = data[:payload][:response]
        access_data = data[:payload][:access]

        @payload = ServerPayload.new(
          access: ServerAccess.new(
            nonce: access_data[:nonce],
            server_identity: access_data[:serverIdentity]
          ),
          response: CreateSessionResponsePayload.from_hash(response_data)
        )
      end
    end

    # Refresh Session Request
    class RefreshSessionRequestAccess
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

    class RefreshSessionRequestPayload
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

    class RefreshSessionRequest < ClientRequest
      def self.new_request(payload, nonce)
        ClientRequest.new_request(payload, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access_obj = ClientAccess.new(nonce: payload_data[:access][:nonce])
        request_access = RefreshSessionRequestAccess.new(
          public_key: payload_data[:request][:access][:publicKey],
          rotation_hash: payload_data[:request][:access][:rotationHash],
          token: payload_data[:request][:access][:token]
        )
        request = RefreshSessionRequestPayload.new(access: request_access)

        new(
          payload: ClientPayload.new(access: access_obj, request: request),
          signature: data[:signature]
        )
      end
    end

    # Refresh Session Response
    class RefreshSessionResponseAccess
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

    class RefreshSessionResponsePayload
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

    class RefreshSessionResponse < ServerResponse
      def self.new_response(payload, server_identity, nonce)
        ServerResponse.new_response(payload, server_identity, nonce)
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access_obj = ServerAccess.new(
          nonce: payload_data[:access][:nonce],
          server_identity: payload_data[:access][:serverIdentity]
        )
        response_access = RefreshSessionResponseAccess.new(
          token: payload_data[:response][:access][:token]
        )
        response = RefreshSessionResponsePayload.new(access: response_access)

        new(
          payload: ServerPayload.new(access: access_obj, response: response),
          signature: data[:signature]
        )
      end
    end
  end
end
