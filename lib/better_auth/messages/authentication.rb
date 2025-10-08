require_relative 'common'

module BetterAuth
  module Messages
    # Start Authentication Request

    class StartAuthenticationRequestAuthentication
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

    class StartAuthenticationRequestPayload
      attr_accessor :authentication

      def initialize(authentication:)
        @authentication = authentication
      end

      def to_h
        { authentication: @authentication.to_h }
      end

      def self.from_hash(data)
        new(authentication: StartAuthenticationRequestAuthentication.from_hash(data[:authentication]))
      end
    end

    class StartAuthenticationRequest < ClientRequest
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

        auth = StartAuthenticationRequestAuthentication.new(identity: request_data[:authentication][:identity])
        @payload = ClientPayload.new(
          access: ClientAccess.new(nonce: access_data[:nonce]),
          request: StartAuthenticationRequestPayload.new(authentication: auth)
        )
      end
    end

    # Start Authentication Response

    class StartAuthenticationResponseAuthentication
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

    class StartAuthenticationResponsePayload
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
        new(authentication: StartAuthenticationResponseAuthentication.from_hash(data[:authentication]))
      end
    end

    class StartAuthenticationResponse < ServerResponse
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
          response: StartAuthenticationResponsePayload.from_hash(response_data)
        )
      end
    end

    # Finish Authentication Request

    class FinishAuthenticationRequestAccess
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

    class FinishAuthenticationRequestAuthentication
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

    class FinishAuthenticationRequestPayload
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
          access: FinishAuthenticationRequestAccess.from_hash(data[:access]),
          authentication: FinishAuthenticationRequestAuthentication.from_hash(data[:authentication])
        )
      end
    end

    class FinishAuthenticationRequest < ClientRequest
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
          request: FinishAuthenticationRequestPayload.from_hash(request_data)
        )
      end
    end

    # Finish Authentication Response

    class FinishAuthenticationResponseAccess
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

    class FinishAuthenticationResponsePayload
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
        new(access: FinishAuthenticationResponseAccess.from_hash(data[:access]))
      end
    end

    class FinishAuthenticationResponse < ServerResponse
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
          response: FinishAuthenticationResponsePayload.from_hash(response_data)
        )
      end
    end
  end
end
