require 'json'

module BetterAuth
  module Messages
    class SignableMessage
      attr_accessor :payload, :signature

      def initialize(payload:, signature: nil)
        @payload = payload
        @signature = signature
      end

      def compose_payload
        JSON.generate(@payload.to_h)
      end

      def serialize
        composed_payload = compose_payload
        if @signature.nil?
          "{\"payload\":#{composed_payload}}"
        else
          "{\"payload\":#{composed_payload},\"signature\":\"#{@signature}\"}"
        end
      end

      def sign(signer)
        composed_payload = compose_payload
        @signature = signer.sign(composed_payload.bytes)
        nil
      end

      def verify(verifier, public_key)
        raise 'nil signature' if @signature.nil?

        composed_payload = compose_payload
        verifier.verify(@signature, public_key, composed_payload.bytes)
      end
    end

    # Helper classes for client requests
    class ClientAccess
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
    end

    class ClientPayload
      attr_accessor :access, :request

      def initialize(access:, request:)
        @access = access
        @request = request
      end

      def to_h
        { access: @access.to_h, request: @request.to_h }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class ClientRequest < SignableMessage
      def self.new_request(request_payload, nonce)
        new(
          payload: ClientPayload.new(
            access: ClientAccess.new(nonce: nonce),
            request: request_payload
          )
        )
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        # Reconstruct the payload structure
        access = ClientAccess.new(nonce: payload_data[:access][:nonce])
        request = parse_request_payload(payload_data[:request])

        new(
          payload: ClientPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end

      def self.parse_request_payload(data)
        # To be overridden in subclasses
        data
      end
    end

    # Helper classes for server responses
    class ServerAccess
      attr_accessor :nonce, :response_key_hash

      def initialize(nonce:, response_key_hash:)
        @nonce = nonce
        @response_key_hash = response_key_hash
      end

      def to_h
        { nonce: @nonce, responseKeyHash: @response_key_hash }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class ServerPayload
      attr_accessor :access, :response

      def initialize(access:, response:)
        @access = access
        @response = response
      end

      def to_h
        { access: @access.to_h, response: @response.to_h }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class ServerResponse < SignableMessage
      def self.new_response(response_payload, response_key_hash, nonce)
        new(
          payload: ServerPayload.new(
            access: ServerAccess.new(nonce: nonce, response_key_hash: response_key_hash),
            response: response_payload
          )
        )
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = ServerAccess.new(
          nonce: payload_data[:access][:nonce],
          response_key_hash: payload_data[:access][:responseKeyHash]
        )
        response = parse_response_payload(payload_data[:response])

        new(
          payload: ServerPayload.new(access: access, response: response),
          signature: data[:signature]
        )
      end

      def self.parse_response_payload(data)
        # To be overridden in subclasses
        data
      end
    end
  end
end
