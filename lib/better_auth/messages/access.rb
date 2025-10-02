require 'json'
require_relative 'common'

module BetterAuth
  module Messages
    # AccessToken class - represents an access token with signature
    class AccessToken
      attr_accessor :identity, :public_key, :rotation_hash, :issued_at, :expiry, :refresh_expiry, :attributes
      attr_reader :signature

      def initialize(identity:, public_key:, rotation_hash:, issued_at:, expiry:, refresh_expiry:, attributes:)
        @identity = identity
        @public_key = public_key
        @rotation_hash = rotation_hash
        @issued_at = issued_at
        @expiry = expiry
        @refresh_expiry = refresh_expiry
        @attributes = attributes
        @signature = nil
      end

      def self.parse(message, public_key_length, token_encoder)
        signature = message[0...public_key_length]
        rest = message[public_key_length..]

        token_string = token_encoder.decode(rest)
        data = JSON.parse(token_string, symbolize_names: true)

        token = new(
          identity: data[:identity],
          public_key: data[:publicKey],
          rotation_hash: data[:rotationHash],
          issued_at: data[:issuedAt],
          expiry: data[:expiry],
          refresh_expiry: data[:refreshExpiry],
          attributes: data[:attributes]
        )
        token.instance_variable_set(:@signature, signature)
        token
      end

      def serialize_token(token_encoder)
        raise 'nil signature' if @signature.nil?

        composed_payload = compose_payload
        raw_token = token_encoder.encode(composed_payload)
        "#{@signature}#{raw_token}"
      end

      def compose_payload
        attrs = @attributes.respond_to?(:to_h) ? @attributes.to_h : @attributes
        {
          identity: @identity,
          publicKey: @public_key,
          rotationHash: @rotation_hash,
          issuedAt: @issued_at,
          expiry: @expiry,
          refreshExpiry: @refresh_expiry,
          attributes: attrs
        }.to_json
      end

      def verify_token(verifier, public_key, timestamper)
        raise 'nil signature' if @signature.nil?

        composed_payload = compose_payload
        verifier.verify(@signature, public_key, composed_payload.bytes)

        now = timestamper.now
        issued_at_time = timestamper.parse(@issued_at)
        expiry_time = timestamper.parse(@expiry)

        raise 'token from future' if now < issued_at_time
        raise 'token expired' if now > expiry_time

        nil
      end

      def sign(signing_key)
        composed_payload = compose_payload
        @signature = signing_key.sign(composed_payload.bytes)
        nil
      end
    end

    # Access request components
    class AccessRequestAccess
      attr_accessor :nonce, :timestamp, :token

      def initialize(nonce:, timestamp:, token:)
        @nonce = nonce
        @timestamp = timestamp
        @token = token
      end

      def to_h
        { nonce: @nonce, timestamp: @timestamp, token: @token }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class AccessRequestPayload
      attr_accessor :access, :request

      def initialize(access:, request:)
        @access = access
        @request = request
      end

      def to_h
        { access: @access.to_h, request: @request }
      end

      def to_json(*)
        to_h.to_json(*)
      end
    end

    class AccessRequest < SignableMessage
      def self.new_request(request_payload, timestamper, token, nonce)
        new(
          payload: AccessRequestPayload.new(
            access: AccessRequestAccess.new(
              nonce: nonce,
              timestamp: timestamper.format(timestamper.now),
              token: token
            ),
            request: request_payload
          )
        )
      end

      def self.parse(message)
        data = JSON.parse(message, symbolize_names: true)
        payload_data = data[:payload]

        access = AccessRequestAccess.new(
          nonce: payload_data[:access][:nonce],
          timestamp: payload_data[:access][:timestamp],
          token: payload_data[:access][:token]
        )
        request = payload_data[:request]

        new(
          payload: AccessRequestPayload.new(access: access, request: request),
          signature: data[:signature]
        )
      end

      def verify_access(nonce_store, verifier, token_verifier, server_access_public_key, token_encoder, timestamper,
                        _attributes)
        access_token = AccessToken.parse(
          @payload.access.token,
          token_verifier.signature_length,
          token_encoder
        )

        access_token.verify_token(token_verifier, server_access_public_key, timestamper)

        composed_payload = compose_payload
        verifier.verify(@signature, access_token.public_key, composed_payload.bytes)

        now = timestamper.now
        access_time = timestamper.parse(@payload.access.timestamp)
        expiry = access_time + nonce_store.lifetime

        raise 'stale request' if now > expiry
        raise 'request from future' if now < access_time

        nonce_store.reserve(@payload.access.nonce)

        [access_token.identity, access_token.attributes]
      end
    end
  end
end
