require_relative 'better_auth'
require_relative '../messages/session'
require_relative '../messages/access'

module BetterAuth
  module API
    class BetterAuthServer
      def request_session(message)
        request = Messages::RequestSessionRequest.parse(message)

        nonce = @store.authentication.nonce.generate(
          request.payload.request.authentication.identity
        )

        server_identity = @crypto.key_pair.response.identity

        response = Messages::RequestSessionResponse.new_response(
          Messages::RequestSessionResponsePayload.new(
            authentication: Messages::RequestSessionResponseAuthentication.new(nonce: nonce)
          ),
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end

      def create_session(message, attributes)
        request = Messages::CreateSessionRequest.parse(message)

        identity = @store.authentication.nonce.verify(
          request.payload.request.authentication.nonce
        )

        authentication_public_key = @store.authentication.key.public(
          identity,
          request.payload.request.authentication.device
        )

        request.verify(@crypto.verifier, authentication_public_key)

        now = @encoding.timestamper.now
        expiry_time = now + @expiry.access
        refresh_expiry_time = now + @expiry.refresh

        issued_at = @encoding.timestamper.format(now)
        expiry = @encoding.timestamper.format(expiry_time)
        refresh_expiry = @encoding.timestamper.format(refresh_expiry_time)

        access_token = Messages::AccessToken.new(
          server_identity: @crypto.key_pair.access.identity,
          device: request.payload.request.authentication.device,
          identity: identity,
          public_key: request.payload.request.access.public_key,
          rotation_hash: request.payload.request.access.rotation_hash,
          issued_at: issued_at,
          expiry: expiry,
          refresh_expiry: refresh_expiry,
          attributes: attributes
        )

        access_token.sign(@crypto.key_pair.access)

        token = access_token.serialize_token(@encoding.token_encoder)

        server_identity = @crypto.key_pair.response.identity

        response = Messages::CreateSessionResponse.new_response(
          Messages::CreateSessionResponsePayload.new(
            access: Messages::CreateSessionResponseAccess.new(token: token)
          ),
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end

      # rubocop:disable Metrics/AbcSize
      def refresh_session(message)
        # rubocop:enable Metrics/AbcSize
        request = Messages::RefreshSessionRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.access.public_key)

        token_string = request.payload.request.access.token
        token = Messages::AccessToken.parse(
          token_string,
          @encoding.token_encoder
        )

        access_verification_key = @store.access.verification_key.get(token.server_identity)
        access_public_key = access_verification_key.public

        token.verify_signature(@crypto.key_pair.access.verifier, access_public_key)

        hash = @crypto.hasher.sum(request.payload.request.access.public_key.bytes)
        raise 'hash mismatch' unless hash.casecmp?(token.rotation_hash)

        now = @encoding.timestamper.now
        refresh_expiry = @encoding.timestamper.parse(token.refresh_expiry)

        raise 'refresh has expired' if now > refresh_expiry

        @store.access.key_hash.reserve(hash)

        later = now + @expiry.access

        issued_at = @encoding.timestamper.format(now)
        expiry = @encoding.timestamper.format(later)

        access_token = Messages::AccessToken.new(
          server_identity: @crypto.key_pair.access.identity,
          device: token.device,
          identity: token.identity,
          public_key: request.payload.request.access.public_key,
          rotation_hash: request.payload.request.access.rotation_hash,
          issued_at: issued_at,
          expiry: expiry,
          refresh_expiry: token.refresh_expiry,
          attributes: token.attributes
        )

        access_token.sign(@crypto.key_pair.access)

        serialized_token = access_token.serialize_token(@encoding.token_encoder)

        server_identity = @crypto.key_pair.response.identity

        response = Messages::RefreshSessionResponse.new_response(
          Messages::RefreshSessionResponsePayload.new(
            access: Messages::RefreshSessionResponseAccess.new(token: serialized_token)
          ),
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
