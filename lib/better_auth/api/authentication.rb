require_relative 'better_auth'
require_relative '../messages/authentication'
require_relative '../messages/access'

module BetterAuth
  module API
    class BetterAuthServer
      def start_authentication(message)
        request = Messages::StartAuthenticationRequest.parse(message)

        nonce = @store.authentication.nonce.generate(
          request.payload.request.authentication.identity
        )

        response_key_hash_value = response_key_hash

        response = Messages::StartAuthenticationResponse.new_response(
          Messages::StartAuthenticationResponsePayload.new(
            authentication: Messages::StartAuthenticationResponseAuthentication.new(nonce: nonce)
          ),
          response_key_hash_value,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end

      def finish_authentication(message, attributes)
        request = Messages::FinishAuthenticationRequest.parse(message)

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

        response_key_hash_value = response_key_hash

        response = Messages::FinishAuthenticationResponse.new_response(
          Messages::FinishAuthenticationResponsePayload.new(
            access: Messages::FinishAuthenticationResponseAccess.new(token: token)
          ),
          response_key_hash_value,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
