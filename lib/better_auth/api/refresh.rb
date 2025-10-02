require_relative 'better_auth'
require_relative '../messages/refresh'
require_relative '../messages/access'

module BetterAuth
  module API
    class BetterAuthServer
      def refresh_access_token(message)
        request = Messages::RefreshAccessTokenRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.access.public_key)

        token_string = request.payload.request.access.token
        token = Messages::AccessToken.parse(
          token_string,
          @crypto.key_pair.access.verifier.signature_length,
          @encoding.token_encoder
        )

        access_public_key = @crypto.key_pair.access.public

        token.verify_token(@crypto.key_pair.access.verifier, access_public_key, @encoding.timestamper)

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

        response_key_hash_value = response_key_hash

        response = Messages::RefreshAccessTokenResponse.new_response(
          Messages::RefreshAccessTokenResponsePayload.new(
            access: Messages::RefreshAccessTokenResponseAccess.new(token: serialized_token)
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
