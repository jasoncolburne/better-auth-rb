require_relative 'better_auth'
require_relative '../messages/rotation'

module BetterAuth
  module API
    class BetterAuthServer
      def rotate_authentication_key(message)
        request = Messages::RotateAuthenticationKeyRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        @store.authentication.key.rotate(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash
        )

        server_identity = @crypto.key_pair.response.identity

        response = Messages::RotateAuthenticationKeyResponse.new_response(
          Messages::RotateAuthenticationKeyResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
