require_relative 'better_auth'
require_relative '../messages/creation'

module BetterAuth
  module API
    class BetterAuthServer
      def create_account(message)
        request = Messages::CreateAccountRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        identity = request.payload.request.authentication.identity

        @encoding.identity_verifier.verify(
          identity,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash,
          request.payload.request.authentication.recovery_hash
        )

        hash = @crypto.hasher.sum(request.payload.request.authentication.public_key.bytes)

        raise 'device mismatch' unless hash.casecmp?(request.payload.request.authentication.device)

        @store.recovery.hash.register(
          identity,
          request.payload.request.authentication.recovery_hash
        )

        @store.authentication.key.register(
          identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash,
          false
        )

        server_identity = @crypto.key_pair.response.identity

        response = Messages::CreateAccountResponse.new_response(
          Messages::CreateAccountResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
