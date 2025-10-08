require_relative 'better_auth'
require_relative '../messages/recovery'

module BetterAuth
  module API
    class BetterAuthServer
      def recover_account(message)
        request = Messages::RecoverAccountRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.recovery_key)

        hash = @crypto.hasher.sum(request.payload.request.authentication.recovery_key.bytes)
        @store.recovery.hash.rotate(
          request.payload.request.authentication.identity,
          hash,
          request.payload.request.authentication.recovery_hash
        )

        @store.authentication.key.revoke_devices(
          request.payload.request.authentication.identity
        )

        @store.authentication.key.register(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash,
          true
        )

        server_identity = @crypto.key_pair.response.identity

        response = Messages::RecoverAccountResponse.new_response(
          Messages::RecoverAccountResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
