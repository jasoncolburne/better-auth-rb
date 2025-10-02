require_relative 'better_auth'
require_relative '../messages/recovery'

module BetterAuth
  module API
    class BetterAuthServer
      def recover_account(message)
        request = Messages::RecoverAccountRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.recovery_key)

        hash = @crypto.hasher.sum(request.payload.request.authentication.recovery_key.bytes)
        @store.recovery.hash.validate(
          request.payload.request.authentication.identity,
          hash
        )

        @store.authentication.key.register(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash,
          true
        )

        response_key_hash_value = response_key_hash

        response = Messages::RecoverAccountResponse.new_response(
          Messages::RecoverAccountResponsePayload.new,
          response_key_hash_value,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
