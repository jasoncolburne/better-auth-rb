require_relative 'better_auth'
require_relative '../messages/account'

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

        device = @crypto.hasher.sum(
          (request.payload.request.authentication.public_key +
           request.payload.request.authentication.rotation_hash).bytes
        )

        raise 'bad device derivation' unless device.casecmp?(request.payload.request.authentication.device)

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

      # rubocop:disable Metrics/AbcSize
      def recover_account(message)
        request = Messages::RecoverAccountRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.recovery_key)

        device = @crypto.hasher.sum(
          (request.payload.request.authentication.public_key +
           request.payload.request.authentication.rotation_hash).bytes
        )

        raise 'bad device derivation' unless device.casecmp?(request.payload.request.authentication.device)

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
      # rubocop:enable Metrics/AbcSize
    end
  end
end
