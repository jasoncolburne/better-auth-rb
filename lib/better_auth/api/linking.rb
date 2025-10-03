require_relative 'better_auth'
require_relative '../messages/linking'

module BetterAuth
  module API
    class BetterAuthServer
      def link_device(message)
        request = Messages::LinkDeviceRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        link_container = request.payload.request.link

        link_container.verify(
          @crypto.verifier,
          link_container.payload.authentication.public_key
        )

        unless link_container.payload.authentication.identity.casecmp?(request.payload.request.authentication.identity)
          raise 'mismatched identities'
        end

        @store.authentication.key.rotate(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash
        )

        @store.authentication.key.register(
          link_container.payload.authentication.identity,
          link_container.payload.authentication.device,
          link_container.payload.authentication.public_key,
          link_container.payload.authentication.rotation_hash,
          true
        )

        response_key_hash_value = response_key_hash

        response = Messages::LinkDeviceResponse.new_response(
          Messages::LinkDeviceResponsePayload.new,
          response_key_hash_value,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end

      def unlink_device(message)
        request = Messages::UnlinkDeviceRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        @store.authentication.key.rotate(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash
        )

        @store.authentication.key.revoke_device(
          request.payload.request.authentication.identity,
          request.payload.request.link.device
        )

        response_key_hash_value = response_key_hash

        response = Messages::UnlinkDeviceResponse.new_response(
          Messages::UnlinkDeviceResponsePayload.new,
          response_key_hash_value,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
