require_relative 'better_auth'
require_relative '../messages/device'

module BetterAuth
  module API
    class BetterAuthServer
      # rubocop:disable Metrics/AbcSize
      def link_device(message)
        request = Messages::LinkDeviceRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        link_container = request.payload.request.link

        link_container.verify(
          @crypto.verifier,
          link_container.payload.authentication.public_key
        )

        unless link_container.payload.authentication.identity.casecmp?(request.payload.request.authentication.identity)
          raise MismatchedIdentitiesError.new(
            link_container_identity: link_container.payload.authentication.identity,
            request_identity: request.payload.request.authentication.identity
          )
        end

        device = @crypto.hasher.sum(
          (link_container.payload.authentication.public_key +
           link_container.payload.authentication.rotation_hash).bytes
        )

        unless device.casecmp?(link_container.payload.authentication.device)
          raise InvalidDeviceError.new(
            provided: link_container.payload.authentication.device,
            calculated: device
          )
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

        server_identity = @crypto.key_pair.response.identity

        response = Messages::LinkDeviceResponse.new_response(
          Messages::LinkDeviceResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
      # rubocop:enable Metrics/AbcSize

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

        server_identity = @crypto.key_pair.response.identity

        response = Messages::UnlinkDeviceResponse.new_response(
          Messages::UnlinkDeviceResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end

      def rotate_device(message)
        request = Messages::RotateDeviceRequest.parse(message)

        request.verify(@crypto.verifier, request.payload.request.authentication.public_key)

        @store.authentication.key.rotate(
          request.payload.request.authentication.identity,
          request.payload.request.authentication.device,
          request.payload.request.authentication.public_key,
          request.payload.request.authentication.rotation_hash
        )

        server_identity = @crypto.key_pair.response.identity

        response = Messages::RotateDeviceResponse.new_response(
          Messages::RotateDeviceResponsePayload.new,
          server_identity,
          request.payload.access.nonce
        )

        response.sign(@crypto.key_pair.response)

        response.serialize
      end
    end
  end
end
