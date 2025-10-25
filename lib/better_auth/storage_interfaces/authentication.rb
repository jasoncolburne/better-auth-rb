module BetterAuth
  module StorageInterfaces
    module AuthenticationNonceStore
      def generate(identity)
        raise NotImplementedError
      end

      def verify(nonce)
        raise NotImplementedError
      end
    end

    module AuthenticationKeyStore
      def register(identity, device, public_key, rotation_hash, existing_identity)
        raise NotImplementedError
      end

      def rotate(identity, device, public_key, rotation_hash)
        raise NotImplementedError
      end

      def public(identity, device)
        raise NotImplementedError
      end

      def revoke_device(identity, device)
        raise NotImplementedError
      end

      def revoke_devices(identity)
        raise NotImplementedError
      end

      def delete_identity(identity)
        raise NotImplementedError
      end

      def ensure_active(identity, device)
        raise NotImplementedError
      end
    end
  end
end
