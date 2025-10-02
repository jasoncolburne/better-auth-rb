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
      def register(identity, device, current, next_digest, existing_identity)
        raise NotImplementedError
      end

      def rotate(identity, device, current, next_digest)
        raise NotImplementedError
      end

      def public(identity, device)
        raise NotImplementedError
      end
    end
  end
end
