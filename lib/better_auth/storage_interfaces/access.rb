module BetterAuth
  module StorageInterfaces
    module AccessNonceStore
      def reserve(identity, nonce)
        raise NotImplementedError
      end
    end
  end
end
