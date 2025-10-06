module BetterAuth
  module StorageInterfaces
    module VerificationKeyStore
      def get(identity)
        raise NotImplementedError
      end
    end
  end
end
