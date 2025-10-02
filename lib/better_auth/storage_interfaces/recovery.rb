module BetterAuth
  module StorageInterfaces
    module RecoveryHashStore
      def register(identity, key_hash)
        raise NotImplementedError
      end

      def validate(identity, key_hash)
        raise NotImplementedError
      end
    end
  end
end
