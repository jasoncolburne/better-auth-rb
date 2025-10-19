module BetterAuth
  module StorageInterfaces
    module RecoveryHashStore
      def register(identity, key_hash)
        raise NotImplementedError
      end

      def rotate(identity, old_hash, new_hash)
        raise NotImplementedError
      end

      # Change forcefully changes the hash if the user loses access to the original
      def change(identity, key_hash)
        raise NotImplementedError
      end
    end
  end
end
