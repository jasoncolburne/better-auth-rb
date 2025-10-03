module Examples
  module Storage
    class InMemoryRecoveryHashStore
      def initialize
        @data_by_identity = {}
      end

      def register(identity, hash)
        raise 'already exists' if @data_by_identity.key?(identity)

        @data_by_identity[identity] = hash

        nil
      end

      def rotate(identity, old_hash, new_hash)
        stored = @data_by_identity[identity]

        raise 'not found' unless stored

        raise 'incorrect hash' unless stored.casecmp?(old_hash)

        @data_by_identity[identity] = new_hash

        nil
      end
    end
  end
end
