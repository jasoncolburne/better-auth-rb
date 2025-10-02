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

      def validate(identity, hash)
        stored = @data_by_identity[identity]

        raise 'not found' unless stored

        raise 'incorrect hash' unless stored.casecmp?(hash)

        nil
      end
    end
  end
end
