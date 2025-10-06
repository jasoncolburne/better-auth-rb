module Examples
  module Storage
    class VerificationKeyStore
      def initialize
        @keys = {}
      end

      def add(identity, key)
        @keys[identity] = key
      end

      def get(identity)
        raise "Key not found for identity: #{identity}" unless @keys.key?(identity)
        @keys[identity]
      end
    end
  end
end
