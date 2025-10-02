module Examples
  module Encoding
    class MockIdentityVerifier
      def initialize(hasher)
        @hasher = hasher
      end

      def verify(identity, public_key, rotation_hash, extra_data = nil)
        message = "#{public_key}#{rotation_hash}"
        message = "#{message}#{extra_data}" unless extra_data.nil?

        hash = @hasher.sum(message.bytes)
        raise 'invalid identity' unless hash.casecmp?(identity)

        nil
      end
    end
  end
end
