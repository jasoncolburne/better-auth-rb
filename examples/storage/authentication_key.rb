module Examples
  module Storage
    class KeyState
      attr_accessor :current, :next_digest

      def initialize(current:, next_digest:)
        @current = current
        @next_digest = next_digest
      end
    end

    class InMemoryAuthenticationKeyStore
      def initialize(hasher)
        @hasher = hasher
        @known_devices = {}
      end

      def register(identity, device, current, next_digest, _existing_identity)
        devices = @known_devices[identity] || {}

        raise 'already registered' if devices.key?(device)

        devices[device] = KeyState.new(current: current, next_digest: next_digest)
        @known_devices[identity] = devices

        nil
      end

      def public(identity, device)
        devices = @known_devices[identity]
        raise 'account not found' unless devices

        instance = devices[device]
        raise 'device not found' unless instance

        instance.current
      end

      def rotate(identity, device, current, next_digest)
        devices = @known_devices[identity]
        raise 'account not found' unless devices

        instance = devices[device]
        raise 'device not found' unless instance

        current_digest = @hasher.sum(current.bytes)

        raise 'hash mismatch' unless current_digest.casecmp?(instance.next_digest)

        devices[device] = KeyState.new(current: current, next_digest: next_digest)
        @known_devices[identity] = devices

        nil
      end
    end
  end
end
