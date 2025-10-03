module Examples
  module Storage
    class KeyState
      attr_accessor :public_key, :rotation_hash

      def initialize(public_key:, rotation_hash:)
        @public_key = public_key
        @rotation_hash = rotation_hash
      end
    end

    class InMemoryAuthenticationKeyStore
      def initialize(hasher)
        @hasher = hasher
        @known_devices = {}
      end

      def register(identity, device, public_key, rotation_hash, _existing_identity)
        devices = @known_devices[identity] || {}

        raise 'already registered' if devices.key?(device)

        devices[device] = KeyState.new(public_key: public_key, rotation_hash: rotation_hash)
        @known_devices[identity] = devices

        nil
      end

      def public(identity, device)
        devices = @known_devices[identity]
        raise 'account not found' unless devices

        instance = devices[device]
        raise 'device not found' unless instance

        instance.public_key
      end

      def rotate(identity, device, public_key, rotation_hash)
        devices = @known_devices[identity]
        raise 'account not found' unless devices

        instance = devices[device]
        raise 'device not found' unless instance

        hash = @hasher.sum(public_key.bytes)

        raise 'hash mismatch' unless hash.casecmp?(instance.rotation_hash)

        devices[device] = KeyState.new(public_key: public_key, rotation_hash: rotation_hash)
        @known_devices[identity] = devices

        nil
      end

      def revoke_device(identity, device)
        devices = @known_devices[identity]
        raise 'account not found' unless devices

        devices.delete(device)

        @known_devices[identity] = devices

        nil
      end

      def revoke_devices(identity)
        @known_devices[identity] = {}

        nil
      end
    end
  end
end
