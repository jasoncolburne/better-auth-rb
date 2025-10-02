module BetterAuth
  module StorageInterfaces
    module TimeLockStore
      def lifetime
        raise NotImplementedError
      end

      def reserve(value)
        raise NotImplementedError
      end
    end
  end
end
