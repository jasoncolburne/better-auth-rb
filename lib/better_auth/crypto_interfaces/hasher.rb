module BetterAuth
  module CryptoInterfaces
    module Hasher
      def sum(message)
        raise NotImplementedError
      end
    end
  end
end
