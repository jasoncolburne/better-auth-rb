module BetterAuth
  module EncodingInterfaces
    module TokenEncoder
      def encode(object)
        raise NotImplementedError
      end

      def decode(token)
        raise NotImplementedError
      end
    end
  end
end
