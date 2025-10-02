module BetterAuth
  module EncodingInterfaces
    module Timestamper
      def format(when_time)
        raise NotImplementedError
      end

      def parse(when_string)
        raise NotImplementedError
      end

      def now
        raise NotImplementedError
      end
    end
  end
end
