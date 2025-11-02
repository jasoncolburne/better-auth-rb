require 'time'

module Examples
  module Encoding
    class Rfc3339
      def format(when_time)
        # Use millisecond precision (3 digits) instead of nanoseconds (9 digits)
        when_time.utc.iso8601(3)
      end

      def parse(when_string)
        Time.iso8601(when_string)
      end

      def now
        Time.now.utc
      end
    end
  end
end
