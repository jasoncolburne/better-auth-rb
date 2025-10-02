require 'securerandom'
require 'base64'

module Examples
  module Crypto
    class Noncer
      def generate128
        entropy = [0, 0].pack('C*') + SecureRandom.random_bytes(16)
        salt = Base64.urlsafe_encode64(entropy, padding: false)
        "0A#{salt[2..]}"
      end
    end
  end
end
