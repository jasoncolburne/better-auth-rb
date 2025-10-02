module BetterAuth
  module EncodingInterfaces
    module IdentityVerifier
      def verify(identity, public_key, rotation_hash, extra_data = nil)
        raise NotImplementedError
      end
    end
  end
end
