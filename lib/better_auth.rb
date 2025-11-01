# Main entry point
require_relative 'better_auth/errors'

require_relative 'better_auth/crypto_interfaces/hasher'
require_relative 'better_auth/crypto_interfaces/noncer'
require_relative 'better_auth/crypto_interfaces/verifier'
require_relative 'better_auth/crypto_interfaces/verification_key'
require_relative 'better_auth/crypto_interfaces/signing_key'

require_relative 'better_auth/encoding_interfaces/identity_verifier'
require_relative 'better_auth/encoding_interfaces/timestamper'
require_relative 'better_auth/encoding_interfaces/token_encoder'

require_relative 'better_auth/storage_interfaces/access'
require_relative 'better_auth/storage_interfaces/authentication'
require_relative 'better_auth/storage_interfaces/recovery'
require_relative 'better_auth/storage_interfaces/timelock'

module BetterAuth
end
