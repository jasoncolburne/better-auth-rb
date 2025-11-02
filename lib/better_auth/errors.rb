# frozen_string_literal: true

module BetterAuth
  # Base error class for Better Auth
  class BetterAuthError < StandardError
    attr_reader :code, :context

    def initialize(code, message, context = {})
      @code = code
      @context = context
      super(message)
    end

    def to_h
      {
        error: {
          code: @code,
          message: message,
          context: @context
        }
      }
    end

    def to_json(*)
      to_h.to_json(*)
    end
  end

  # ============================================================================
  # Validation Errors
  # ============================================================================

  # Message structure is invalid or malformed
  class InvalidMessageError < BetterAuthError
    def initialize(field: nil, details: nil)
      message = 'Message structure is invalid or malformed'
      message = "Message structure is invalid: #{field}" if field
      message = "#{message} (#{details})" if field && details

      context = {}
      context[:field] = field if field
      context[:details] = details if details

      super('BA101', message, context)
    end
  end

  # Identity verification failed
  class InvalidIdentityError < BetterAuthError
    def initialize(provided: nil, details: nil)
      context = {}
      context[:provided] = provided if provided
      context[:details] = details if details

      super('BA102', 'Identity verification failed', context)
    end
  end

  # Device hash does not match hash(publicKey || rotationHash)
  class InvalidDeviceError < BetterAuthError
    def initialize(provided: nil, calculated: nil)
      context = {}
      context[:provided] = provided if provided
      context[:calculated] = calculated if calculated

      super('BA103', 'Device hash does not match hash(publicKey || rotationHash)', context)
    end
  end

  # Hash validation failed
  class InvalidHashError < BetterAuthError
    def initialize(expected: nil, actual: nil, hash_type: nil)
      context = {}
      context[:expected] = expected if expected
      context[:actual] = actual if actual
      context[:hash_type] = hash_type if hash_type

      super('BA104', 'Hash validation failed', context)
    end
  end

  # ============================================================================
  # Cryptographic Errors
  # ============================================================================

  # Response nonce does not match request nonce
  class IncorrectNonceError < BetterAuthError
    def initialize(expected: nil, actual: nil)
      truncate = ->(s) { s.length > 16 ? "#{s[0..15]}..." : s }

      context = {}
      context[:expected] = truncate.call(expected) if expected
      context[:actual] = truncate.call(actual) if actual

      super('BA203', 'Response nonce does not match request nonce', context)
    end
  end

  # ============================================================================
  # Authentication/Authorization Errors
  # ============================================================================

  # Link container identity does not match request identity
  class MismatchedIdentitiesError < BetterAuthError
    def initialize(link_container_identity: nil, request_identity: nil)
      context = {}
      context[:link_container_identity] = link_container_identity if link_container_identity
      context[:request_identity] = request_identity if request_identity

      super('BA302', 'Link container identity does not match request identity', context)
    end
  end

  # ============================================================================
  # Token Errors
  # ============================================================================

  # Token has expired
  class ExpiredTokenError < BetterAuthError
    def initialize(expiry_time: nil, current_time: nil, token_type: nil)
      context = {}
      context[:expiry_time] = expiry_time if expiry_time
      context[:current_time] = current_time if current_time
      context[:token_type] = token_type if token_type

      super('BA401', 'Token has expired', context)
    end
  end

  # Token issued_at timestamp is in the future
  class FutureTokenError < BetterAuthError
    def initialize(issued_at: nil, current_time: nil, time_difference: nil)
      context = {}
      context[:issued_at] = issued_at if issued_at
      context[:current_time] = current_time if current_time
      context[:time_difference] = time_difference if time_difference

      super('BA403', 'Token issued_at timestamp is in the future', context)
    end
  end

  # ============================================================================
  # Temporal Errors
  # ============================================================================

  # Request timestamp is too old
  class StaleRequestError < BetterAuthError
    def initialize(request_timestamp: nil, current_time: nil, maximum_age: nil)
      context = {}
      context[:request_timestamp] = request_timestamp if request_timestamp
      context[:current_time] = current_time if current_time
      context[:maximum_age] = maximum_age if maximum_age

      super('BA501', 'Request timestamp is too old', context)
    end
  end

  # Request timestamp is in the future
  class FutureRequestError < BetterAuthError
    def initialize(request_timestamp: nil, current_time: nil, time_difference: nil)
      context = {}
      context[:request_timestamp] = request_timestamp if request_timestamp
      context[:current_time] = current_time if current_time
      context[:time_difference] = time_difference if time_difference

      super('BA502', 'Request timestamp is in the future', context)
    end
  end
end
