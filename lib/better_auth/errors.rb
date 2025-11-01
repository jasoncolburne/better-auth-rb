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

  # Signature verification failed
  class SignatureVerificationError < BetterAuthError
    def initialize(public_key: nil, signed_data: nil)
      context = {}
      context[:public_key] = public_key if public_key
      context[:signed_data] = signed_data if signed_data

      super('BA201', 'Signature verification failed', context)
    end
  end

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

  # Authentication challenge has expired
  class ExpiredNonceError < BetterAuthError
    def initialize(nonce_timestamp: nil, current_time: nil, expiration_window: nil)
      context = {}
      context[:nonce_timestamp] = nonce_timestamp if nonce_timestamp
      context[:current_time] = current_time if current_time
      context[:expiration_window] = expiration_window if expiration_window

      super('BA204', 'Authentication challenge has expired', context)
    end
  end

  # Nonce has already been used (replay attack detected)
  class NonceReplayError < BetterAuthError
    def initialize(nonce: nil, previous_usage_timestamp: nil)
      truncate = ->(s) { s.length > 16 ? "#{s[0..15]}..." : s }

      context = {}
      context[:nonce] = truncate.call(nonce) if nonce
      context[:previous_usage_timestamp] = previous_usage_timestamp if previous_usage_timestamp

      super('BA205', 'Nonce has already been used (replay attack detected)', context)
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

  # Insufficient permissions for requested operation
  class PermissionDeniedError < BetterAuthError
    def initialize(required_permissions: nil, actual_permissions: nil, operation: nil)
      context = {}
      context[:required_permissions] = required_permissions if required_permissions
      context[:actual_permissions] = actual_permissions if actual_permissions
      context[:operation] = operation if operation

      super('BA303', 'Insufficient permissions for requested operation', context)
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

  # Token structure or format is invalid
  class InvalidTokenError < BetterAuthError
    def initialize(details: nil)
      context = {}
      context[:details] = details if details

      super('BA402', 'Token structure or format is invalid', context)
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

  # Client and server clock difference exceeds tolerance
  class ClockSkewError < BetterAuthError
    def initialize(client_time: nil, server_time: nil, time_difference: nil, max_tolerance: nil)
      context = {}
      context[:client_time] = client_time if client_time
      context[:server_time] = server_time if server_time
      context[:time_difference] = time_difference if time_difference
      context[:max_tolerance] = max_tolerance if max_tolerance

      super('BA503', 'Client and server clock difference exceeds tolerance', context)
    end
  end

  # ============================================================================
  # Storage Errors
  # ============================================================================

  # Resource not found
  class NotFoundError < BetterAuthError
    def initialize(resource_type: nil, resource_identifier: nil)
      message = 'Resource not found'
      message = "Resource not found: #{resource_type}" if resource_type

      context = {}
      context[:resource_type] = resource_type if resource_type
      context[:resource_identifier] = resource_identifier if resource_identifier

      super('BA601', message, context)
    end
  end

  # Resource already exists
  class AlreadyExistsError < BetterAuthError
    def initialize(resource_type: nil, resource_identifier: nil)
      message = 'Resource already exists'
      message = "Resource already exists: #{resource_type}" if resource_type

      context = {}
      context[:resource_type] = resource_type if resource_type
      context[:resource_identifier] = resource_identifier if resource_identifier

      super('BA602', message, context)
    end
  end

  # Storage backend is unavailable
  class StorageUnavailableError < BetterAuthError
    def initialize(backend_type: nil, connection_details: nil, backend_error: nil)
      context = {}
      context[:backend_type] = backend_type if backend_type
      context[:connection_details] = connection_details if connection_details
      context[:backend_error] = backend_error if backend_error

      super('BA603', 'Storage backend is unavailable', context)
    end
  end

  # Stored data is corrupted or invalid
  class StorageCorruptionError < BetterAuthError
    def initialize(resource_type: nil, resource_identifier: nil, corruption_details: nil)
      context = {}
      context[:resource_type] = resource_type if resource_type
      context[:resource_identifier] = resource_identifier if resource_identifier
      context[:corruption_details] = corruption_details if corruption_details

      super('BA604', 'Stored data is corrupted or invalid', context)
    end
  end

  # ============================================================================
  # Encoding Errors
  # ============================================================================

  # Failed to serialize message
  class SerializationError < BetterAuthError
    def initialize(message_type: nil, format: nil, details: nil)
      context = {}
      context[:message_type] = message_type if message_type
      context[:format] = format if format
      context[:details] = details if details

      super('BA701', 'Failed to serialize message', context)
    end
  end

  # Failed to deserialize message
  class DeserializationError < BetterAuthError
    def initialize(message_type: nil, raw_data: nil, details: nil)
      truncate_data = ->(s) { s.length > 100 ? "#{s[0..99]}..." : s }

      context = {}
      context[:message_type] = message_type if message_type
      context[:raw_data] = truncate_data.call(raw_data) if raw_data
      context[:details] = details if details

      super('BA702', 'Failed to deserialize message', context)
    end
  end

  # Failed to compress or decompress data
  class CompressionError < BetterAuthError
    def initialize(operation: nil, data_size: nil, details: nil)
      context = {}
      context[:operation] = operation if operation
      context[:data_size] = data_size if data_size
      context[:details] = details if details

      super('BA703', 'Failed to compress or decompress data', context)
    end
  end

  # ============================================================================
  # Network Errors (Client-Only)
  # ============================================================================

  # Failed to connect to server
  class ConnectionError < BetterAuthError
    def initialize(server_url: nil, details: nil)
      context = {}
      context[:server_url] = server_url if server_url
      context[:details] = details if details

      super('BA801', 'Failed to connect to server', context)
    end
  end

  # Request timed out
  class TimeoutError < BetterAuthError
    def initialize(timeout_duration: nil, endpoint: nil)
      context = {}
      context[:timeout_duration] = timeout_duration if timeout_duration
      context[:endpoint] = endpoint if endpoint

      super('BA802', 'Request timed out', context)
    end
  end

  # Invalid HTTP response or protocol violation
  class ProtocolError < BetterAuthError
    def initialize(http_status_code: nil, details: nil)
      context = {}
      context[:http_status_code] = http_status_code if http_status_code
      context[:details] = details if details

      super('BA803', 'Invalid HTTP response or protocol violation', context)
    end
  end

  # ============================================================================
  # Protocol Errors
  # ============================================================================

  # Operation not allowed in current state
  class InvalidStateError < BetterAuthError
    def initialize(current_state: nil, attempted_operation: nil, required_state: nil)
      context = {}
      context[:current_state] = current_state if current_state
      context[:attempted_operation] = attempted_operation if attempted_operation
      context[:required_state] = required_state if required_state

      super('BA901', 'Operation not allowed in current state', context)
    end
  end

  # Key rotation failed
  class RotationError < BetterAuthError
    def initialize(rotation_type: nil, details: nil)
      context = {}
      context[:rotation_type] = rotation_type if rotation_type
      context[:details] = details if details

      super('BA902', 'Key rotation failed', context)
    end
  end

  # Account recovery failed
  class RecoveryError < BetterAuthError
    def initialize(details: nil)
      context = {}
      context[:details] = details if details

      super('BA903', 'Account recovery failed', context)
    end
  end

  # Device has been revoked
  class DeviceRevokedError < BetterAuthError
    def initialize(device_identifier: nil, revocation_timestamp: nil)
      context = {}
      context[:device_identifier] = device_identifier if device_identifier
      context[:revocation_timestamp] = revocation_timestamp if revocation_timestamp

      super('BA904', 'Device has been revoked', context)
    end
  end

  # Identity has been deleted
  class IdentityDeletedError < BetterAuthError
    def initialize(identity_identifier: nil, deletion_timestamp: nil)
      context = {}
      context[:identity_identifier] = identity_identifier if identity_identifier
      context[:deletion_timestamp] = deletion_timestamp if deletion_timestamp

      super('BA905', 'Identity has been deleted', context)
    end
  end
end
