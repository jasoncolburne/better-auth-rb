require 'sinatra'
require 'json'
require_relative '../lib/better_auth/api/better_auth'
require_relative '../lib/better_auth/api/access'
require_relative '../lib/better_auth/api/account'
require_relative '../lib/better_auth/api/device'
require_relative '../lib/better_auth/api/session'
require_relative '../lib/better_auth/messages/account'
require_relative '../lib/better_auth/messages/device'
require_relative '../lib/better_auth/messages/session'
require_relative 'crypto/blake3'
require_relative 'crypto/nonce'
require_relative 'crypto/secp256r1'
require_relative 'encoding/identity_verifier'
require_relative 'encoding/rfc3339nano'
require_relative 'encoding/token_encoder'
require_relative 'storage/authentication_key'
require_relative 'storage/authentication_nonce'
require_relative 'storage/recovery_hash'
require_relative 'storage/timelock'
require_relative 'storage/verification_key_store'

module Examples
  class MockTokenAttributes
    attr_accessor :permissions_by_role

    def initialize(permissions_by_role = {})
      @permissions_by_role = permissions_by_role
    end

    def to_json(*)
      { permissionsByRole: @permissions_by_role }.to_json(*)
    end

    def self.from_hash(data)
      new(data[:permissionsByRole] || {})
    end
  end

  class Server
    def initialize
      access_lifetime = 15 * 60 # 15 minutes
      access_window = 30 # 30 seconds
      refresh_lifetime = 12 * 60 * 60 # 12 hours
      authentication_challenge_lifetime = 60 # 1 minute

      hasher = Crypto::Blake3.new
      verifier = Crypto::Secp256r1Verifier.new
      noncer = Crypto::Noncer.new

      access_key_hash_store = Storage::InMemoryTimeLockStore.new(refresh_lifetime)
      access_nonce_store = Storage::InMemoryTimeLockStore.new(access_window)
      authentication_key_store = Storage::InMemoryAuthenticationKeyStore.new(hasher)
      authentication_nonce_store = Storage::InMemoryAuthenticationNonceStore.new(authentication_challenge_lifetime)
      recovery_hash_store = Storage::InMemoryRecoveryHashStore.new

      identity_verifier = Encoding::MockIdentityVerifier.new(hasher)
      timestamper = Encoding::Rfc3339Nano.new
      token_encoder = Encoding::TokenEncoder.new

      @server_response_key = Crypto::Secp256r1.new
      server_access_key = Crypto::Secp256r1.new

      @ba = BetterAuth::API::BetterAuthServer.new(
        crypto: BetterAuth::API::CryptoContainer.new(
          hasher: hasher,
          key_pair: BetterAuth::API::KeyPairContainer.new(
            access: server_access_key,
            response: @server_response_key
          ),
          noncer: noncer,
          verifier: verifier
        ),
        encoding: BetterAuth::API::EncodingContainer.new(
          identity_verifier: identity_verifier,
          timestamper: timestamper,
          token_encoder: token_encoder
        ),
        expiry: BetterAuth::API::ExpiryContainer.new(
          access: access_lifetime,
          refresh: refresh_lifetime
        ),
        store: BetterAuth::API::StoresContainer.new(
          access: BetterAuth::API::AccessStoreContainer.new(
            key_hash: access_key_hash_store
          ),
          authentication: BetterAuth::API::AuthenticationStoreContainer.new(
            key: authentication_key_store,
            nonce: authentication_nonce_store
          ),
          recovery: BetterAuth::API::RecoveryStoreContainer.new(
            hash: recovery_hash_store
          )
        )
      )

      @access_key_store = Examples::Storage::VerificationKeyStore.new
      @access_key_store.add(server_access_key.identity, server_access_key)

      @av = BetterAuth::API::AccessVerifier.new(
        crypto: BetterAuth::API::VerifierCryptoContainer.new(
          verifier: verifier
        ),
        encoding: BetterAuth::API::VerifierEncodingContainer.new(
          token_encoder: token_encoder,
          timestamper: timestamper
        ),
        store: BetterAuth::API::VerifierStoreContainer.new(
          access_nonce: access_nonce_store,
          access_key_store: @access_key_store
        )
      )
    end

    def wrap_response(message, &block)
      block.call(message)
    rescue StandardError => e
      warn "error: #{e.message}"
      warn e.backtrace.join("\n")
      { error: 'an error occurred' }.to_json
    end

    def create(message)
      wrap_response(message) { |msg| @ba.create_account(msg) }
    end

    def recover(message)
      wrap_response(message) { |msg| @ba.recover_account(msg) }
    end

    def link(message)
      wrap_response(message) { |msg| @ba.link_device(msg) }
    end

    def unlink(message)
      wrap_response(message) { |msg| @ba.unlink_device(msg) }
    end

    def start_authentication(message)
      wrap_response(message) { |msg| @ba.request_session(msg) }
    end

    def finish_authentication(message)
      wrap_response(message) do |msg|
        @ba.create_session(
          msg,
          MockTokenAttributes.new('admin' => %w[read write])
        )
      end
    end

    def rotate_authentication(message)
      wrap_response(message) { |msg| @ba.rotate_device(msg) }
    end

    def rotate_access(message)
      wrap_response(message) { |msg| @ba.refresh_session(msg) }
    end

    def response_key(message)
      wrap_response(message) { |_msg| @server_response_key.public }
    end

    def respond_to_access_request(message, bad_nonce)
      @av.verify(message, MockTokenAttributes.new)

      request_obj = BetterAuth::Messages::AccessRequest.parse(message)

      server_identity = @server_response_key.identity

      nonce = bad_nonce ? '0A0123456789' : request_obj.payload.access.nonce

      response_payload = {
        wasFoo: request_obj.payload.request[:foo],
        wasBar: request_obj.payload.request[:bar]
      }

      response = BetterAuth::Messages::ServerResponse.new_response(
        response_payload,
        server_identity,
        nonce
      )

      response.sign(@server_response_key)
      response.serialize
    end

    def foo_bar(message)
      wrap_response(message) { |msg| respond_to_access_request(msg, false) }
    end

    def bad_nonce(message)
      wrap_response(message) { |msg| respond_to_access_request(msg, true) }
    end
  end
end

# Sinatra routes
set :bind, 'localhost'
set :port, 8080

server = Examples::Server.new

post '/account/create' do
  server.create(request.body.read)
end

post '/account/recover' do
  server.recover(request.body.read)
end

post '/session/request' do
  server.start_authentication(request.body.read)
end

post '/session/create' do
  server.finish_authentication(request.body.read)
end

post '/session/refresh' do
  server.rotate_access(request.body.read)
end

post '/device/rotate' do
  server.rotate_authentication(request.body.read)
end

post '/device/link' do
  server.link(request.body.read)
end

post '/device/unlink' do
  server.unlink(request.body.read)
end

post '/key/response' do
  server.response_key(request.body.read)
end

post '/foo/bar' do
  server.foo_bar(request.body.read)
end

post '/bad/nonce' do
  server.bad_nonce(request.body.read)
end
