require 'spec_helper'
require_relative '../lib/better_auth/api/better_auth'
require_relative '../lib/better_auth/api/creation'
require_relative '../lib/better_auth/api/authentication'
require_relative '../lib/better_auth/api/linking'
require_relative '../lib/better_auth/api/recovery'
require_relative '../lib/better_auth/api/refresh'
require_relative '../lib/better_auth/api/rotation'
require_relative '../lib/better_auth/api/access'
require_relative '../lib/better_auth/messages/access'
require_relative '../lib/better_auth/messages/authentication'
require_relative '../lib/better_auth/messages/creation'
require_relative '../lib/better_auth/messages/linking'
require_relative '../lib/better_auth/messages/recovery'
require_relative '../lib/better_auth/messages/refresh'
require_relative '../lib/better_auth/messages/rotation'
require_relative '../examples/crypto/blake3'
require_relative '../examples/crypto/nonce'
require_relative '../examples/crypto/secp256r1'
require_relative '../examples/encoding/identity_verifier'
require_relative '../examples/encoding/rfc3339nano'
require_relative '../examples/encoding/token_encoder'
require_relative '../examples/storage/authentication_key'
require_relative '../examples/storage/authentication_nonce'
require_relative '../examples/storage/recovery_hash'
require_relative '../examples/storage/timelock'
require_relative '../examples/storage/verification_key_store'

RSpec.describe 'BetterAuth API' do
  class MockAttributes
    attr_accessor :permissions_by_role

    def initialize(permissions_by_role = {})
      @permissions_by_role = permissions_by_role
    end

    def to_h
      { permissionsByRole: @permissions_by_role }
    end

    def to_json(*)
      to_h.to_json(*)
    end

    def self.from_hash(data)
      new(data[:permissionsByRole] || {})
    end
  end

  class FakeAccessRequest < BetterAuth::Messages::AccessRequest
    attr_accessor :payload, :signature

    def initialize(payload:, signature: nil)
      @payload = payload
      @signature = signature
    end
  end

  class FakeAccessRequestPayload
    attr_accessor :foo, :bar

    def initialize(foo:, bar:)
      @foo = foo
      @bar = bar
    end

    def to_h
      { foo: @foo, bar: @bar }
    end

    def to_json(*)
      to_h.to_json(*)
    end
  end

  def test_flow
    access_lifetime = 15 * 60 # 15 minutes
    access_window = 30 # 30 seconds
    refresh_lifetime = 12 * 60 * 60 # 12 hours
    authentication_challenge_lifetime = 60 # 1 minute

    hasher = Examples::Crypto::Blake3.new
    verifier = Examples::Crypto::Secp256r1Verifier.new
    noncer = Examples::Crypto::Noncer.new

    access_key_hash_store = Examples::Storage::InMemoryTimeLockStore.new(refresh_lifetime)
    access_nonce_store = Examples::Storage::InMemoryTimeLockStore.new(access_window)
    authentication_key_store = Examples::Storage::InMemoryAuthenticationKeyStore.new(hasher)
    authentication_nonce_store = Examples::Storage::InMemoryAuthenticationNonceStore.new(authentication_challenge_lifetime)
    recovery_hash_store = Examples::Storage::InMemoryRecoveryHashStore.new

    identity_verifier = Examples::Encoding::MockIdentityVerifier.new(hasher)
    timestamper = Examples::Encoding::Rfc3339Nano.new
    token_encoder = Examples::Encoding::TokenEncoder.new

    server_response_key = Examples::Crypto::Secp256r1.new
    server_response_public_key = server_response_key.public

    server_access_key = Examples::Crypto::Secp256r1.new

    access_key_store = Examples::Storage::VerificationKeyStore.new
    access_key_store.add(server_access_key.identity, server_access_key)

    ba = BetterAuth::API::BetterAuthServer.new(
      crypto: BetterAuth::API::CryptoContainer.new(
        hasher: hasher,
        key_pair: BetterAuth::API::KeyPairContainer.new(
          access: server_access_key,
          response: server_response_key
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

    av = BetterAuth::API::AccessVerifier.new(
      crypto: BetterAuth::API::VerifierCryptoContainer.new(
        verifier: verifier
      ),
      encoding: BetterAuth::API::VerifierEncodingContainer.new(
        token_encoder: token_encoder,
        timestamper: timestamper
      ),
      store: BetterAuth::API::VerifierStoreContainer.new(
        access_nonce: access_nonce_store,
        access_key_store: access_key_store
      )
    )

    current_authentication_key = Examples::Crypto::Secp256r1.new
    next_authentication_key = Examples::Crypto::Secp256r1.new
    next_next_authentication_key = Examples::Crypto::Secp256r1.new
    recovery_key = Examples::Crypto::Secp256r1.new

    next_authentication_public_key = next_authentication_key.public
    next_next_authentication_public_key = next_next_authentication_key.public

    rotation_hash = hasher.sum(next_authentication_public_key.bytes)
    current_key = current_authentication_key.public

    recovery_public_key = recovery_key.public
    recovery_hash = hasher.sum(recovery_public_key.bytes)

    device = hasher.sum(current_key.bytes)
    identity_seed = "#{current_key}#{rotation_hash}#{recovery_hash}"
    identity = hasher.sum(identity_seed.bytes)

    nonce = noncer.generate128

    create_request = BetterAuth::Messages::CreateAccountRequest.new_request(
      BetterAuth::Messages::CreateAccountRequestPayload.new(
        authentication: BetterAuth::Messages::CreateAccountRequestAuthentication.new(
          device: device,
          identity: identity,
          public_key: current_key,
          recovery_hash: recovery_hash,
          rotation_hash: rotation_hash
        )
      ),
      nonce
    )

    create_request.sign(current_authentication_key)

    message = create_request.serialize

    reply = ba.create_account(message)

    create_response = BetterAuth::Messages::CreateAccountResponse.parse(reply)

    create_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(create_response.payload.access.nonce)).to be true

    # Rotate authentication key
    nonce = noncer.generate128
    rotation_hash = hasher.sum(next_next_authentication_public_key.bytes)

    rotate_request = BetterAuth::Messages::RotateAuthenticationKeyRequest.new_request(
      BetterAuth::Messages::RotateAuthenticationKeyRequestPayload.new(
        authentication: BetterAuth::Messages::RotateAuthenticationKeyRequestAuthentication.new(
          device: device,
          identity: identity,
          public_key: next_authentication_public_key,
          rotation_hash: rotation_hash
        )
      ),
      nonce
    )

    rotate_request.sign(next_authentication_key)

    message = rotate_request.serialize

    reply = ba.rotate_authentication_key(message)

    rotate_response = BetterAuth::Messages::RotateAuthenticationKeyResponse.parse(reply)

    rotate_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(rotate_response.payload.access.nonce)).to be true

    # Start authentication
    nonce = noncer.generate128

    start_authentication_request = BetterAuth::Messages::StartAuthenticationRequest.new_request(
      BetterAuth::Messages::StartAuthenticationRequestPayload.new(
        authentication: BetterAuth::Messages::StartAuthenticationRequestAuthentication.new(
          identity: identity
        )
      ),
      nonce
    )

    message = start_authentication_request.serialize

    reply = ba.start_authentication(message)

    start_authentication_response = BetterAuth::Messages::StartAuthenticationResponse.parse(reply)

    start_authentication_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(start_authentication_response.payload.access.nonce)).to be true

    # Finish authentication
    nonce = noncer.generate128

    client_access_key = Examples::Crypto::Secp256r1.new
    client_next_access_key = Examples::Crypto::Secp256r1.new
    client_next_next_access_key = Examples::Crypto::Secp256r1.new

    client_access_public_key = client_access_key.public
    client_next_access_public_key = client_next_access_key.public
    client_next_next_access_public_key = client_next_next_access_key.public

    rotation_hash = hasher.sum(client_next_access_public_key.bytes)

    finish_authentication_request = BetterAuth::Messages::FinishAuthenticationRequest.new_request(
      BetterAuth::Messages::FinishAuthenticationRequestPayload.new(
        access: BetterAuth::Messages::FinishAuthenticationRequestAccess.new(
          public_key: client_access_public_key,
          rotation_hash: rotation_hash
        ),
        authentication: BetterAuth::Messages::FinishAuthenticationRequestAuthentication.new(
          device: device,
          nonce: start_authentication_response.payload.response.authentication.nonce
        )
      ),
      nonce
    )

    finish_authentication_request.sign(next_authentication_key)

    message = finish_authentication_request.serialize

    attributes = MockAttributes.new('admin' => %w[read write])

    reply = ba.finish_authentication(message, attributes)

    finish_authentication_response = BetterAuth::Messages::FinishAuthenticationResponse.parse(reply)

    finish_authentication_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(finish_authentication_response.payload.access.nonce)).to be true

    # Refresh access token
    nonce = noncer.generate128
    rotation_hash = hasher.sum(client_next_next_access_public_key.bytes)

    refresh_access_token_request = BetterAuth::Messages::RefreshAccessTokenRequest.new_request(
      BetterAuth::Messages::RefreshAccessTokenRequestPayload.new(
        access: BetterAuth::Messages::RefreshAccessTokenRequestAccess.new(
          public_key: client_next_access_public_key,
          rotation_hash: rotation_hash,
          token: finish_authentication_response.payload.response.access.token
        )
      ),
      nonce
    )

    refresh_access_token_request.sign(client_next_access_key)

    message = refresh_access_token_request.serialize

    reply = ba.refresh_access_token(message)

    refresh_access_token_response = BetterAuth::Messages::RefreshAccessTokenResponse.parse(reply)

    refresh_access_token_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(refresh_access_token_response.payload.access.nonce)).to be true

    # Verify access
    nonce = noncer.generate128

    access_request = BetterAuth::Messages::AccessRequest.new_request(
      { foo: 'bar', bar: 'foo' },
      timestamper,
      refresh_access_token_response.payload.response.access.token,
      nonce
    )

    access_request.sign(client_next_access_key)

    message = access_request.serialize

    verified_identity, verified_attributes = av.verify(message, MockAttributes.new)

    expect(verified_identity.casecmp?(identity)).to be true
    expect(verified_attributes[:permissionsByRole][:admin]).to eq(attributes.permissions_by_role['admin'])

    # Recover account
    recovered_authentication_key = Examples::Crypto::Secp256r1.new
    recovered_next_authentication_key = Examples::Crypto::Secp256r1.new
    next_recovery_key = Examples::Crypto::Secp256r1.new

    recovered_authentication_public_key = recovered_authentication_key.public
    recovered_next_authentication_public_key = recovered_next_authentication_key.public
    next_recovery_public_key = next_recovery_key.public

    recovered_device = hasher.sum(recovered_authentication_public_key.bytes)
    rotation_hash = hasher.sum(recovered_next_authentication_public_key.bytes)
    next_recovery_hash = hasher.sum(next_recovery_public_key.bytes)

    nonce = noncer.generate128

    recover_request = BetterAuth::Messages::RecoverAccountRequest.new_request(
      BetterAuth::Messages::RecoverAccountRequestPayload.new(
        authentication: BetterAuth::Messages::RecoverAccountRequestAuthentication.new(
          device: recovered_device,
          identity: identity,
          public_key: recovered_authentication_public_key,
          recovery_hash: next_recovery_hash,
          recovery_key: recovery_public_key,
          rotation_hash: rotation_hash
        )
      ),
      nonce
    )

    recover_request.sign(recovery_key)

    message = recover_request.serialize

    reply = ba.recover_account(message)

    recover_account_response = BetterAuth::Messages::RecoverAccountResponse.parse(reply)

    recover_account_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(recover_account_response.payload.access.nonce)).to be true

    # Link device
    linked_authentication_key = Examples::Crypto::Secp256r1.new
    linked_next_authentication_key = Examples::Crypto::Secp256r1.new
    recovered_next_next_authentication_key = Examples::Crypto::Secp256r1.new

    linked_authentication_public_key = linked_authentication_key.public
    linked_next_authentication_public_key = linked_next_authentication_key.public
    recovered_next_next_authentication_public_key = recovered_next_next_authentication_key.public

    linked_device = hasher.sum(linked_authentication_public_key.bytes)
    rotation_hash = hasher.sum(linked_next_authentication_public_key.bytes)

    recovered_next_rotation_hash = hasher.sum(recovered_next_next_authentication_public_key.bytes)

    nonce = noncer.generate128

    link_container = BetterAuth::Messages::LinkContainer.new_container(
      BetterAuth::Messages::LinkContainerPayload.new(
        authentication: BetterAuth::Messages::LinkContainerAuthentication.new(
          device: linked_device,
          identity: identity,
          public_key: linked_authentication_public_key,
          rotation_hash: rotation_hash
        )
      )
    )

    link_container.sign(linked_authentication_key)

    link_device_request = BetterAuth::Messages::LinkDeviceRequest.new_request(
      BetterAuth::Messages::LinkDeviceRequestPayload.new(
        authentication: BetterAuth::Messages::LinkDeviceRequestAuthentication.new(
          device: recovered_device,
          identity: identity,
          public_key: recovered_next_authentication_public_key,
          rotation_hash: recovered_next_rotation_hash
        ),
        link: link_container
      ),
      nonce
    )

    link_device_request.sign(recovered_next_authentication_key)

    message = link_device_request.serialize

    reply = ba.link_device(message)

    link_device_response = BetterAuth::Messages::LinkDeviceResponse.parse(reply)

    link_device_response.verify(server_response_key.verifier, server_response_public_key)

    expect(nonce.casecmp?(link_device_response.payload.access.nonce)).to be true
  end

  it 'completes the full authentication flow' do
    expect { test_flow }.not_to raise_error
  end
end
