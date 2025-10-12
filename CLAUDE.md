# Better Auth - Ruby Implementation

## Project Context

This is a **Ruby server-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation provides **server-side only** components. For client functionality, use one of the other implementations (TypeScript, Python, Rust, Swift, Dart, or Kotlin).

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript - Client + Server)

**Other Implementations:**
- Full (Client + Server): [Python](https://github.com/jasoncolburne/better-auth-py), [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Install dependencies (bundle install)
make test           # Run tests (bundle exec rspec)
make lint           # Run linter (bundle exec rubocop)
make format         # Format code (bundle exec rubocop -a)
make format-check   # Check formatting (bundle exec rubocop)
make clean          # Clean artifacts
make server         # Run example server (bundle exec ruby examples/server.rb)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
lib/
├── better_auth.rb                  # Main entry point, requires all files
└── better_auth/
    ├── api/                        # Server API implementation
    │   ├── better_auth.rb          # BetterAuth::Server class
    │   ├── account.rb              # Account protocol handlers
    │   ├── device.rb               # Device protocol handlers
    │   ├── session.rb              # Session protocol handlers
    │   └── access.rb               # Access protocol handlers
    ├── crypto_interfaces/          # Crypto interface modules
    │   ├── hasher.rb               # Hasher module
    │   ├── verifier.rb             # Verifier module
    │   ├── signing_key.rb          # SigningKey module
    │   ├── verification_key.rb     # VerificationKey module
    │   └── noncer.rb               # Noncer module
    ├── encoding_interfaces/        # Encoding interface modules
    │   ├── timestamper.rb          # Timestamper module
    │   ├── token_encoder.rb        # TokenEncoder module
    │   └── identity_verifier.rb    # IdentityVerifier module
    ├── storage_interfaces/         # Storage interface modules
    │   ├── authentication.rb       # Authentication storage
    │   ├── access.rb               # Access storage
    │   ├── recovery.rb             # Recovery storage
    │   ├── verification_key_store.rb
    │   └── timelock.rb             # Timelock storage
    └── messages/                   # Protocol message types
        ├── common.rb               # Base message types
        ├── account.rb              # Account messages
        ├── device.rb               # Device messages
        ├── session.rb              # Session messages
        └── access.rb               # Access messages

spec/                               # RSpec tests
├── api_spec.rb                     # Main API test suite
├── token_spec.rb                   # Token tests
└── spec_helper.rb                  # Test configuration

examples/
├── crypto/                         # Example crypto implementations
│   ├── blake3.rb                   # BLAKE3 hasher
│   ├── nonce.rb                    # Nonce generator
│   └── secp256r1.rb                # SECP256R1 signing/verification
├── encoding/                       # Example encoding implementations
│   ├── identity_verifier.rb        # Identity verification
│   ├── rfc3339nano.rb              # Timestamper
│   └── token_encoder.rb            # Token encoding
├── storage/                        # Example storage implementations
│   ├── authentication_key.rb       # Authentication key storage
│   ├── authentication_nonce.rb     # Nonce storage
│   ├── recovery_hash.rb            # Recovery hash storage
│   ├── timelock.rb                 # Timelock storage
│   └── verification_key_store.rb   # Verification key storage
└── server.rb                       # Example HTTP server
```

### Key Components

**BetterAuth::Server** (`lib/better_auth/api/better_auth.rb`)
- Main server class
- Composes crypto, encoding, and storage modules
- Routes requests to appropriate protocol handlers

**Protocol Handlers** (`lib/better_auth/api/*.rb`)
- `account.rb`: CreateAccount, DeleteAccount, RecoverAccount
- `device.rb`: LinkDevice, UnlinkDevice, RotateDevice
- `session.rb`: RequestSession, CreateSession, RefreshSession
- `access.rb`: HandleAccessRequest, VerifyAccessToken

**Message Types** (`lib/better_auth/messages/`)
- Ruby classes with attributes
- Request and response types for all protocols
- JSON serialization via `to_json` / `from_json`

**Interface Modules** (`lib/better_auth/*/`)
- Module definitions for crypto, encoding, and storage
- Duck typing - objects must respond to required methods
- Implementations provided via constructor

## Ruby-Specific Patterns

### Module-Based Interfaces

This implementation uses Ruby modules to define interface contracts:
- `Hasher`, `Verifier`, `SigningKey` for crypto
- `Timestamper`, `TokenEncoder`, `IdentityVerifier` for encoding
- Storage modules for server state management

Ruby uses duck typing:
- No explicit interface inheritance required
- Objects just need to respond to the required methods
- Modules document expected method signatures

### Class-Based Messages

Message types are defined as classes:
- Attributes defined with `attr_accessor` or `attr_reader`
- Instance methods for serialization (`to_h`, `to_json`)
- Class methods for deserialization (`from_hash`)

### Error Handling

Ruby-style exception handling:
- Custom exception classes inheriting from `StandardError`
- `raise` to throw exceptions
- `rescue` to catch exceptions
- Stack traces preserved

### JSON Serialization

Messages use Ruby's JSON library:
- `to_h` converts objects to hashes
- `JSON.generate` for JSON string output
- `JSON.parse` for JSON string input
- `from_hash` class methods for object construction

### Dependency Injection

Server initialization uses a configuration hash:
- Hash of configuration options
- Clear structure with nested hashes
- Easy to extend with new options

## Testing

### RSpec Tests (`spec/api_spec.rb`, `spec/token_spec.rb`)
Tests covering all protocol operations:
- Account creation, recovery, deletion
- Device linking/unlinking, rotation
- Session request/creation/refresh
- Access token generation and verification
- Token encoding/decoding

Run with: `bundle exec rspec`

### Running Tests
```bash
bundle exec rspec              # Run all tests
bundle exec rspec -fd          # Verbose format
bundle exec rspec spec/api_spec.rb  # Run API tests
bundle exec rspec spec/token_spec.rb  # Run token tests
```

## Usage Patterns

### Server Initialization

```ruby
require 'better_auth'

server = BetterAuth::Server.new(
  crypto: {
    hasher: your_hasher,
    key_pair: {
      response: response_signing_key,
      access: access_signing_key
    },
    verifier: your_verifier
  },
  encoding: {
    identity_verifier: your_identity_verifier,
    timestamper: your_timestamper,
    token_encoder: your_token_encoder
  },
  expiry: {
    access_in_minutes: 15,
    refresh_in_hours: 24
  },
  store: {
    access: {
      key_hash: access_key_hash_store
    },
    authentication: {
      key: auth_key_store,
      nonce: nonce_store
    },
    recovery: {
      hash: recovery_hash_store
    }
  }
)
```

### Handling Requests

```ruby
# Parse request from JSON
request = JSON.parse(request_json)

# Handle request
response = server.handle_request(request)

# Serialize response to JSON
response_json = JSON.generate(response)
```

### HTTP Server Example

See `examples/server.rb` for a complete HTTP server implementation using Sinatra or similar:
- Listens on port 8080
- Handles JSON POST requests
- Routes to the BetterAuth::Server
- Returns JSON responses

Run with: `bundle exec ruby examples/server.rb`

## Development Workflow

### Installation
```bash
bundle install                # Install dependencies
```

### Testing
```bash
bundle exec rspec             # Run all tests
bundle exec rspec -fd         # Verbose format
bundle exec rspec --format documentation  # Documentation format
```

### Linting & Formatting
```bash
bundle exec rubocop           # Lint with RuboCop
bundle exec rubocop -a        # Auto-correct issues
```

### Running Example Server
```bash
bundle exec ruby examples/server.rb       # Start HTTP server
```

## Integration with Other Implementations

This Ruby server is designed for integration testing with client implementations:
- TypeScript client (`better-auth-ts`)
- Python client (`better-auth-py`)
- Rust client (`better-auth-rs`)
- Swift client (`better-auth-swift`)
- Dart client (`better-auth-dart`)
- Kotlin client (`better-auth-kt`)

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `bundle exec rspec`
3. Lint code: `bundle exec rubocop`
4. If protocol changes: sync with the TypeScript reference implementation
5. If breaking changes: update client implementations that depend on this server
6. Run integration tests from client repositories
7. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `lib/better_auth/api/better_auth.rb` - Main server class
- `lib/better_auth/api/account.rb` - Account protocol handlers
- `lib/better_auth/api/device.rb` - Device protocol handlers
- `lib/better_auth/api/session.rb` - Session protocol handlers
- `lib/better_auth/api/access.rb` - Access protocol handlers and token verification
- `lib/better_auth/messages/` - Protocol message type definitions
- `lib/better_auth/crypto_interfaces/` - Crypto interface modules
- `lib/better_auth/encoding_interfaces/` - Encoding interface modules
- `lib/better_auth/storage_interfaces/` - Storage interface modules
- `examples/crypto/` - Example crypto implementations (BLAKE3, SECP256R1, nonce)
- `examples/encoding/` - Example encoding implementations (timestamper, token encoder, identity verifier)
- `examples/storage/` - Example storage implementations (authentication, recovery, timelock)
- `examples/server.rb` - Example HTTP server
- `spec/api_spec.rb` - Comprehensive API test suite
- `spec/token_spec.rb` - Token encoding/decoding tests
- `better_auth.gemspec` - Gem specification

## Ruby Version

Requires Ruby 3.0+ for:
- Modern syntax features
- Performance improvements
- Better pattern matching support

## Gem Structure

This is packaged as a Ruby gem:
- `better_auth.gemspec` defines the gem
- `Gemfile` manages dependencies
- Install with: `gem install better_auth` or `bundle install`
