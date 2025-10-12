# better-auth-rb

**Ruby server-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This implementation provides server-side protocol handling. For client functionality, use TypeScript, Python, Rust, Swift, Dart, or Kotlin implementations.

## What's Included

- ✅ **Server Only** - All server-side protocol operations
- ✅ **Module-Based** - Duck-typed interfaces using Ruby modules
- ✅ **RSpec Tests** - Complete test suite
- ✅ **Example Server** - HTTP server for integration testing
- ✅ **Gem Package** - Installable as a Ruby gem

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # bundle install
```

### Running Tests

```bash
make test           # Run RSpec tests
make lint           # Run RuboCop
make format-check   # Check code formatting
```

### Running Example Server

```bash
make server         # Start HTTP server on localhost:8080
```

## Development

This implementation uses:
- **Ruby 3.0+** for modern Ruby features
- **Bundler** for dependency management
- **RSpec** for testing
- **RuboCop** for linting and formatting
- **Duck typing** for interface contracts

All development commands use standardized `make` targets:

```bash
make setup          # bundle install
make test           # bundle exec rspec
make lint           # bundle exec rubocop
make format         # bundle exec rubocop -a
make format-check   # bundle exec rubocop
make clean          # Remove build artifacts
make server         # Run example server
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Ruby-specific patterns (modules, duck typing, error handling)
- Message types and protocol handlers
- Usage examples and API patterns

### Key Features

- **Module-Based Interfaces**: Hasher, Verifier, SigningKey, Timestamper, TokenEncoder, etc.
- **Duck Typing**: Objects must respond to required methods
- **Class-Based Messages**: Attributes with `to_h` and `from_hash` methods
- **Ruby-Style Errors**: Custom exception classes inheriting from `StandardError`
- **JSON Serialization**: Using Ruby's JSON library

### Reference Implementations

The `examples/` directory contains reference implementations using:
- **BLAKE3** for cryptographic hashing
- **SECP256R1** for signing/verification
- **In-memory stores** for testing
- **RFC3339** timestamps
- **gzip** token compression

## Integration with Other Implementations

This Ruby server is designed for integration testing with client implementations:
- **TypeScript client** (better-auth-ts)
- **Python client** (better-auth-py)
- **Rust client** (better-auth-rs)
- **Swift client** (better-auth-swift)
- **Dart client** (better-auth-dart)
- **Kotlin client** (better-auth-kt)

See `examples/server.rb` for the HTTP server implementation.

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb) - **This repository**

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
