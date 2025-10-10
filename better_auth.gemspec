# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'better_auth'
  spec.version       = '0.1.0'
  spec.authors       = ['Jason Colburne']
  spec.email         = ['jasoncolburne@users.noreply.github.com']
  spec.summary       = 'Ruby server implementation of better-auth'
  spec.description   = 'Server-side implementation of better-auth - Agnostic authentication framework'
  spec.homepage      = 'https://github.com/jasoncolburne/better-auth-rb'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.4.0'

  spec.files         = Dir['lib/**/*', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']

  spec.add_dependency 'json', '~> 2.9'

  spec.metadata['rubygems_mfa_required'] = 'true'
end
