# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'fast_dsl'
  spec.version       = ENV.fetch('GEM_VERSION', '0.0.0')
  spec.authors       = ['Mikhail Pronyakin']
  spec.email         = ['pronyakin@onsec.ru']

  spec.summary       = 'FAST DSL'
  spec.description   = 'Wallarm FAST easy DSL'
  spec.homepage      = 'https://wallarm.com'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'dry-validation'
  spec.add_dependency 'rkelly-remix'
  spec.add_dependency 'ruby-gumbo'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rubocop'
  spec.add_development_dependency 'simplecov'
end
