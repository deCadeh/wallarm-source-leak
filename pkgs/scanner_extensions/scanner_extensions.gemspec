# coding: utf-8

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'scanner_extensions'
  spec.version       = ENV.fetch('GEM_VERSION', '0.0.0')
  spec.authors       = ['Mikhail Pronyakin']
  spec.email         = ['pronyakin@onsec.ru']

  spec.summary       = 'Wallarm Scanner Extensions'
  spec.description   = 'Wallarm Scanner Extensions. Include Helpers and Extensions::Detect '
  spec.homepage      = 'https://wallarm.com'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'rkelly-fixed'
  spec.add_runtime_dependency 'ruby-gumbo'
  spec.add_runtime_dependency 'therubyracer'
  spec.add_runtime_dependency 'digest-crc'
  spec.add_runtime_dependency 'net-http-rest_client'
  spec.add_runtime_dependency 'kmeans-clusterer'

  # wallarm gems
  spec.add_runtime_dependency 'vuln_templates', '3.47.3'

  spec.add_development_dependency 'bundler', '~> 1.12'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
