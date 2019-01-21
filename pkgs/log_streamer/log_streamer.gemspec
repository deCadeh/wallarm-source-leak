lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'log_streamer'
  spec.version       = ENV.fetch('GEM_VERSION', '0.0.0')
  spec.authors       = ['Mikhail Pronyakin']
  spec.email         = ['pronyakin@onsec.ru']

  spec.summary       = 'Wallarm ruby log streamer library'
  spec.description   = 'Wallarm ruby log streamer library'
  spec.homepage      = 'https://wallarm.com/'

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end

  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'redis'
  spec.add_dependency 'elasticsearch'

  spec.add_development_dependency 'rubocop', '~> 0.50.0'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
end
