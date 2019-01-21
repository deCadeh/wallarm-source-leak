# -*- encoding: utf-8 -*-
# stub: scanner_extensions 0.14.2 ruby lib

Gem::Specification.new do |s|
  s.name = "scanner_extensions".freeze
  s.version = "0.14.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Mikhail Pronyakin".freeze]
  s.bindir = "exe".freeze
  s.date = "2018-11-02"
  s.description = "Wallarm Scanner Extensions. Include Helpers and Extensions::Detect ".freeze
  s.email = ["pronyakin@onsec.ru".freeze]
  s.homepage = "https://wallarm.com".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "Wallarm Scanner Extensions".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rkelly-fixed>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<therubyracer>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<digest-crc>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<net-http-rest_client>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<kmeans-clusterer>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<vuln_templates>.freeze, ["= 3.47.3"])
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.12"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 10.0"])
      s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0"])
    else
      s.add_dependency(%q<rkelly-fixed>.freeze, [">= 0"])
      s.add_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
      s.add_dependency(%q<therubyracer>.freeze, [">= 0"])
      s.add_dependency(%q<digest-crc>.freeze, [">= 0"])
      s.add_dependency(%q<net-http-rest_client>.freeze, [">= 0"])
      s.add_dependency(%q<kmeans-clusterer>.freeze, [">= 0"])
      s.add_dependency(%q<vuln_templates>.freeze, ["= 3.47.3"])
      s.add_dependency(%q<bundler>.freeze, ["~> 1.12"])
      s.add_dependency(%q<rake>.freeze, ["~> 10.0"])
      s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
    end
  else
    s.add_dependency(%q<rkelly-fixed>.freeze, [">= 0"])
    s.add_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
    s.add_dependency(%q<therubyracer>.freeze, [">= 0"])
    s.add_dependency(%q<digest-crc>.freeze, [">= 0"])
    s.add_dependency(%q<net-http-rest_client>.freeze, [">= 0"])
    s.add_dependency(%q<kmeans-clusterer>.freeze, [">= 0"])
    s.add_dependency(%q<vuln_templates>.freeze, ["= 3.47.3"])
    s.add_dependency(%q<bundler>.freeze, ["~> 1.12"])
    s.add_dependency(%q<rake>.freeze, ["~> 10.0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 3.0"])
  end
end
