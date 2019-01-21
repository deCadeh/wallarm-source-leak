# -*- encoding: utf-8 -*-
# stub: fluent-config-regexp-type 1.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "fluent-config-regexp-type".freeze
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Kenji Okimoto".freeze]
  s.bindir = "exe".freeze
  s.date = "2018-05-24"
  s.description = "The compatibility monkey patch to use regexp type ".freeze
  s.email = ["okimoto@clear-code.com".freeze]
  s.homepage = "https://github.com/okkez/fluent-config-regexp-type".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "The compatibility monkey patch to use regexp type".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<appraisal>.freeze, [">= 0"])
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.16"])
      s.add_development_dependency(%q<rake>.freeze, ["> 10.0"])
      s.add_development_dependency(%q<test-unit>.freeze, ["> 3"])
      s.add_runtime_dependency(%q<fluentd>.freeze, ["< 2", "> 1.0.0"])
    else
      s.add_dependency(%q<appraisal>.freeze, [">= 0"])
      s.add_dependency(%q<bundler>.freeze, ["~> 1.16"])
      s.add_dependency(%q<rake>.freeze, ["> 10.0"])
      s.add_dependency(%q<test-unit>.freeze, ["> 3"])
      s.add_dependency(%q<fluentd>.freeze, ["< 2", "> 1.0.0"])
    end
  else
    s.add_dependency(%q<appraisal>.freeze, [">= 0"])
    s.add_dependency(%q<bundler>.freeze, ["~> 1.16"])
    s.add_dependency(%q<rake>.freeze, ["> 10.0"])
    s.add_dependency(%q<test-unit>.freeze, ["> 3"])
    s.add_dependency(%q<fluentd>.freeze, ["< 2", "> 1.0.0"])
  end
end
