# -*- encoding: utf-8 -*-
# stub: fast_dsl 0.4.2 ruby lib

Gem::Specification.new do |s|
  s.name = "fast_dsl".freeze
  s.version = "0.4.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Mikhail Pronyakin".freeze]
  s.bindir = "exe".freeze
  s.date = "2018-12-24"
  s.description = "Wallarm FAST easy DSL".freeze
  s.email = ["pronyakin@onsec.ru".freeze]
  s.homepage = "https://wallarm.com".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "FAST DSL".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<dry-validation>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<rkelly-remix>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
      s.add_development_dependency(%q<bundler>.freeze, [">= 0"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_development_dependency(%q<rubocop>.freeze, [">= 0"])
      s.add_development_dependency(%q<simplecov>.freeze, [">= 0"])
    else
      s.add_dependency(%q<dry-validation>.freeze, [">= 0"])
      s.add_dependency(%q<rkelly-remix>.freeze, [">= 0"])
      s.add_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
      s.add_dependency(%q<bundler>.freeze, [">= 0"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
      s.add_dependency(%q<rubocop>.freeze, [">= 0"])
      s.add_dependency(%q<simplecov>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<dry-validation>.freeze, [">= 0"])
    s.add_dependency(%q<rkelly-remix>.freeze, [">= 0"])
    s.add_dependency(%q<ruby-gumbo>.freeze, [">= 0"])
    s.add_dependency(%q<bundler>.freeze, [">= 0"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
    s.add_dependency(%q<rubocop>.freeze, [">= 0"])
    s.add_dependency(%q<simplecov>.freeze, [">= 0"])
  end
end
