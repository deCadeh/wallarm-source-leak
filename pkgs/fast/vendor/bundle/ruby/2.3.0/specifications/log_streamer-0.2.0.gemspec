# -*- encoding: utf-8 -*-
# stub: log_streamer 0.2.0 ruby lib

Gem::Specification.new do |s|
  s.name = "log_streamer".freeze
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Mikhail Pronyakin".freeze]
  s.bindir = "exe".freeze
  s.date = "2018-09-12"
  s.description = "Wallarm ruby log streamer library".freeze
  s.email = ["pronyakin@onsec.ru".freeze]
  s.homepage = "https://wallarm.com/".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "Wallarm ruby log streamer library".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<redis>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<elasticsearch>.freeze, [">= 0"])
      s.add_development_dependency(%q<rubocop>.freeze, ["~> 0.50.0"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
    else
      s.add_dependency(%q<redis>.freeze, [">= 0"])
      s.add_dependency(%q<elasticsearch>.freeze, [">= 0"])
      s.add_dependency(%q<rubocop>.freeze, ["~> 0.50.0"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<redis>.freeze, [">= 0"])
    s.add_dependency(%q<elasticsearch>.freeze, [">= 0"])
    s.add_dependency(%q<rubocop>.freeze, ["~> 0.50.0"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
  end
end
