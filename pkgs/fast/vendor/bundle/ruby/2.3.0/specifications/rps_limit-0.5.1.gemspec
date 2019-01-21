# -*- encoding: utf-8 -*-
# stub: rps_limit 0.5.1 ruby lib

Gem::Specification.new do |s|
  s.name = "rps_limit".freeze
  s.version = "0.5.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["pronyakin".freeze]
  s.date = "2018-07-19"
  s.description = "Library for limiting rps while scanning wallarm clients".freeze
  s.email = "pronyakin@onsec.ru".freeze
  s.homepage = "http://my.wallarm.com".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "Library for limiting rps while scanning wallarm clients".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<etcd>.freeze, [">= 0"])
    else
      s.add_dependency(%q<etcd>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<etcd>.freeze, [">= 0"])
  end
end
