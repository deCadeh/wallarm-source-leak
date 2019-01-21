# -*- encoding: utf-8 -*-
# stub: kmeans-clusterer 0.11.4 ruby lib

Gem::Specification.new do |s|
  s.name = "kmeans-clusterer".freeze
  s.version = "0.11.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Geoff Buesing".freeze]
  s.date = "2015-04-17"
  s.description = "k-means clustering. Uses NArray for fast calculations.".freeze
  s.email = "gbuesing@gmail.com".freeze
  s.homepage = "https://github.com/gbuesing/kmeans-clusterer".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "k-means clustering".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<narray>.freeze, ["~> 0.6"])
    else
      s.add_dependency(%q<narray>.freeze, ["~> 0.6"])
    end
  else
    s.add_dependency(%q<narray>.freeze, ["~> 0.6"])
  end
end
