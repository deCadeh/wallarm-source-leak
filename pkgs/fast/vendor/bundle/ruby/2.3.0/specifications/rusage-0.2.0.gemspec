# -*- encoding: utf-8 -*-
# stub: rusage 0.2.0 ruby ext
# stub: ext/rusage/extconf.rb

Gem::Specification.new do |s|
  s.name = "rusage".freeze
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["ext".freeze]
  s.authors = ["Ben Sandofsky".freeze]
  s.date = "2010-05-04"
  s.description = "A gem that calls getrusage to get details on the current process.\n\nRipped out of the proc/wait3 library, originally written by Daniel J. Berger.\n\nhttp://raa.ruby-lang.org/project/proc-wait3/".freeze
  s.email = ["ben@sandofsky.com".freeze]
  s.extensions = ["ext/rusage/extconf.rb".freeze]
  s.extra_rdoc_files = ["History.txt".freeze, "Manifest.txt".freeze, "README.txt".freeze]
  s.files = ["History.txt".freeze, "Manifest.txt".freeze, "README.txt".freeze, "ext/rusage/extconf.rb".freeze]
  s.homepage = "http://github.com/sandofsky/rusage".freeze
  s.rdoc_options = ["--main".freeze, "README.txt".freeze]
  s.rubyforge_project = "rusage".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "A gem that calls getrusage to get details on the current process".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<hoe>.freeze, [">= 2.3.3"])
    else
      s.add_dependency(%q<hoe>.freeze, [">= 2.3.3"])
    end
  else
    s.add_dependency(%q<hoe>.freeze, [">= 2.3.3"])
  end
end
