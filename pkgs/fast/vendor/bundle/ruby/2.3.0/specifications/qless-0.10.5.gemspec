# -*- encoding: utf-8 -*-
# stub: qless 0.10.5 ruby lib

Gem::Specification.new do |s|
  s.name = "qless".freeze
  s.version = "0.10.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dan Lecocq".freeze, "Myron Marston".freeze]
  s.bindir = "exe".freeze
  s.date = "2016-11-29"
  s.description = "\n`qless` is meant to be a performant alternative to other queueing\nsystems, with statistics collection, a browser interface, and\nstrong guarantees about job losses.\n\nIt's written as a collection of Lua scipts that are loaded into the\nRedis instance to be used, and then executed by the client library.\nAs such, it's intended to be extremely easy to port to other languages,\nwithout sacrificing performance and not requiring a lot of logic\nreplication between clients. Keep the Lua scripts updated, and your\nlanguage-specific extension will also remain up to date.\n  ".freeze
  s.email = ["dan@moz.com".freeze, "myron@moz.com".freeze]
  s.executables = ["qless-web".freeze, "qless-config".freeze, "qless-stats".freeze]
  s.files = ["exe/qless-config".freeze, "exe/qless-stats".freeze, "exe/qless-web".freeze]
  s.homepage = "http://github.com/seomoz/qless".freeze
  s.rubyforge_project = "qless".freeze
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "A Redis-Based Queueing System".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<metriks>.freeze, ["~> 0.9"])
      s.add_runtime_dependency(%q<redis>.freeze, ["< 4.0.0.rc1", ">= 2.2"])
      s.add_runtime_dependency(%q<rusage>.freeze, ["~> 0.2.0"])
      s.add_runtime_dependency(%q<sentry-raven>.freeze, ["~> 0.4"])
      s.add_runtime_dependency(%q<sinatra>.freeze, ["~> 1.3"])
      s.add_runtime_dependency(%q<statsd-ruby>.freeze, ["~> 1.3"])
      s.add_runtime_dependency(%q<thin>.freeze, ["~> 1.6.4"])
      s.add_runtime_dependency(%q<thor>.freeze, ["~> 0.19.1"])
      s.add_runtime_dependency(%q<vegas>.freeze, ["~> 0.1.11"])
    else
      s.add_dependency(%q<metriks>.freeze, ["~> 0.9"])
      s.add_dependency(%q<redis>.freeze, ["< 4.0.0.rc1", ">= 2.2"])
      s.add_dependency(%q<rusage>.freeze, ["~> 0.2.0"])
      s.add_dependency(%q<sentry-raven>.freeze, ["~> 0.4"])
      s.add_dependency(%q<sinatra>.freeze, ["~> 1.3"])
      s.add_dependency(%q<statsd-ruby>.freeze, ["~> 1.3"])
      s.add_dependency(%q<thin>.freeze, ["~> 1.6.4"])
      s.add_dependency(%q<thor>.freeze, ["~> 0.19.1"])
      s.add_dependency(%q<vegas>.freeze, ["~> 0.1.11"])
    end
  else
    s.add_dependency(%q<metriks>.freeze, ["~> 0.9"])
    s.add_dependency(%q<redis>.freeze, ["< 4.0.0.rc1", ">= 2.2"])
    s.add_dependency(%q<rusage>.freeze, ["~> 0.2.0"])
    s.add_dependency(%q<sentry-raven>.freeze, ["~> 0.4"])
    s.add_dependency(%q<sinatra>.freeze, ["~> 1.3"])
    s.add_dependency(%q<statsd-ruby>.freeze, ["~> 1.3"])
    s.add_dependency(%q<thin>.freeze, ["~> 1.6.4"])
    s.add_dependency(%q<thor>.freeze, ["~> 0.19.1"])
    s.add_dependency(%q<vegas>.freeze, ["~> 0.1.11"])
  end
end
