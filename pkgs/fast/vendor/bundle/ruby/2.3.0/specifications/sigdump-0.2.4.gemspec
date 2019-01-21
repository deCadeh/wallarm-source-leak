# -*- encoding: utf-8 -*-
# stub: sigdump 0.2.4 ruby lib

Gem::Specification.new do |s|
  s.name = "sigdump".freeze
  s.version = "0.2.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Sadayuki Furuhashi".freeze]
  s.date = "2016-02-04"
  s.description = "Setup signal handler which dumps backtrace of running threads and number of allocated objects per class. Require 'sigdump/setup', send SIGCONT, and see /tmp/sigdump-<pid>.log.".freeze
  s.email = ["frsyuki@gmail.com".freeze]
  s.homepage = "https://github.com/frsyuki/sigdump".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "Setup signal handler which dumps backtrace of running threads and number of allocated objects per class. Require 'sigdump/setup', send SIGCONT, and see /tmp/sigdump-<pid>.log.".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, [">= 0.9.2"])
    else
      s.add_dependency(%q<rake>.freeze, [">= 0.9.2"])
    end
  else
    s.add_dependency(%q<rake>.freeze, [">= 0.9.2"])
  end
end
