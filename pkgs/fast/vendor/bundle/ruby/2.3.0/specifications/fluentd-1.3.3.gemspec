# -*- encoding: utf-8 -*-
# stub: fluentd 1.3.3 ruby lib

Gem::Specification.new do |s|
  s.name = "fluentd".freeze
  s.version = "1.3.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Sadayuki Furuhashi".freeze]
  s.date = "2019-01-07"
  s.description = "Fluentd is an open source data collector designed to scale and simplify log management. It can collect, process and ship many kinds of data in near real-time.".freeze
  s.email = ["frsyuki@gmail.com".freeze]
  s.executables = ["fluent-binlog-reader".freeze, "fluent-ca-generate".freeze, "fluent-cat".freeze, "fluent-debug".freeze, "fluent-gem".freeze, "fluent-plugin-config-format".freeze, "fluent-plugin-generate".freeze, "fluentd".freeze]
  s.files = ["bin/fluent-binlog-reader".freeze, "bin/fluent-ca-generate".freeze, "bin/fluent-cat".freeze, "bin/fluent-debug".freeze, "bin/fluent-gem".freeze, "bin/fluent-plugin-config-format".freeze, "bin/fluent-plugin-generate".freeze, "bin/fluentd".freeze]
  s.homepage = "https://www.fluentd.org/".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1".freeze)
  s.rubygems_version = "2.5.2.1".freeze
  s.summary = "Fluentd event collector".freeze

  s.installed_by_version = "2.5.2.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<msgpack>.freeze, ["< 2.0.0", ">= 0.7.0"])
      s.add_runtime_dependency(%q<yajl-ruby>.freeze, ["~> 1.0"])
      s.add_runtime_dependency(%q<cool.io>.freeze, ["< 2.0.0", ">= 1.4.5"])
      s.add_runtime_dependency(%q<serverengine>.freeze, ["< 3.0.0", ">= 2.0.4"])
      s.add_runtime_dependency(%q<http_parser.rb>.freeze, ["< 0.7.0", ">= 0.5.1"])
      s.add_runtime_dependency(%q<sigdump>.freeze, ["~> 0.2.2"])
      s.add_runtime_dependency(%q<tzinfo>.freeze, ["~> 1.0"])
      s.add_runtime_dependency(%q<tzinfo-data>.freeze, ["~> 1.0"])
      s.add_runtime_dependency(%q<strptime>.freeze, ["< 1.0.0", ">= 0.2.2"])
      s.add_runtime_dependency(%q<dig_rb>.freeze, ["~> 1.0.0"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 11.0"])
      s.add_development_dependency(%q<flexmock>.freeze, ["~> 2.0"])
      s.add_development_dependency(%q<parallel_tests>.freeze, ["~> 0.15.3"])
      s.add_development_dependency(%q<simplecov>.freeze, ["~> 0.7"])
      s.add_development_dependency(%q<rr>.freeze, ["~> 1.0"])
      s.add_development_dependency(%q<timecop>.freeze, ["~> 0.3"])
      s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.2"])
      s.add_development_dependency(%q<test-unit-rr>.freeze, ["~> 1.0"])
      s.add_development_dependency(%q<oj>.freeze, ["< 4", ">= 2.14"])
    else
      s.add_dependency(%q<msgpack>.freeze, ["< 2.0.0", ">= 0.7.0"])
      s.add_dependency(%q<yajl-ruby>.freeze, ["~> 1.0"])
      s.add_dependency(%q<cool.io>.freeze, ["< 2.0.0", ">= 1.4.5"])
      s.add_dependency(%q<serverengine>.freeze, ["< 3.0.0", ">= 2.0.4"])
      s.add_dependency(%q<http_parser.rb>.freeze, ["< 0.7.0", ">= 0.5.1"])
      s.add_dependency(%q<sigdump>.freeze, ["~> 0.2.2"])
      s.add_dependency(%q<tzinfo>.freeze, ["~> 1.0"])
      s.add_dependency(%q<tzinfo-data>.freeze, ["~> 1.0"])
      s.add_dependency(%q<strptime>.freeze, ["< 1.0.0", ">= 0.2.2"])
      s.add_dependency(%q<dig_rb>.freeze, ["~> 1.0.0"])
      s.add_dependency(%q<rake>.freeze, ["~> 11.0"])
      s.add_dependency(%q<flexmock>.freeze, ["~> 2.0"])
      s.add_dependency(%q<parallel_tests>.freeze, ["~> 0.15.3"])
      s.add_dependency(%q<simplecov>.freeze, ["~> 0.7"])
      s.add_dependency(%q<rr>.freeze, ["~> 1.0"])
      s.add_dependency(%q<timecop>.freeze, ["~> 0.3"])
      s.add_dependency(%q<test-unit>.freeze, ["~> 3.2"])
      s.add_dependency(%q<test-unit-rr>.freeze, ["~> 1.0"])
      s.add_dependency(%q<oj>.freeze, ["< 4", ">= 2.14"])
    end
  else
    s.add_dependency(%q<msgpack>.freeze, ["< 2.0.0", ">= 0.7.0"])
    s.add_dependency(%q<yajl-ruby>.freeze, ["~> 1.0"])
    s.add_dependency(%q<cool.io>.freeze, ["< 2.0.0", ">= 1.4.5"])
    s.add_dependency(%q<serverengine>.freeze, ["< 3.0.0", ">= 2.0.4"])
    s.add_dependency(%q<http_parser.rb>.freeze, ["< 0.7.0", ">= 0.5.1"])
    s.add_dependency(%q<sigdump>.freeze, ["~> 0.2.2"])
    s.add_dependency(%q<tzinfo>.freeze, ["~> 1.0"])
    s.add_dependency(%q<tzinfo-data>.freeze, ["~> 1.0"])
    s.add_dependency(%q<strptime>.freeze, ["< 1.0.0", ">= 0.2.2"])
    s.add_dependency(%q<dig_rb>.freeze, ["~> 1.0.0"])
    s.add_dependency(%q<rake>.freeze, ["~> 11.0"])
    s.add_dependency(%q<flexmock>.freeze, ["~> 2.0"])
    s.add_dependency(%q<parallel_tests>.freeze, ["~> 0.15.3"])
    s.add_dependency(%q<simplecov>.freeze, ["~> 0.7"])
    s.add_dependency(%q<rr>.freeze, ["~> 1.0"])
    s.add_dependency(%q<timecop>.freeze, ["~> 0.3"])
    s.add_dependency(%q<test-unit>.freeze, ["~> 3.2"])
    s.add_dependency(%q<test-unit-rr>.freeze, ["~> 1.0"])
    s.add_dependency(%q<oj>.freeze, ["< 4", ">= 2.14"])
  end
end
