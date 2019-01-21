# -*- encoding: utf-8 -*-

require 'logger'

class LocalLogger < Logger
  FORMAT = '%Y-%m-%d %H:%M:%S'

  alias :write :'<<' # rack support
  alias :warning :warn

  def initialize(*a)
    super

    self.formatter = Proc.new do |s, d, p, m|
      "#{d.strftime(FORMAT)} #{s.ljust(5)} #{self.progname}[#{$$}] -- #{m}\n"
    end
  end

  def exception(ex)
    self.error { "#{ex}\n    #{ex.backtrace.join("\n    ")}" }
  end
end

