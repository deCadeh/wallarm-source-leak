# -*- encoding: utf-8 -*-

require 'logger'
require 'time'

class StandartLogger < Logger
  FORMAT = '%Y-%m-%d %H:%M:%S'

  alias :write   :'<<'
  alias :warning :warn

  attr_reader :params

  def initialize(*a)
    @params = Array.new a
    super *a

    self.formatter = proc do |severity, datetime, progname, msg|
      "[#{datetime.strftime(FORMAT)}] [#{severity}] #{msg}\n"
    end
  end

  def reopen
    self.close unless params[0]==STDOUT
    r = StandartLogger.new *params
    r.level = self.level
    return r
  end

  def exception(ex)
    self.error do
      "#{ex.message} (#{ex.class})\n    #{ex.backtrace.join("\n    ")}"
    end
  end
end
