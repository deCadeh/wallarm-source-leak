#
# Log formatter
#

require 'logger'

class Wallarm
  class LogFormatter < Logger::Formatter
    attr_accessor :colored

    def call(severity, time, progname, msg)
      if colored
        setcolor="\033[0;31m" if severity == "FATAL"
        setcolor="\033[0;31m" if severity == "ERROR"
        setcolor="\033[0;33m" if severity == "WARN"
        setcolor="\033[0;32m" if severity == "INFO"
        setcolor="\033[m" if severity == "DEBUG"
        unsetcolor="\033[m"
      else
        setcolor=''
        unsetcolor=''
      end

      if progname.nil?
        prefix = "#{time.strftime("%Y-%m-%d %H:%M:%S")} #{severity} rake[#{$$}]"
      else
        prefix = "#{time.strftime("%Y-%m-%d %H:%M:%S")} #{severity} #{progname}[#{$$}]"
      end

      case msg
      when ::String
        msg.split("\n").map{ |l| "#{setcolor}#{prefix}: #{l}#{unsetcolor}\n" }.join("")
      when ::Exception
        "#{setcolor}#{prefix}: #{msg.message} (#{msg.class})#{unsetcolor}\n" <<
          (msg.backtrace || []).map{ |l| "#{setcolor}#{prefix}:   #{l}#{unsetcolor}\n" }.join("")
      end
    end
  end
end
