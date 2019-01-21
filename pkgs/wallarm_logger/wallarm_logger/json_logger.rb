# -*- encoding: utf-8 -*-

require 'logger'
require 'time'
require 'json'
require_relative 'safe_json'

class JsonLogger < Logger
  attr_accessor :base_msg_hash
  attr_reader   :params

  def reopen
    self.close
    r = JsonLogger.new *params
    r.level = self.level
    return r
  end

  def initialize(*a)
    @params        = Array.new a
    @base_msg_hash = {}
    if a.size > 1
      @base_msg_hash = a.pop
    end

    super *a

    self.formatter = Proc.new do |severity, datetime, progname, msg|
      record = @base_msg_hash.merge(
        { :time  => datetime.getutc.iso8601(6),
          :level => severity,
          :app   => progname,
        }
      )
      if msg.class == Hash
        record.merge! msg
      elsif msg.class == String
        record[:msg] = msg
      else
        raise ArgumentError
      end
      record.merge! additional_fields

      around_request_id(record[:request_id])
      around_job_id(record[:job_id])

      JSON.safe_dump(record) + "\n"
    end
  end

  def exception(ex)
    record = {
      :exception => ex.to_s,
      :backtrace => ex.backtrace
    }
    self.error record
  end

  alias :warning :warn

  def around_request_id(id); end
  def around_job_id(id);     end

  private

  def additional_fields
    record = {}
    if $request_id
      record[:request_id] = $request_id
    end
    if $job_id
      record[:job_id] = $job_id
    end
    record
  end
end
