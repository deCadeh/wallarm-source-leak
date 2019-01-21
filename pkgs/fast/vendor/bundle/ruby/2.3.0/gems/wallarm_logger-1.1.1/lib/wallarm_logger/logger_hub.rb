require_relative './json_logger'
require_relative './local_logger'
require_relative './standart_logger'

# Singletone container of all LoggerHub instances
# Use it to reopen all logs by signal
class ActiveLoggerHubs
  @@hubs = []

  class << self
    def hubs
      @@hubs
    end

    def clear
      @@hubs = []
    end

    def add(hub)
      @@hubs << hub
    end

    def reopen
      @@hubs.each(&:reopen)
    end

    def trap(signal)
      Signal.trap(signal) do
        ActiveLoggerHubs.reopen
      end
    end
  end
end

# LoggerHub contains other loggers
# Use LoggerHub to log messages into different loggers simultaneously
class LoggerHub
  attr_reader :loggers
  attr_reader :old_loggers

  def initialize
    @mutex       = Mutex.new
    @reopen      = false
    @loggers     = []
    @old_loggers = []
    ActiveLoggerHubs.add(self)
  end

  # Use for loggers that can be reopened
  def add_logger(logger)
    @loggers << logger
  end

  # Use for loggers that cannot be reopened
  def add_old_logger(logger)
    @old_loggers << logger
  end

  # Logs will be reopened later
  def reopen
    @reopen = true
  end

  def get_reopen
    @reopen
  end

  def pop_last_logger
    @loggers = @loggers[0...-1]
  end

  LOG_METHODS = [
    :debug, :info, :warn, :warning, :error, :fatal, :unknown
  ].freeze

  def exception(ex)
    @mutex.synchronize { reopen_logs if @reopen }
    (@loggers + @old_loggers).each do |logger|
      logger.exception(ex)
    end
  end

  LOG_METHODS.each do |method|
    define_method(method) do |*args, &block|
      @mutex.synchronize do
        reopen_logs if @reopen
        (@loggers + @old_loggers).each do |logger|
          if block
            logger.method(method).call(block.call)
          else
            logger.method(method).call(*args)
          end
        end
      end
    end
  end

  private

  def reopen_logs
    @loggers.map!(&:reopen)
    @reopen = false
  end
end
