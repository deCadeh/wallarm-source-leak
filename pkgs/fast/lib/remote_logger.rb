class RemoteLogger
  def initialize
    @queue = Queue.new
  end

  def run!
    raise RuntimeError.new('Worker already running') if running?

    @worker = Thread.new { Thread.handle_interrupt(RuntimeError => :on_blocking) { main_loop } }
  end

  def stop!
    @worker.raise
  end

  def running?
    @worker && @worker.alive?
  end

  def write params
    raise ArgumentError.new('Logger argument should be a Hash') unless params.is_a? Hash

    @queue.push params
  end

  def main_loop
    loop do
      record = @queue.pop

      loop do
        failed = false

        begin
          BaselineCheckAPI.create_record record
        rescue
          failed = true
        end

        break unless failed

        sleep App.config.remote_logger.retry_timeout
      end if record

      break if Thread.pending_interrupt?
    end
  end
end
