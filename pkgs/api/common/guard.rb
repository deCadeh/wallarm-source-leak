class Guard
  attr_accessor :logger

  def self.run(args={}, &blk)
    self.new(args, &blk).run!
  end

  def initialize(args={}, &blk)
    @guards = {}
    @threads = {}
    @logger = args[:logger] || Logger.new(nil)

    instance_eval &blk if block_given?
  end

  def add_guard(name, &blk)
    raise "Guard #{name} already exists" if @guards.key? name
    @guards[name] = blk
  end

  def set_logger(logger)
    @logger = logger
  end

  def run!
    loop do
      guards.each do |name, blk|
        thread = threads[name]

        if thread && !thread.alive?
          err = nil
          begin
            thread.join(0)
          rescue => e
            err = e
          end

          logger.warn "#{name} thread is dead: #{err}"
          thread = nil
        end

        if thread.nil?
          threads[name] = Thread.new{ blk.call }
        end
      end

      sleep 1
    end
  end

  private

  attr_reader :guards, :threads
end
