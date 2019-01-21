class Processor
  attr_accessor :name

  def initialize(*args)
    @min_delay ||= 1
    @ttl ||= 90
    @name ||= self.class.name.gsub(/[^a-z]+/i,"_").downcase
  end

  def start
    if @thread and @thread.alive?
      @thread.terminate
      @thread.join
    end

    heartbeat

    @thread = Thread.new do
      Log.info("#{@name}: Thread started")
      until @stop
        time1 = Time.now.to_f
        process
        time2 = Time.now.to_f

        heartbeat

        process_time = time2 - time1

        if process_time < @min_delay
          sleep @min_delay - process_time
        end
      end
    end
  end

  def heartbeat
    @expire = Time.now.to_i + @ttl
  end

  def stop
    @stop = true
  end

  def stopped?
    @stop
  end

  def alive?
    @thread.alive?
  end

  def expired?
    @expire < Time.now.to_i
  end

  def bt
    @thread.join(1)
  rescue => e
    e
  end

  private

  def process
    raise StandardError, 'not implemented'
  end
end
