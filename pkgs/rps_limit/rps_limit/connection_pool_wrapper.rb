# Make pool from single connection class
class ConnectionWrapperPool
  REPAIR_DOWN_SERVER_CHANCE = 10

  attr_reader :good_servers
  attr_reader :down_servers

  def initialize(opts)
    @retries      = opts[:retries] || 1
    @good_servers = Queue.new
    @down_servers = Queue.new

    @valid_exceptions = opts[:valid_exceptions] || []

    @unshuffled = []
    @shuffled   = false
    @mutex      = Mutex.new

    opts[:connection_params].each do |params|
      @unshuffled << yield(params)
    end

    (opts[:methods] || []).each do |method|
      self.class.send(:define_method, method) do |*args, &block|
        proxy_call(method, *args, &block)
      end
    end
  end

  # rubocop:disable Style/MethodMissing
  def method_missing(name, *args, &block)
    proxy_call(name, *args, &block)
  end

  private

  def shuffle
    return if @shuffled
    @mutex.synchronize do
      return if @shuffled

      @unshuffled.shuffle.each { |con| @good_servers << con }

      @shuffled = true
    end
  end

  def proxy_call(method, *args, &block)
    last_ex = nil

    @retries.times do
      begin
        connection do |con|
          return con.method(method).call(*args, &block)
        end
      rescue => ex
        last_ex = ex
        raise ex if @valid_exceptions.include?(ex.class)
      end
    end

    raise last_ex
  end

  def repair?
    !@down_servers.empty? && lucky?
  end

  def lucky?
    rand(REPAIR_DOWN_SERVER_CHANCE).zero?
  end

  def connection
    shuffle

    server = nil

    until server
      begin
        Timeout.timeout(0.1) do
          server = if @good_servers.empty? || repair?
                     @down_servers.pop
                   else
                     @good_servers.pop
                   end
        end
      rescue
        next
      end
    end

    yield(server)
  rescue => ex
    unless @valid_exceptions.include?(ex.class)
      @down_servers << server
      server = nil
    end
    raise ex
  ensure
    server && @good_servers << server
  end
end
