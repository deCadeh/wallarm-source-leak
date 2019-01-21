require 'securerandom'

class FastFakeJob < Hash
  def initialize(hash={})
    self.merge! hash
  end

  def heartbeat
    msg = "TestRun##{self['test_run_id']} is gone away"
    exception = BaselineCheckJob::BaselineCheckTestRunIsGone.new(msg)
    raise exception unless self['fast'].test_run_ids.include? self['test_run_id']
  end
end

class Fast
  attr_reader :test_run_ids

  def initialize(opts = {})
    @marker       = nil
    @mutex        = Mutex.new
    @queue        = Queue.new
    @opts         = { workers: 10, retry_timeout: 60 }.merge(opts)
    @test_run_ids = []
    @inwork_size  = 0
  end

  def run
    @opts[:workers].times { Thread.new { loop { process_task } } }

    loop { get_tasks }
  end

  private

  QUANT = 5

  def tasks_size
    @mutex.synchronize { @queue.size + @inwork_size }
  end

  def process_task
    task = @queue.pop

    @mutex.synchronize { @inwork_size += 1 }

    job = FastFakeJob.new(
      'clientid'          => FastAPI.clientid,
      'es_hit_id'         => task['es_hit_id'],
      'baseline_check_id' => task['id'],
      'test_run_id'       => task['test_run_id'],
      'fast'              => self
    )
    BaselineCheckJob.perform(job)
  rescue => ex
    BaselineCheckJob.handle_last_retry(job, ex) if task['retries'] >= 3
  ensure
    @mutex.synchronize { @inwork_size -= 1 }
  end

  def get_tasks
    sleep QUANT

    App.watch_node_yaml

    test_runs = nil

    begin
      test_runs = FastAPI.test_runs
    rescue => ex
      App.logger.error(ex)
      @test_run_ids = []
      return
    end

    @test_run_ids = test_runs.select { |tr| tr['node_active'] }.map { |tr| tr['id'] }

    if @test_run_ids.empty?
      test_runs = FastAPI.test_runs(:cloud)

      set_marker(test_runs[0], 'Recording baselines for') if test_runs.size == 1
      return
    elsif @test_run_ids.size ==1
      set_marker(test_runs[0], 'Recording baselines for')
    end

    size = @opts[:workers] - tasks_size
    return if size <= 0

    test_runs.each do |test_run|
      baseline_checks = FastAPI.baseline_checks(test_run['id'], size, @opts[:retry_timeout])
      baseline_checks.each do |baseline_check|
        next unless FastAPI.lock_baseline_check(baseline_check['id'])
        @queue << baseline_check
        size -= 1
        App.logger.info "Lock baseline_check##{baseline_check['id']}"
        return if size <= 0
      end
    end
  rescue => ex
    App.logger.error(ex)
  end

  def set_marker(test_run, msg)
    marker        = test_run['marker_secret']
    test_run_id   = test_run['id']
    test_run_name = test_run['name']

    return if @marker == marker
    @marker = marker
    App.logger.info "#{msg} TestRun##{test_run_id} '#{test_run_name}'"
    `set_marker #{@marker}`
  end
end
