require_relative './rps_limit/lock'
require_relative './rps_limit/connection_pool_wrapper'
require_relative './rps_limit/etcd_key_names'
require_relative './rps_limit/multi_lock'
require_relative './rps_limit/chains'

require 'securerandom'
require 'json'
require 'etcd'

##
# Library for limiting rps while scanning wallarm clients
#
# Usage:
#
#   RpsLimit.config = [
#     {
#       :host      => '127.0.0.1',
#       :port      =>  2379,
#       :user_name => 'test',
#       :password  => 'test'
#     },
#     {
#       :host      => '127.0.0.2',
#       :port      =>  2379,
#       :user_name => 'test',
#       :password  => 'test'
#     }
#   ]
#
#   # obtain lock
#   lock = RpsLimit.lock(clientid: 123, ip: '8.8.8.8', domain: 'vk.com')
#
#   # if lock was not obtained
#   unless lock
#     # ...
#   end
#
#   # get value of locked requests per second
#   rps = lock.rps
#
#   # keep lock alive
#   lock.heartbeat
#
#   # release lock
#   lock.unlock
#
#   # get & set testrun limits
#   limit  = RpsLimit.where(testrun: 31337).rps
#   RpsLimit.where(testrun: 31337).rps = limit
#   limit  = RpsLimit.where(testrun: 31337).default_session_rps
#   RpsLimit.where(testrun: 31337).default_session_rps = limit
#
#   # get & set default limits
#   limit  = RpsLimit.where(clientid: 31337).rps_per_domain
#   RpsLimit.where(clientid: 31337).rps_per_domain = limit
#   limit  = RpsLimit.where(clientid: 31337).rps_per_ip
#   RpsLimit.where(clientid: 31337).rps_per_ip = limit
#
#   # get & set & delete limits for ip/domian
#   limit = RpsLimit.where(clientid: 31337, domain: 'vk.com').rps
#   RpsLimit.where(clientid: 31337, domain: 'vk.com').rps = limit
#   # unset settings
#   RpsLimit.where(clientid: 31337, domain: 'vk.com').rps = nil
#
#   limit = RpsLimit.where(clientid: 31337, ip: '8.8.8.8').rps
#   RpsLimit.where(clientid: 31337, ip: '8.8.8.8').rps = limit
#   # unset settings
#   RpsLimit.where(clientid: 31337, ip: '8.8.8.8').rps = nil
#
#   # get & set & delete limits for domain per ip
#   limit = RpsLimit.where(clientid: 31337, domain: 'vk.com').rps_per_ip
#   RpsLimit.where(clientid: 31337, domain: 'vk.com').rps_per_ip = limit
#   # unset settings
#   RpsLimit.where(clientid: 31337, domain: 'vk.com').rps_per_ip = nil
#
# rubocop:disable Metrics/ModuleLength
module RpsLimit
  OptimisticLockError = Class.new(RuntimeError)
  MissingConfig       = Class.new(RuntimeError)
  EtcdError           = Class.new(RuntimeError)

  LOCK_KEEPALIVE_TIMEOUT    = 60 * 5

  DEFAULT_RPS_FOR_IP        = 30
  DEFAULT_RPS_FOR_DOMAIN    = 300

  MIN_RPS_POWER_PER_THREAD  = 5
  MAX_RPS_POWER_PER_THREAD  = 10
  MAX_ALLOWED_RPS           = 1000
  MAX_ALLOWED_TESTRUN_RPS   = 10_000
  EXPECTED_PARALLEL_THREADS = 3

  @config  = nil
  @etcd    = nil
  @retries = 3

  module_function

  attr_accessor :config, :retries

  def wrap_etcd_errors
    yield
  rescue => e
    raise EtcdError, e.to_s
  end

  def skip_errors
    yield
  rescue
    return false
  end

  def where(params)
    params[:testrun] ? Chains::TestRunQuery.new(params) : Chains::Query.new(params)
  end

  def related_obj_by(obj)
    { ip: :domain, domain: :ip }[obj]
  end

  def config=(conf)
    @config = conf
    connect_etcd
  end

  def optimistic_retry
    @retries.times do
      begin
        return yield
      rescue OptimisticLockError
        next
      end
    end
    false
  end

  def connect_etcd
    raise MissingConfig if @config.nil?

    @etcd = ConnectionWrapperPool.new(
      methods:           %i[get set delete],
      valid_exceptions:  [Etcd::TestFailed, Etcd::NodeExist, Etcd::KeyNotFound],
      retries:           @retries,
      connection_params: [@config].flatten
    ) do |params|
      Etcd.client(params)
    end
  end

  def etcd
    @etcd ||= connect_etcd
  end

  def check_testrun_rps!(rps)
    valid = rps.is_a?(Integer) && rps >= 1 && rps <= MAX_ALLOWED_TESTRUN_RPS
    raise ArgumentError, 'Invalid RPS' unless valid
  end

  def check_rps!(rps)
    valid = rps.is_a?(Integer) && rps >= 1 && rps <= MAX_ALLOWED_RPS
    raise ArgumentError, 'Invalid RPS' unless valid
  end

  def testrun_lock(params)
    rps_limit_for_obj   = RpsLimit.where(testrun: params[:testrun]).rps
    default_session_rps = RpsLimit.where(testrun: params[:testrun]).default_session_rps

    return default_session_rps ? SessionLock.new(default_session_rps) : nil unless rps_limit_for_obj

    default_session_rps ||= 30

    optimistic_retry do
      key = EtcdKeyNames.send('testrun_lock_key', params[:testrun])

      locks, additional = load_locks(key)
      total_locked_rps  = locks.values.inject(0) { |sum, lock| sum + lock.rps }

      limit  = rps_limit_for_obj
      locked = total_locked_rps

      rps_lock = rps_strategy(locked, limit, default_session_rps)

      # no avaliable rps
      return nil unless rps_lock

      lock = Lock.new(key: key, rps: rps_lock, testrun: params[:testrun])
      locks[lock.id] = lock
      save_locks(key, locks, additional)

      lock
    end
  end

  def lock(params)
    raise ArgumentError, 'Args should be a Hash' unless params.is_a? Hash

    return testrun_lock(params) if params[:testrun]

    clientid, ip, domain = params.values_at(:clientid, :ip, :domain)

    raise ArgumentError, 'Invalid clientid' unless clientid && clientid.is_a?(Integer)

    if ip && domain
      ip_lock = internal_get_lock(:ip, clientid, ip, domain)
      return nil unless ip_lock

      domain_lock = internal_get_lock(:domain, clientid, domain, ip)
      unless domain_lock
        ip_lock.unlock
        return nil
      end

      min_rps = [ip_lock.rps, domain_lock.rps].min

      res1 = ip_lock.update_rps(min_rps)
      res2 = domain_lock.update_rps(min_rps)

      unless res1 && res2
        skip_errors { ip_lock.unlock }
        skip_errors { domain_lock.unlock }
        return false
      end

      MultiLock.new(ip_lock, domain_lock)
    elsif ip
      internal_get_lock(:ip, clientid, ip, domain)
    elsif domain
      internal_get_lock(:domain, clientid, domain, ip)
    else
      raise ArgumentError, 'No ip or domain selected'
    end
  end

  def internal_get_lock(obj, clientid, item, related_item)
    optimistic_retry do
      key = EtcdKeyNames.send("#{obj}_lock_key", clientid, item)

      rps_limit_for_obj = RpsLimit.where(:clientid => clientid, obj => item).rps
      locks, additional = load_locks(key)
      total_locked_rps  = locks.values.inject(0) { |sum, lock| sum + lock.rps }

      limit  = rps_limit_for_obj
      locked = total_locked_rps

      if related_item
        related_locks = locks.values.select { |lock| lock.related_item == related_item }

        locked_rps_for_related_item = related_locks.inject(0) { |sum, lock| sum + lock.rps }

        rps_limit_per_related_item = RpsLimit.where(
          :clientid           => clientid,
          obj                 => item,
          related_obj_by(obj) => related_item
        ).send("rps_per_#{related_obj_by(obj)}")

        if limit - locked > rps_limit_per_related_item - locked_rps_for_related_item
          limit  = rps_limit_per_related_item
          locked = locked_rps_for_related_item
        end
      end

      rps_lock = rps_strategy(locked, limit)

      # no avaliable rps
      return nil unless rps_lock

      lock = Lock.new(key: key, rps: rps_lock, item: item, related_item: related_item)
      locks[lock.id] = lock
      save_locks(key, locks, additional)

      lock
    end
  end

  def rps_strategy(locked, limit, max = MAX_RPS_POWER_PER_THREAD)
    max    ||= MAX_RPS_POWER_PER_THREAD
    free_rps = limit - locked

    # no free rmp
    return nil if free_rps <= 0

    # we have got too many rps
    return max if free_rps > MAX_ALLOWED_RPS * EXPECTED_PARALLEL_THREADS

    # we have got too little rps
    return free_rps if free_rps < MIN_RPS_POWER_PER_THREAD

    rps = nil
    EXPECTED_PARALLEL_THREADS.downto(2).each do |parts|
      test_rps = free_rps / parts + 1
      if test_rps > MIN_RPS_POWER_PER_THREAD
        rps = test_rps
        break
      end
    end
    rps = free_rps unless rps

    rps > max ? max : rps
  end

  def load_locks(key)
    additional = {}
    locks      = {}
    begin
      data = etcd.get(key)
      JSON.parse(data.value).each do |id, lock|
        lock = Lock.new(lock)
        locks[id] = lock if lock.alive?
      end
      additional[:prevExist] = true
      additional[:prevIndex] = data.node.modified_index
    rescue Etcd::KeyNotFound
      additional[:prevExist] = false
    rescue => e
      # unexpected etcd error
      raise EtcdError, e.to_s
    end
    [locks, additional]
  end

  def save_locks(key, locks, additional)
    etcd.set(
      key,
      additional.merge(
        ttl:   4 * LOCK_KEEPALIVE_TIMEOUT,
        value: locks.to_json
      )
    )
  rescue Etcd::TestFailed, Etcd::NodeExist, Etcd::KeyNotFound => e
    # race condition let's try again
    raise OptimisticLockError, e.to_s
  rescue => e
    # unexpected etcd error
    raise EtcdError, e.to_s
  end

  def delete_locks(key, additional)
    etcd.delete(key, additional)
  rescue Etcd::TestFailed, Etcd::NodeExist, Etcd::KeyNotFound => e
    raise OptimisticLockError, e.to_s
  rescue => e
    # unexpected etcd error
    raise EtcdError, e.to_s
  end

  def ping_locks(key)
    locks, additional = RpsLimit.load_locks(key)
    RpsLimit.save_locks(key, locks, additional)
    true
  rescue RpsLimit::OptimisticLockError
    return false
  end
end
