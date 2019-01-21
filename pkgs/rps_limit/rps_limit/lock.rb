require 'json'

module RpsLimit
  # just session lock without concurency
  class SessionLock
    attr_reader :rps

    def initialize(rps)
      @rps = rps
    end

    def rpm
      rps * 60
    end

    def heartbeat; end

    def alive?
      true
    end

    def unlock; end
  end

  # just normal lock
  class Lock
    PARAMS = %i[id key rps item related_item time].freeze

    attr_reader(*Lock::PARAMS)
    attr_writer :time, :rps

    def initialize(params)
      PARAMS.each { |param| instance_variable_set("@#{param}", params[param] || params[param.to_s]) }

      @id   ||= SecureRandom.uuid
      @time ||= Time.now.to_i
    end

    def rpm
      rps * 60
    end

    def heartbeat
      RpsLimit.optimistic_retry do
        locks, additional           = RpsLimit.load_locks(key)
        locks[id] && locks[id].time = Time.now.to_i
        save_locks(locks, additional)
        true
      end
    end

    def update_rps(rps)
      @rps = rps
      RpsLimit.optimistic_retry do
        locks, additional          = RpsLimit.load_locks(key)
        locks[id] && locks[id].rps = @rps
        save_locks(locks, additional)
        true
      end
    end

    def alive?
      time = @time || 0
      Time.now.to_i - time < RpsLimit::LOCK_KEEPALIVE_TIMEOUT
    end

    def to_h
      res = {}
      PARAMS.each { |param| res[param] = send(param) }
      res
    end

    def to_json(*a)
      to_h.to_json(*a)
    end

    def unlock
      RpsLimit.optimistic_retry do
        begin
          locks, additional = RpsLimit.load_locks(key)
          locks.delete(id)
          save_locks(locks, additional)
        rescue Etcd::KeyNotFound
          # already ulocked
          return true
        end
        true
      end
    end

    private

    def save_locks(locks, additional)
      if locks.empty?
        RpsLimit.delete_locks(key, additional)
      else
        RpsLimit.save_locks(key, locks, additional)
      end
    end
  end
end
