module RpsLimit
  # union several locks
  class MultiLock
    attr_reader :locks

    def initialize(lock1, lock2)
      @locks = [lock1, lock2]
    end

    def heartbeat
      @locks.map(&:heartbeat)
    end

    def unlock
      @locks.map(&:unlock)
    end

    def rps
      @locks.sample.rps
    end

    def rpm
      rps * 60
    end
  end
end
