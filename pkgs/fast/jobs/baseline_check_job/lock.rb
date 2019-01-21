class BaselineCheckJob
  module RpsHelper
    def get_cloud_rps_lock(job)
      test_run_id = job['test_run_id']

      rps_defined =
        RpsLimit.where(testrun: test_run_id).default_session_rps ||
        RpsLimit.where(testrun: test_run_id).rps

      return nil unless rps_defined

      lock = RpsLimit.lock(testrun: test_run_id)

      unless lock
        msg = 'Failed to get RPS lock, retry job later'
        App.log(level: :error, msg: msg)

        job.cancel

        job.queue.put(
          job.klass_name,
          job.data,
          priority: job.priority,
          jid:      job.jid,
          delay:    RpsLimit::LOCK_KEEPALIVE_TIMEOUT * rand(2..10)
        )

        return false
      end

      msg = "Got #{lock.rps} RPS lock"
      App.log(level: :info, msg: msg)

      lock
    end

    def get_local_rps_lock(job)
      lock = RpsLock.lock(job['test_run_id'])
      return nil if lock.nil?
      msg = "Got #{lock.rps} RPS lock"
      App.log(level: :info, msg: msg)
      lock
    rescue Wallarm::API::AlreadyLocked
      msg = 'Failed to get RPS lock, retry job later'
      App.log(level: :error, msg: msg)
      BaselineCheckAPI.silent_retry(id: job['baseline_check_id'])
      return false
    end
  end
end
