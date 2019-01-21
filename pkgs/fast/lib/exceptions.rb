# -*- encoding: utf-8 -*-

# Job::Exceptions.RULES examples:
#   [/Testing:Exception1/, {action: :skip}] - silent skip exception
#   [/Testing:Exception2/, {action: :retry, tries: 4, timeout: 1.seconds}] - retry 4 times
#   [/Testing:Exception3/, {action: :raise}] - raise to worker

module Job
  module Exceptions
    RetriableException = Class.new(RuntimeError)

    def handling_rules
      unless @handling_rules
        rules = App.config.exceptions
        @handling_rules = if rules.kind_of? Array # legacy case
          rules
        else
          Hash[rules.map { |rule, action| [Regexp.new(rule), action] }]
        end
      end
      @handling_rules
    end

    def around_perform(job)
      exception = nil
      result    = nil
      begin
        result = super
      rescue => exception
      end
      return result unless exception
      return handle_exception(job, result, exception)
    end

    def handle_exception(job, result, exception)
      marker = "#{job.klass_name}:#{exception.class}"
      App.logger.warn "Handle exception: '#{marker}'"
      handling_rules.each do |regexp, action|
        if marker =~ regexp
          method = "do_#{action[:action]}".to_sym

          do_response = send(method, job, exception, action)

          if do_response.is_a?(Exception)
            App.logger.error("#{do_response.inspect}\n#{do_response.backtrace.join("\n")}")
            raise do_response
          elsif do_response === true
            return result
          elsif do_response === false
            break
          else
            fail('Something wrong')
          end
        end
      end

      App.logger.error("#{exception.inspect}\n#{exception.backtrace.join("\n")}")
      raise exception
    end

    def do_retry(job, exception, action)
      retries_left =
        if job.data.key?('job.exceptions.retries_left')
          job.data['job.exceptions.retries_left'] - 1
        else
          action[:tries] - 1
        end

      retries_time_total = job.data['job.exceptions.retries_time_total'] || 0
      retries_history    = job.data['job.exceptions.retries_history']    || []

      job_klass = Kernel.const_get(job.klass_name.to_sym) rescue nil

      if retries_left <= 0
        ##
        # If we will need this later
        #
        #   if action[:final] == :skip
        #     App.logger.info 'Skip last exception'
        #     job.cancel
        #     return true
        #   end

        if job_klass && job_klass.respond_to?(:handle_last_retry)
          job_klass.handle_last_retry(job, exception)
          job.cancel
          return true
        end

        job.data.delete('job.exceptions.retries_left')
        job.heartbeat

        formatted_history = retries_history.map do |h|
          "%s: %s [Retries left: %s]\n%s\n\n" % [
            h['class'],
            h['message'],
            h['retries_left'],
            (h['backtrace'] || []).join("\n")
          ]
        end.join("\n")

        begin
          raise exception.class.new(), exception.message + "\nHistory:\n#{formatted_history}"
        rescue => new_exception
          new_exception.set_backtrace(exception.backtrace)
          return new_exception
        end
      else
        retry_job(job, exception, action[:timeout], retries_left, retries_time_total, retries_history)
        return true
      end
    end

    def retry_job(job, exception, timeout, retries_left, retries_time_total, retries_history)
      history = retries_history + [
        {
          class:        exception.class.to_s,
          message:      exception.message,
          backtrace:    exception.backtrace,
          retries_left: retries_left
        }
      ]

      data = job.data.merge(
        'job.exceptions.retries_left'       => retries_left,
        'job.exceptions.retries_time_total' => retries_time_total + timeout,
        'job.exceptions.retries_history'    => history
      )

      opts = {
        data:    data,
        delay:   timeout,
        retries: 0
      }

      job.requeue(job.queue, opts)
    end

    def do_skip(job, exception, action)
      true
    end

    def do_raise(job, exception, action)
      false
    end
  end
end
