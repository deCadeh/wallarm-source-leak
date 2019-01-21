# -*- encoding: utf-8 -*-

require 'app'
require 'qless/worker'
require 'qless/job_reservers/ordered'

module QlessWorkerMaxMemReqLimit
  def around_perform( job)
    job.perform

    unless @options[:max_memory].nil?
      mem = memory_usage

      if mem and mem > @options[:max_memory]
        App.logger.info "Max memory usage reached (#{mem} > #{@options[:max_memory]})"
        @shutdown = true
      end
    end

    unless @options[:max_requests].nil?
      @processed ||= 0
      @processed  += 1

      if @processed >= @options[:max_requests]
        App.logger.info "Max requests count reached (#{@processed})"
        @shutdown = true
      end
    end
  end

  def memory_usage
    File.open( '/proc/self/status').each_line do |line|
      next unless line =~ /^VmRSS:/
      info = line.split

      case info[2].downcase
      when 'kb'
        return info[1].to_i * 1024
      when 'mb'
        return info[1].to_i * 2**20
      when 'gb'
        return info[1].to_i * 2**30
      else
        return info[1].to_i
      end
    end
  rescue => e
    App.logger.error "Can't detect memory usage (#{e})"
  end
end

class Worker < Qless::Workers::ForkingWorker
  def initialize
    queues  = [App.queue]
    queues += [App.save_attack_status_queue] if App.config.save_attack_status_redis

    reserver = Qless::JobReservers::Ordered.new(queues)

    super(
      reserver,
      :num_workers  => App.config.workers,
      :max_memory   => App.config.max_memory,
      :max_requests => App.config.max_requests
    )
    extend QlessWorkerMaxMemReqLimit
    extend Job::Exceptions
  end
end

