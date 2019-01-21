require 'base64'
require 'proton'
require 'proton/raw'
require 'proton/by_point'
require 'proton/proton_point'
require 'proton/ip_port'
require 'proton/refresh'
require 'securerandom'
require 'rps_limit'

require_relative './request_count'

require 'scanner_extensions'
require './wrappers/scanner_object'
require './wrappers/wapi_vuln'
require './wrappers/fast'

require 'json'

require_relative './exclude'
require_relative './str_decode'
require_relative './proton2scanner'
require_relative './object_helpers'

require_relative './custom_extensions'

Dir['./jobs/*.rb'].each { |f| require f }

class GeneralJob
  def self.skip_etcd_exceptions(&block)
    block.call
  rescue RpsLimit::EtcdError => ex
    App.logger.error(ex)
  end

  def self.get_rps_lock(job, object)
    return true unless App.config.rps_limit

    App.logger.info "Try to get RPS lock for #{object}"

    lock = RpsLimit.lock(clientid: job['clientid'], ip: object.params[:ip], domain: object.host)

    unless lock
      App.logger.info "Lock was not obtained for #{object}"
      return false
    end

    App.logger.info 'Lock was obtained'

    object.params[:locks] = [lock]
    object.params[:lock]  = lock

    return true
  rescue RpsLimit::EtcdError => ex
    App.logger.error(ex)
    return false
  end

  def self.retry_due_to_rps_lock(job, failed_rps_locks)
    data_key = 'job.exceptions.retries_history'

    job[data_key] ||= []

    job[data_key]  += [
      message: "(clientid: #{job['clientid']}) Unable to get rps locks for #{failed_rps_locks.join(',')}"
    ]

    job.cancel

    job.queue.put(
      job.klass_name,
      job.data,
      priority: job.priority,
      jid:      job.jid,
      delay:    RpsLimit::LOCK_KEEPALIVE_TIMEOUT * rand(2..10)
    )
  end

  def self.get_vuln_id_by_handled_vuln(handled_vuln, _vuln_recheck_flag)
    if handled_vuln['body']
      vuln = [handled_vuln['body']].flatten[0]
      vuln['id']
    else
      handled_vuln['id']
    end
  end

  def self.mark_tech_failed(job, msg)
    if job['attack_id']
      App.save_attack_status_queue.put(
        SaveVulnStatusJob,
        { event: 'tech_failed', attackid: job['attack_id'] }
      )
    end
    App.logger.info msg
  end

  def self.get_entry_methods(point, detect_type)
    entry_methods = [:normal]

    # Describe logic here if we want to send raw vectors for some points
    pure_get_post_point = point.to_a.flatten.select { |e| e.is_a?(Symbol) }.reject do |e|
      %i[get post form_urlencoded hash array].include? e
    end.empty?

    entry_methods = [:raw] + entry_methods if pure_get_post_point && detect_type == :sqli

    # Disable get_pollution for optimise request count
    # arr = point.to_a
    # if(detect_type == :xss && arr.size == 2 && arr[0] == :get && arr[1].is_a?(String))
    #   entry_methods = [:get_pollution] + entry_methods
    # end

    entry_methods
  end

  def self.perform(job, detect_type, vuln_recheck_flag = false)
    App.init
    App.logger.info "Start processing job #{job.jid}"
    App.logger.jid = job.jid

    update_attack_recheck_status = job['attack_id']

    req = job['id'].nil? ? raw_by_data(job['req']) : raw_by_id(job['id'])

    job.heartbeat

    unless req
      mark_tech_failed(job, "Can't get req for #{job.jid}")
      return
    end

    point = Proton::Point.new(job['point'].str_decode).from_all(req, detect_type)

    unless point
      mark_tech_failed(job, "Cannot get point for #{job.jid}")
      return
    end

    objects    = Proton2Scanner.get_objects_from(req, point, job['preserve_auth'])
    extensions = ObjectHelpers.get_extensions(detect_type, point)

    if objects.empty?
      mark_tech_failed(job, 'No objects to check')
      return
    end

    objects.each { |obj| obj.job = job }

    App.logger.info "clientid - #{job['clientid']}"
    App.logger.info "uri      - #{objects[0].params[:uri]}" unless objects.empty?
    App.logger.info "point    - #{point.point.inspect}"

    job.heartbeat

    found = false

    entry_methods = get_entry_methods(point, detect_type)

    run_at_least_once         = false
    should_retry_due_rps_lock = false
    failed_rps_locks          = []

    objects.each do |object|
      job.heartbeat

      processed = job['processed'] || []

      run_at_least_once = true unless processed.empty?

      # Skip already processed ip:port
      next if processed.include?(object.to_s)

      # Fill object info params to mark requests
      object.params[:info][:detect_type] = detect_type
      object.params[:info][:hit_id]      = job['id']
      object.params[:info][:point]       = job['point']

      use_ssl = ObjectHelpers.check_connection(object)

      job.heartbeat

      next if use_ssl.empty?

      unless get_rps_lock(job, object)
        failed_rps_locks << object.to_s
        should_retry_due_rps_lock = true
        next
      end

      run_at_least_once = true

      use_ssl.each do |ssl|
        object.params[:use_ssl] = ssl
        entry_methods.each do |entry_method|
          object.entry_method = entry_method
          extensions.each do |ext|
            # Fill object info params to mark requests
            object.params[:info][:extension] = ext.class.to_s

            job.heartbeat

            App.logger.info("Running em=#{entry_method} ssl=#{ssl} #{ext.class} for #{object}")

            object.job = job

            begin
              ext.run(object, open_timeout: 5)
            rescue StandardError => detail
              App.logger.error(detail)
            end

            next if object.vulns.empty?
            found        = true
            handled_vuln = handle_vuln(object, object.vulns[0], job, detect_type, vuln_recheck_flag, point)

            next unless update_attack_recheck_status
            vulnid = get_vuln_id_by_handled_vuln(handled_vuln, vuln_recheck_flag)
            App.save_attack_status_queue.put(
              SaveVulnStatusJob,
              { event: 'vuln_found', attackid: job['attack_id'], vulnid: vulnid }
            )
            break if found
          end
          break if found
        end
        break if found
      end
      break if found

      skip_etcd_exceptions { object.params[:lock].unlock } if App.config.rps_limit

      # Do not check already checked ip:port next time
      job['processed'] ||= []
      job['processed'] << object.to_s
      job.heartbeat
    end

    if should_retry_due_rps_lock
      App.logger.info 'Retry because not all ip:port were checked due to rps limit'
      retry_due_to_rps_lock(job, failed_rps_locks)
      return
    end

    unless run_at_least_once
      mark_tech_failed(job, 'Cannot perform connections to possibly vuln server')
      return
    end

    App.wapi.update_vuln_status(job['vulnid'], :closed) if vuln_recheck_flag && !found

    if update_attack_recheck_status && !found
      App.save_attack_status_queue.put(
        SaveVulnStatusJob,
        { event: 'vuln_not_found', attackid: job['attack_id'] }
      )
    end
  rescue StandardError => ex
    App.logger.error(ex)
    raise ex
  ensure
    App.logger.info 'Processing finished'
    App.logger.jid = nil
  end

  def self.handle_vuln(object, vuln, job, detect_type, vuln_recheck_flag, point)
    vuln_recheck_data = {
      id: job['id'],
      req: job['req'],
      point: point.to_a,
      preserve_auth: job['preserve_auth'],
      detect_type: detect_type
    }
    vuln_recheck = {
      vuln_recheck_type: 'attack',
      vuln_recheck_data: AttackFormat.dump(vuln_recheck_data)
    }

    if vuln_recheck_flag
      App.wapi.update_vuln_status(job['vulnid'], :open)
    else
      App.wapi.create_vuln(vuln, job['clientid'], object, vuln_recheck)
    end
  end

  def self.raw_by_id(id)
    App.wapi.req_by_es_hit_id(id)
  end

  def self.raw_by_data(data)
    Proton::SerializedRequest.new(Base64.decode64(data))
  end
end
