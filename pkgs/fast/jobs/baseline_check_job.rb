# -*- encoding: utf-8 -*-

require 'base64'
require 'proton'
require 'proton/raw'
require 'proton/by_point'
require 'proton/ip_port'
require 'proton/refresh'

require './wrappers/scanner_object'
require './wrappers/rps_lock'
require './lib/proton2scanner'
require './lib/object_helpers'

require_relative './baseline_check_job/run_extensions'
require_relative './baseline_check_job/policies'
require_relative './baseline_check_job/entries'
require_relative './baseline_check_job/lock'
require_relative './baseline_check_job/vulns'

# Job for checking TestRuns
class BaselineCheckJob
  BaselineCheckError           = Class.new(RuntimeError)
  BaselineCheckErrorMissingReq = Class.new(BaselineCheckError)
  BaselineCheckTestRunIsGone   = Class.new(BaselineCheckError)

  extend RunExtensionsHelper
  extend PoliciesHelper
  extend RpsHelper
  extend Vulns

  def self.get_serialized_request(job)
    if job['req']
      msg = 'Retrieving the baseline request from job params'
      App.log(level: :info, msg: msg)
      Proton::SerializedRequest.new(Base64.decode64(job['req']))
    else
      msg = "Retrieving the baseline request Hit##{job['es_hit_id']}"
      App.log(level: :info, msg: msg)
      App.wapi.req_by_es_hit_id(job['es_hit_id'])
    end
  end

  def self.get_connection_params(objects, job)
    use_ssl = []
    objects.each do |object|
      object.params[:info][:baseline_check_id] = job['baseline_check_id']
      object.job = job
      use_ssl << ObjectHelpers.check_connection(object, true)
    end
    use_ssl
  end

  def self.handle_last_retry(job, exception)
    msg = 'Exceeded the number of allowed retries'
    App.log(level: :error, msg: msg)

    BaselineCheckAPI.run(id: job['baseline_check_id'])

    case exception
    when BaselineCheckErrorMissingReq
      msg = "Marking test set for baseline ##{job['baseline_check_id']} as incomplete due to missing request data"
      App.log(level: :error, msg: msg)

      BaselineCheckAPI.tech_fail(
        id: job['baseline_check_id'], reason: :missing_req
      )
    else
      msg = "Marking test set for baseline ##{job['baseline_check_id']} as incomplete due to exception"
      App.log(level: :error, msg: msg)

      BaselineCheckAPI.tech_fail(
        id: job['baseline_check_id'], reason: :exception
      )
    end
  end

  def self.perform(job)
    Thread.current[:baseline_check_id] = job['baseline_check_id']

    msg = "Running a test set for the baseline ##{job['baseline_check_id']}"
    App.log(level: :info, msg: msg)

    lock = job['fast'] ? get_local_rps_lock(job) : get_cloud_rps_lock(job)

    # job is retried due to rps lock
    return if lock == false

    run(job, lock)
  rescue ScannerExtensions::Helpers::FuzzerConditions::InvalidPolicies
    msg = 'Invalid value in a X-Wallarm-Test-Policy header, tests stopped'
    App.log(level: :error, msg: msg)

    BaselineCheckAPI.tech_fail(
      id: job['baseline_check_id'], reason: :invalid_policies
    )
    return
  rescue BaselineCheckTestRunIsGone => ex
    App.logger.info(ex.message)
  rescue => detail
    App.logger.error(detail)

    msg = "Internal exception detected, the test set for the baseline ##{job['baseline_check_id']} will be retried"
    App.log(level: :error, msg: msg)

    BaselineCheckAPI.retry(id: job['baseline_check_id'])

    raise detail
  ensure
    lock && lock.unlock
  end

  def self.run(job, lock)
    msg = "Test set for the baseline ##{job['baseline_check_id']} is running"
    App.log(level: :info, msg: msg)

    BaselineCheckAPI.run(id: job['baseline_check_id'])

    req = get_serialized_request(job)
    job.heartbeat

    unless req
      msg = 'Cannot retrieve the baseline request'
      App.log(level: :error, msg: msg)
      raise BaselineCheckErrorMissingReq
    end

    policies = parse_policies(req, job['test_run_id'])

    all_entries = []

    anomalies     = nil
    could_connect = false
    found_points  = false

    checks = []

    policies.each do |policy|
      # one entry could have many scan objects for different ip/port/use_ssl pairs
      # so entries is array of arrays of scan objects
      entries = get_entries(req, policy)

      entries.each { |entry| entry.each { |object| object.job = job } }

      job.heartbeat

      next if entries.empty?

      found_points = true

      msg = 'Establishing a connection with the target server'
      App.log(level: :info, msg: msg)

      # check connection with auditable server for random entry
      # all entries has same ip/port/use_ssl order so if we check connection
      # for one entry then we can use this info for other entries
      ssl_connection_params = get_connection_params(entries.sample, job)

      next if ssl_connection_params.flatten.empty?

      could_connect = true

      checks << [entries, ssl_connection_params, policy]
    end

    total_checks = 0
    checks.each do |entries, ssl_connection_params, policy|
      entries.each do |entry|
        entry.each_with_index do |object, i|
          (policy[:type_include] - policy[:type_exclude] + [:custom]).each do |detect_type|
            ObjectHelpers.get_extensions(
              detect_type,
              object.params[:point],
              :fast
            ).each do |ext|
              next if ext.respond_to?(:applicable?) && !ext.applicable?(object)

              use_ssl = ssl_connection_params[i]
              use_ssl.each do |ssl|
                total_checks += 1
              end
            end
          end
        end
      end
    end

    BaselineCheckAPI.set_total_checks_count(job['baseline_check_id'], total_checks)

    checks.each do |entries, ssl_connection_params, policy|
      cur_anomalies = run_extensions(entries, ssl_connection_params, policy, job, lock)

      if cur_anomalies
        anomalies ||= {}
        anomalies.merge!(cur_anomalies)
      end

      all_entries += entries.flatten
    end

    reason = nil
    unless could_connect
      if found_points
        msg = "Target application is unreachable. The test set for baseline ##{job['baseline_check_id']} is marked as failed"
        App.log(level: :error, msg: msg)
        reason = :connection_failed
        BaselineCheckAPI.tech_fail(id: job['baseline_check_id'], reason: reason)
      else
        msg = "Nothing to test based on Test Policy used. Check Insertion section in Test Policy 'test-policy-name' https://my.wallarm.com/link-to-test-policy"
        App.log(level: :info, msg: msg)
        reason = :nothing_to_check
        BaselineCheckAPI.passed(id: job['baseline_check_id'], reason: reason)
      end
      return
    end

    handle_result(job, all_entries, anomalies)
  end

  def self.handle_result(job, all_entries, anomalies)
    # for all oob dns detects
    sleep 1

    # process callbacks and handle vulns
    all_entries.each do |object|
      job.heartbeat

      object.vulns.clear

      begin
        object.oob_callbacks.each do |callback|
          callback.call
          job.heartbeat
        end
      rescue => detail
        App.logger.error(detail)
      end

      next if object.vulns.empty?

      sync_vulns_with_api(object, job)
    end

    finish_baseline_check(job, synced_vulns(job), anomalies)
  end

  def self.finish_baseline_check(job, vulns, anomalies)
    if vulns.empty?
      msg = "No issues found. Test set for baseline ##{job['baseline_check_id']} passed."
      App.log(level: :info, msg: msg)

      BaselineCheckAPI.passed(id: job['baseline_check_id'])
    else
      msg = "Found #{vulns.size} vulnerabilities, marking the test set for baseline ##{job['baseline_check_id']} as failed"
      App.log(level: :info, msg: msg)

      fail_opts = { id: job['baseline_check_id'], vulns: vulns.values }
      fail_opts[:anomalies] = anomalies if anomalies

      BaselineCheckAPI.failed(fail_opts)
    end
  end
end
