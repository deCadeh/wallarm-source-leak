# -*- encoding: utf-8 -*-

require_relative '../attack_format'

module VulnRechecker
  UnsupportedJobFormat = Class.new(RuntimeError)
  MissingJobParams     = Class.new(RuntimeError)
  InvalidJobFormat     = Class.new(RuntimeError)
  WapiError            = Class.new(RuntimeError)
end

class VulnRecheckJob
  def self.perform(job)
    App.logger.jid = job.jid
    App.logger.info "Start processing job #{job.jid}"

    unless job['vulnid']
      raise VulnRechecker::MissingJobParams, 'Missing vulnid'
    end

    clientid, data = App.wapi.get_vuln(job['vulnid'])
    unless data
      msg = "Cannot get vuln_recheck_data for vuln with id='#{job['vulnid']}'"
      raise VulnRechecker::WapiError, msg
    end
    job['vuln_recheck_data'] = data
    unless clientid
      msg = "Cannot get clientid for vuln with id='#{job['vulnid']}'"
      raise VulnRechecker::WapiError, msg
    end
    job['clientid'] = data

    hash = AttackFormat.load(job['vuln_recheck_data'])

    ['id', 'req', 'point', 'preserve_auth'].each do |key|
      job[key] = hash[key]
    end

    GeneralJob.perform(job, hash['detect_type'].to_sym, true)
  end
end

