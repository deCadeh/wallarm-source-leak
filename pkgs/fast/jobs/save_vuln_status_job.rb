# Job for save vuln status

# Job to ensure that attack-recheck status is saved
class SaveVulnStatusJob
  def self.perform(job)
    event = job['event'] || job[:event]
    case event
    when 'vuln_found'
      vuln_id = job['vulnid']
      vuln    = App.wapi.vuln_by_id(vuln_id)

      if vuln['status'] == 'falsepositive'
        App.wapi.vuln_not_found(job['attackid'])
      elsif vuln['validated'] && !vuln['hidden']
        App.wapi.vuln_found(job['attackid'], vuln_id)
      else
        opts = {
          data:    job.data,
          delay:   App.config['wait_validated_timeout'],
          retries: 0
        }

        job.requeue(job.queue, opts)
      end
    when 'vuln_not_found'
      App.wapi.vuln_not_found(job['attackid'])
    when 'tech_failed'
      App.wapi.tech_failed(job['attackid'])
    end
  end
end
