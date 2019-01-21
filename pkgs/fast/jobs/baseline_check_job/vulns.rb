class BaselineCheckJob
  module Vulns
    def sync_vulns_with_api(scanning_object, job)
      scanning_object.vulns.each do |vuln|
        created = App.wapi.create_vuln_for_baseline(vuln, job['clientid'], scanning_object, job['test_run_id'])

        formatted_vuln = {
          'id'     => created['id'],
          'threat' => created['threat'],
          'code'   => created['wid'],
          'type'   => created['type']
        }

        vuln_was_synced(formatted_vuln, job)

        job.heartbeat

        BaselineCheckAPI.add_vuln(id: job['baseline_check_id'], vulns: [formatted_vuln])

        msg = "#{created['type'].upcase} vulnerability found at host #{created['domain']} https://my.wallarm.com/vulnerabilities/#{created['id']}"

        App.log(level: :info, msg: msg)

        job.heartbeat
      end

      scanning_object.vulns.clear
    end

    def vuln_was_synced(vuln, job)
      job['vulns'] = synced_vulns(job).merge(vuln['id'] => vuln)
    end

    # if job fails we will keep already created vulns and retry job
    def synced_vulns(job)
      job['vulns'] || {}
    end
  end
end
