module RpsLimit
  # just generate etcd key names
  module EtcdKeyNames
    module_function

    def testrun_lock_key(testrun)
      format('/db/testrun_%<testrun>i/lock', testrun: testrun)
    end

    def domain_lock_key(clientid, domain)
      format(
        '/db/client_%<clientid>i/locks/domain/%<domain>s',
        clientid: clientid,
        domain:   escape_etcd(domain)
      )
    end

    def ip_lock_key(clientid, ip)
      format(
        '/db/client_%<clientid>i/locks/ip/%<ip>s',
        clientid: clientid,
        ip:       escape_etcd(ip)
      )
    end

    def default_rps_for_ip_key(clientid)
      format('/db/client_%<clientid>i/limits/default_rps_for_ip', clientid: clientid)
    end

    def default_rps_for_domain_key(clientid)
      format('/db/client_%<clientid>i/limits/default_rps_for_domain', clientid: clientid)
    end

    def rps_for_testrun_key(testrun)
      format('/db/testrun_%<testrun>i/limit', testrun: testrun)
    end

    def default_session_rps_for_testrun_key(testrun)
      format('/db/testrun_%<testrun>i/default_limit', testrun: testrun)
    end

    def rps_for_ip_key(clientid, ip)
      format(
        '/db/client_%<clientid>i/limits/ip/%<ip>s',
        clientid: clientid,
        ip:       escape_etcd(ip)
      )
    end

    def rps_for_domain_key(clientid, domain)
      format(
        '/db/client_%<clientid>i/limits/domain/%<domain>s',
        clientid: clientid,
        domain:   escape_etcd(domain)
      )
    end

    def rps_for_ip_per_domain_key(clientid, ip)
      format(
        '/db/client_%<clientid>i/limits/for_ip_per_domain/%<ip>s',
        clientid: clientid,
        ip:       escape_etcd(ip)
      )
    end

    def rps_for_domain_per_ip_key(clientid, domain)
      format(
        '/db/client_%<clientid>i/limits/for_domain_per_ip/%<domain>s',
        clientid: clientid,
        domain:   escape_etcd(domain)
      )
    end

    def escape_etcd(str)
      str.gsub(/[^\w\-\.]/, '#')
    end
  end
end
