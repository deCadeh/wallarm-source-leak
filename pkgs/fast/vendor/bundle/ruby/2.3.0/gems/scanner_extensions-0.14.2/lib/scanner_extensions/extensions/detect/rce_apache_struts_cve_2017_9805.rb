module ScannerExtensions
  module Extensions
    # extension for detect apache struts rce(CVE-2017-9805)
    class RceApacheStrutsCve20179805 < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce
        @point               = ->(p) { p.to_a == [:header, 'CONTENT-TYPE'] }

        @defaults = {
          timeout: 15,
          sleep: 10
        }
      end

      def oob_callback(object, token)
        array = ScannerExtensions::Helpers::OobDnsClient.get token
        unless array.empty?
          cmd = "ping -c 3 #{token} || ping -n 3 #{token}"
          payload = format(ScannerExtensions::Fixtures::PAYLOADS['cve-2017-9805'], cmd: cmd)
          curl = object.curl_helper(value: payload)
          object.vuln(
            extension: 'rce_apache_struts',
            template: '/rce/apache_struts',
            args: {
              exploit_example: curl,
              footers: {
                exploit_example: {
                  view: 'oob_dns',
                  splitter: "\n",
                  params: {
                    hosts: array
                  }
                }
              }
            }
          )
          return object
        end
        nil
      end

      def run(object, params)
        params = @defaults.merge(params)
        token = ScannerExtensions::Helpers::OobDnsClient.create
        cmd = "ping -c 3 #{token} || ping -n 3 #{token}"

        payload = format(ScannerExtensions::Fixtures::PAYLOADS['cve-2017-9805'], cmd: cmd)

        object.http(value: payload, timeout: params[:timeout], open_timeout: params[:open_timeout])
        if object.respond_to?(:oob_callbacks) && object.oob_callbacks
          object.oob_callbacks << proc do
            oob_callback(object, token)
          end
        else
          sleep params[:sleep]
          oob_callback(object, token)
        end
      end
    end
  end
end
