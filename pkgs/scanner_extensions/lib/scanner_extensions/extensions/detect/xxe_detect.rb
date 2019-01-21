require 'uri'

module ScannerExtensions
  module Extensions
    class XxeDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :xxe

        @defaults = {
          timeout: 15,
          sleep: 10,
          utf16: true
        }
      end

      def oob_callback(object, tokens)
        tokens.each do |token, template|
          array = ScannerExtensions::Helpers::OobDnsClient.get token
          next if array.empty?
          curl = object.curl_helper(value: template)
          object.vuln(
            extension: 'xxe_detect',
            template: 'xxe',
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

        ScannerExtensions::Helpers::XmlTemplates.each do |t|
          token    = ScannerExtensions::Helpers::OobDnsClient.create
          template = ScannerExtensions::Helpers::XmlTemplates.fill(t, token)
          tokens << [token, template]
          check(template, object, params, token)

          next unless params[:utf16]
          token    = ScannerExtensions::Helpers::OobDnsClient.create
          template = ScannerExtensions::Helpers::XmlTemplates.fill16(t, token)
          tokens << [token, template]
          check(template, object, params, token)
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

      def check(template, object, params, _token)
        object.http(value: template, timeout: params[:timeout], open_timeout: params[:open_timeout])
      end
    end
  end
end
