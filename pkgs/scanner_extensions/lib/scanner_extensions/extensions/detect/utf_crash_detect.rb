module ScannerExtensions
  module Extensions
    class UtfCrashDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :fuzzer

        @defaults = {
          timeout: 15,
          sleep: 15
        }

        @poison    = '%C1%81'
        @errors    = [/(Warning:.+ Invalid multibyte sequence)/, /<b>Warning<\/b>: (.*)/, /<b>Fatal Error<\/b>: (.*)/, /<b>Notice<\/b>: (.*)/, /<\/b> on line <b>(.*)/]
      end

      def run(object, params)
        params = @defaults.merge(params)
        resp = object.http(value: @poison, timeout: params[:timeout], open_timeout: params[:open_timeout])

        return unless resp
        return unless resp.body

        body = resp.body.normalize_enconding

        @errors.each do |r|
          next unless r =~ body
          data = body.scan(r)
          data = data.flatten.join(' ... ')
          add_vuln(object, @poison, "...\n" + data + "\n...")
          return
        end
      end

      def add_vuln(object, value, data)
        curl = object.curl_helper(value: value, resp: data)
        object.vuln(
          extension: 'utf_crash_detect',
          template: '/info/exeption',
          binding: :protocol,
          args: {
            exploit_example: curl
          }
        )
      end
    end
  end
end
