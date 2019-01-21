module ScannerExtensions
  module Extensions
    class SsiDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = [:ptrav, :redir]

        @defaults = {
          timeout: 15
        }

        @secret = 'k2m00subnccns7jw'
      end

      def run(object, params)
        params = @defaults.merge(params)

        [
          'http://wallarm.tools/ssi.php',
          'http://wallarm.tools/ssi',
        ].each do |url|
          resp = object.http(
            value:        url,
            timeout:      params[:timeout],
            open_timeout: params[:open_timeout]
          )
          next unless resp && resp.body

          # we found SSI if body contains secret
          next unless resp.body.index(@secret)
          # SSI was not processed
          next if resp.body.index('value="k2m00subnccns7jw"')

          curl = object.curl_helper(
            value: url,
            resp:  "...\n#{@secret}\n..."
          )

          object.vuln(
            extension: 'ssi_detect',
            template:  '/ssi',
            args: {
              exploit_example: curl
            }
          )

          return
        end
      end
    end
  end
end
