require 'cgi'

module ScannerExtensions
  module Extensions
    class XssDetect < BaseExtension; end

    class FastXssDetect < XssDetect
      def initialize
        super
        @components = :fast
        @payloads   = [%q('"\'\" wlrm=1 </title></textarea></style></scRipt/--!><wlrm>)]
        @defaults[:payloads] = @payloads
      end
    end

    class XssDetect < BaseExtension
      def initialize
        require 'rkelly'

        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :xss
        @components          = :rechecker

        @payloads = [
          '<wlrm>', '><wlrm>', "'wlrm=1><wlrm>", '"wlrm=1><wlrm>', 'wlrm', '<h1 wlrm=x>',
          '%3Cwlrm%3E',
          "'\";\n/**/;wlrm=1;/*",
          "';\n/**/;wlrm=1;//",
          "\n/**/;wlrm=1;/*",
          "\n/**/;wlrm=1;//",
          %q(1 '"\'\" wlrm=1 </title></textarea></style></scRipt/--!><wlrm>)
        ]

        @defaults = {
          timeout: 15,
          example_size: 100,
          payloads: @payloads
        }
      end

      def run(object, params)
        params = @defaults.merge(params)
        esize  = params[:example_size]
        for payload in params[:payloads] do
          resp = object.http(
            value:        payload,
            timeout:      params[:timeout],
            open_timeout: params[:open_timeout]
          )
          next if resp.nil?
          next if resp.body.nil?
          next unless resp['Content-Type']
          # TODO: Add more XSS compatible content types
          next if resp['Content-Type'] !~ %r{text/html}
          doc = ScannerExtensions::Helpers::Gumbo.parse(resp.body)
          pattern = nil

          scripts   = doc.find_scripts
          js_parser = RKelly::Parser.new

          scripts.each do |script|
            ast = nil
            begin
              ast = js_parser.parse(script)
              if ast && !ast.select do |i|
                i.respond_to?(:value) && i.value.class == String && i.value == 'wlrm'
              end.empty?
                pattern = 'wlrm'
              end
            rescue RKelly::SyntaxError => ex
            rescue => ex
            end
          end

          index = nil
          unless pattern
            xss, index = doc.xss?
            pattern = 'wlrm' if doc.find_hrefs.include?('wlrm') || xss
          end

          next unless pattern
          body = resp.body.normalize_enconding
          data = if index
                   body[[index - esize / 2, 0].max, esize]
                 elsif (i = body.index(pattern))
                   body[[i - esize / 2, 0].max, esize]
                 else
                   body[0, esize] + "\n..."
                 end
          curl = object.curl_helper(value: payload, resp: data)
          object.vuln(
            extension: 'xss_detect',
            template: '/xss/general',
            binding: :protocol,
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
