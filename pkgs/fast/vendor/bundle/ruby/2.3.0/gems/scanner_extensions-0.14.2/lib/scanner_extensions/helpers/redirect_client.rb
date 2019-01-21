require 'cgi'

module ScannerExtensions
  module Helpers
    module RedirectClient
      module_function

      def config
        @@conf ||= {
          'url' => 'http://wallarm.tools/redirect.php?url='
        }
      end

      def config=(conf)
        @@conf = conf
      end

      def get_redirect_to_url(url)
        config['url'] + CGI.escape(url)
      end
    end
  end
end
