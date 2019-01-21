require 'webrick'
require 'webrick/https'

module ScannerExtensions
  module Test
    class WebServer
      attr_reader :server

      def initialize(port, https = false, bind = '0.0.0.0')
        # crutch for WEBrick output while creating cert
        previous_stderr = $stderr
        $stderr = StringIO.new
        cert_name = [
          %w[CN localhost]
        ]
        @server =
          if https
            WEBrick::HTTPServer.new(
              Port: port,
              BindAddress: bind,
              Logger: WEBrick::Log.new('/dev/null'),
              AccessLog: [],
              SSLEnable: true,
              SSLCertName: cert_name
            )
          else
            WEBrick::HTTPServer.new(
              Port: port,
              BindAddress: bind,
              Logger: WEBrick::Log.new('/dev/null'),
              AccessLog: []
            )
          end
      rescue => detail
        puts detail
      ensure
        $stderr = previous_stderr
      end

      def mount(path, body, content_type = nil)
        @server.mount_proc path do |_req, res|
          res.body            = body
          res['Content-Type'] = content_type if content_type
        end
      end

      def start
        Thread.new { @server.start }
        sleep 0.05
      end

      def stop
        @server.shutdown
      end
    end
  end
end
