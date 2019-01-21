require 'net/http/rest_client'
require 'json'

module ScannerExtensions
  module Helpers
    module OobDnsClient
      module_function

      def config
        @@conf ||= {
          'host' => 'api.wlrm.tl',
          'port' => '443'
        }
      end

      def config=(conf)
        @@conf = conf
      end

      def create
        JSON.parse(rest_client.post('/v1/token'))['dns_name']
      end

      def get(token)
        JSON.parse(rest_client.get('/v1/token/' + token))['history']
      end

      private

      module_function

      def rest_client
        Net::HTTP::RestClient.new host: config['host'], port: config['port'].to_i
      end
    end
  end
end
