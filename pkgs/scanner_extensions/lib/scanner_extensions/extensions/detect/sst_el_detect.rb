require 'cgi'

module ScannerExtensions
  module Extensions
    # TODO
    class SstElDetect < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce # Server Side template

        @defaults = {
          :timeout      => 15,
          :example_size => 100,
          :payloads     => {
            :el => ['wl${191*7}rm', 'wl%{191*7}rm'],
            :ssti => ['wl{{191*7}}rm']
          }
        }
      end

      def is_applicable?(object, params)
        true
      end

      def run(object, params)
        params   = @defaults.merge(params)
        resp = object.http(value: '', timeout: params[:timeout], open_timeout: params[:open_timeout])
        return if resp.nil?
        esize    = params[:example_size]
        for vuln_type, payloads in params[:payloads] do
          payloads.each do |payload|
            resp = object.http(value: payload, timeout: params[:timeout], open_timeout: params[:open_timeout])
            next if resp.nil?
            next if resp.body.nil?

            if resp.body.include? 'wl1337rm'
              body = resp.body.normalize_enconding
              curl = object.curl_helper(:value => payload, :resp => body)
              object.vuln(
                :template  => "/rce/#{vuln_type}",
                :binding   => :protocol,
                :args => {
                  :exploit_example => curl
                }
              )
              return
            end
          end
        end
      end
    end
  end
end
