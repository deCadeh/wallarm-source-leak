require 'vuln_templates'

module ScannerExtensions
  module Wrappers
    class Object
      attr_reader :vulns

      attr_accessor :fuzzer_policies
      attr_accessor :has_conditions
      attr_accessor :include_conditions
      attr_accessor :exclude_conditions
      attr_accessor :hardstop_conditions

      attr_accessor :oob_callbacks

      def initialize(hash = {})
        @hash  = hash
        @vulns = []
      end

      def point
        self[:point]
      end

      def [](key)
        key = format_key(key)
        @hash[key]
      end

      def []=(key, val)
        key = format_key(key)
        @hash[key] = val
      end

      def vuln(params)
        @vulns << params
      end

      def http(params)
        params = wrap_get_params(params)
        ScannerExtensions::Helpers::Http.request(params)
      end

      alias _http http

      def curl_helper(params)
        params = wrap_get_params(params)
        VulnTemplates::Helpers.curl(params)
      end

      private

      def wrap_get_params(params)
        params = @hash['http_params'].merge(params)
        pname, pval = params.values_at(:param_name, :value)
        if pname && pval
          params[:get_params]      ||= {}
          params[:get_params][pname] = pval
        end
        params.delete(:param_name)
        params.delete(:value)
        params[:method] =
          case params[:request_class].new('/')
          when Net::HTTP::Get
            :get
          when Net::HTTP::Post
            :post
          end
        params[:follow_redirect] = 5
        params
      end

      def format_key(key)
        key = key.to_s
        key = key[1..-1] if key[0] == ':'
        key
      end
    end
  end
end
