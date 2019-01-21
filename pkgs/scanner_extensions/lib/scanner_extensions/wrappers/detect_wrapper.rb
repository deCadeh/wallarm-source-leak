module ScannerExtensions
  module Wrappers
    class DetectWrapper
      def initialize(object, additional = {})
        @additional = additional
        @object     = object
      end

      def wrap_params(params)
        params
      end

      def http(params)
        @object.http(wrap_params(params))
      end

      def curl_helper(params)
        API::UrlDesc.get(@object, wrap_params(params))
      end

      def vuln(args)
        @object.vuln(args.deep_merge(@additional))
      end

      def method_missing(name, *args, &block)
        @object.method(name).call(*args, &block)
      end
    end
  end
end
