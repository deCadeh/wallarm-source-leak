require 'net/http/rest_client'
require 'json'

module ScannerExtensions
  module Helpers
    module OobDnsClient
      OobDnsUnavaliable = Class.new(RuntimeError)

      module_function

      def create
        res = App.wapi.request('/v1/oob_dns/token', {}, { raw: true, method: :post})['dns_name']
        raise OobDnsUnavaliable unless res
        res
      end

      def get(token)
        res = App.wapi.request('/v1/oob_dns/token/' + token, {}, { raw: true, method: :get})['history']
        raise OobDnsUnavaliable unless res
        res
      end
    end
  end
end

class OobDnsStub
  def create
    ScannerExtensions::Helpers::OobDnsClient.create
  end

  def get(token)
    ScannerExtensions::Helpers::OobDnsClient.get(token)
  end
end
