require_relative './string'

module ScannerExtensions
  module Helpers
    module StableCheck
      def self.check(object, params, reg = [], count = 2, value = '')
        count.times do
          resp = object.http(value: value, timeout: params[:timeout])
          return false if resp.nil?
          return false if resp.body.nil?
          return false if resp.code.to_i != 200
          body = resp.body.normalize_enconding
          reg.each do |r|
            return false if r =~ body
          end
        end
        true
      end
    end
  end
end
