require 'timeout'
require 'net/http'
require 'erb'
require 'uri'
require 'openssl'

class OpenSSL::SSL::SSLSocket
  alias old_hostname= hostname=
  def hostname=(val)
    old_hostname = Thread.current[:http_sni_name] || val
  end
end

module ScannerExtensions
  module Helpers
    module Http
      module_function

      def request(params)
        params = {
          url_code: true
        }.merge(params)
        params[:open_timeout] ||= params[:timeout]
        Thread.current[:http_sni_name] = params[:vhost]
        begin
          result =
            if params[:timeout]
              Timeout.timeout(params[:timeout]) do
                execute(params)
              end
            else
              execute(params)
            end
          return result
        rescue Timeout::Error => detail
          return nil
        rescue => detail
          return nil
        end
      ensure
        Thread.current[:http_sni_name] = nil
      end

      def construct_cookies(cookies)
        res = []
        cookies.each do |key, value|
          res << if value
                   "#{key}=#{value}"
                 else
                   key.to_s
                 end
        end
        res.join(';')
      end

      def parse_cookies(data)
        result = {}
        data.each do |item|
          pair = item.split(';')[0]
          next unless pair
          data = pair.split('=')
          next if data.size > 2
          key   = data[0].strip
          value = data[1] && data[1].strip
          result[key] = value
        end
        result
      end

      private

      module_function

      def req_by_params(params)
        url, get_params = params.values_at(:url, :get_params)
        if get_params
          url += '?' unless url.index('?')
          get_params.each do |param, value|
            url += if params[:url_code]
                     "#{ERB::Util.url_encode(param)}=#{ERB::Util.url_encode(value.to_s)}&"
                   else
                     "#{param}=#{value}&"
                   end
          end
          url = url[0...-1]
        end
        req = params[:request_class].new(url)
        if params[:form_data]
          req.set_form_data(params[:form_data])
          params[:headers] ||= {}
          params[:headers]['Content-Type'] = 'application/x-www-form-urlencoded'
        end
        req['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko'
        req.body      = params[:body]   if params[:body]
        req['Host']   = params[:vhost]  if params[:vhost]
        req['Cookie'] = params[:cookie] if params[:cookie]
        if params[:headers]
          params[:headers].each do |key, value|
            req[key] = value
          end
        end
        req.basic_auth(params[:user], params[:password]) if params[:user]
        req
      end

      def execute(params)
        follow_redirect = params[:follow_redirect]
        read_timeout    = params[:timeout]         || 30
        open_timeout    = params[:open_timeout]    || 10

        resoponse = nil

        while follow_redirect != 0
          use_ssl = params[:use_ssl]
          host    = params[:host]
          port    = params[:port]

          req     = req_by_params(params)

          http_params  = {
             :use_ssl      => use_ssl,
             :open_timeout => open_timeout,
             :read_timeout => read_timeout
          }

          unless params[:check_ssl]
            http_params[:verify_mode] = OpenSSL::SSL::VERIFY_NONE
          end

          response = Net::HTTP.start(host, port, http_params) do |http|
            http.request(req)
          end

          # When we does not follow redirect
          return response unless follow_redirect

          follow_redirect -= 1

          if [301, 302, 307].include?(response.code.to_i)
            location = response['location']

            # Bad redirect
            return response unless location

            new_uri = URI.parse(location)
            if new_uri.relative?
              # TODO: check for attack-rechecker
              params[:url] = location
            else
              if new_uri.host != params[:vhost]
                # redirect to another host
                return response
              end
              split = (params[:url].index('?') || params[:url].size)
              params[:url]     = new_uri.path + params[:url][split..-1]
              params[:port]    = new_uri.port
              params[:use_ssl] = new_uri.scheme == 'https'
            end
          else
            return response
          end
        end
        response
      end
    end
  end
end
