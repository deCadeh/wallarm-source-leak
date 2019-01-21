require 'timeout'
require 'net/http'

module Net
  class HTTP
    # Pure ruby http rest client class
    class RestClient
      VERSION = '0.1.0'

      # Get class verion
      def self.version
        VERSION
      end

      # Main longstanding params (the same params as params at #initialize)
      attr_reader :params
      # Main longstanding cookies
      attr_reader :cookies
      # Main longstanding headers
      attr_reader :headers
      # Returns last Net::HTTP::Response
      attr_reader :response

      ##
      # To create class just pass params to constructor
      #    Net::HTTP::RestClient.new :host => '127.0.0.1', :port => 8080
      def initialize params = {}
        defaults = {
          :port       => 80,
          :user_agent => 'Net::HTTP::RestClient'
        }
        if params[:port]==443 && !params[:ssl]
          defaults.merge! :ssl => {
            :use_ssl     => true,
            :verify_mode => OpenSSL::SSL::VERIFY_NONE
          } 
        end
        @params  = defaults.merge(params)
        @cookies = {}
        @headers = {}
        @params[:headers] && @headers=@params[:headers]
        @params[:cookies] && @cookies=@params[:cookies]
      end

      def clear_cookies
        @cookies = {}
      end

      def clear_headers
        @headers = {}
      end

      def get url, params = {}
        params[:url] = url
        request Net::HTTP::Get, params
      end

      def post url, data=nil, params = {}
        params[:url]  = url
        params[:body] = data
        request Net::HTTP::Post, params
      end

      def put url, data=nil, params = {}
        params[:url]  = url
        params[:body] = data
        request Net::HTTP::Put, params
      end

      def delete url, params = {}
        params[:url] = url
        request Net::HTTP::Delete, params
      end

      def head url, params = {}
        params[:url] = url
        request Net::HTTP::Head, params
      end

      private

      def request method, params
        params = { :headers => {}, :cookies => {} }.merge(params)
        params = @params.merge(params)
        req = method.new(params[:url])
        req['User-Agent'] = params[:user_agent]
        params[:body] && req.body = params[:body]
        params[:virtual_host] && req['Host'] = params[:virtual_host]
        params[:user] && req.basic_auth(params[:user], params[:password])
        cookies = []
        @cookies.merge(params[:cookies]).each do |key, value|
          if value
            cookies << "#{key}=#{value}"
          else
            cookies << "#{key}"
          end
        end
        cookies.size>0 && req['Cookie'] = cookies.join(';')        
        @headers.merge(params[:headers]).each do |key, value|
          req[key] = value
        end
        response = nil
        if params[:timeout]
          Timeout::timeout(params[:timeout]) do
            response = execute req, params
          end
        else
          response = execute req, params
        end
        @response = response
        return nil unless response
        if response['Set-Cookie'] && response['Set-Cookie'].size>0
          parse_cookies response          
        end        
        return response.body
      end

      def parse_cookies response
        response['Set-Cookie'].split(';').each do |pair|
          data = pair.split('=')
          raise 'Invalid cookie format' if data.size>2
          key   = data[0].strip
          value = data[1] && data[1].strip
          @cookies[key] = value
        end
      end

      def execute req, params
        Net::HTTP.start(
          params[:host],
          params[:port],
          params[:ssl]
        ) do |http|
          http.request(req)
        end
      end
    end
  end
end
