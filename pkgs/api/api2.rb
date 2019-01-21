require 'hashie/mash'
require 'json'
require 'restclient'

class Wallarm
  class API2
    class Error < StandardError; end
    class AccessDenied < Error; end
    class BadRequest < Error; end
    class BadResponse < Error; end
    class ServerError < Error; end

    def initialize(args)
      @conf = Hashie::Mash.new(
        :host => 'api.wallarm.com',
        :port => 444,
        :use_ssl => true,
        :ca_file => '/usr/share/wallarm-common/ca.pem',
        :ca_verify => true,
        :open_timeout => 5,
        :read_timeout => 90)

      @conf.merge! args

      if @conf.uuid.nil? or @conf.secret.nil?
        raise ArgumentError, 'api uuid and secret required'
      end
    end

    def user
      return @user if @user

      resp = JSON.parse(post_json('/v1/user'))
      raise BadResponse, 'Bad json response' unless resp.is_a?(Hash) && resp['body'].is_a?(Hash)
      raise BadResponse, "Bad id (#{resp['body']['id']})" unless resp['body']['id'].is_a? Integer

      @user = resp['body']
    end

    def create_instance
      url = format('/v2/node/%d/instance', user['id'])
      resp = JSON.parse(post_json(url))
      raise BadResponse, 'Bad json response' unless resp.is_a?(Hash) && resp['body'].is_a?(Hash)

      [resp['body']['uuid'], resp['body']['secret']]
    end

    def heartbeat
      url = format('/v2/node/%d/instance/%d/action/heartbeat', user['cloud_node_id'], user['id'])

      resp = JSON.parse(post_json(url))
      raise BadResponse, 'Bad json response' unless resp.is_a?(Hash) && resp['body'].is_a?(Hash)

      true
    end

    def node_data(type, formats, current = nil)
      args = {}
      args[:type] = type
      args[:format] = formats
      args[:current] = current unless current.nil?

      resp = post_json('/v1/objects/node_data', args)
      if resp.code == 304
        nil
      else
        resp.force_encoding('ASCII-8BIT')
      end
    end

    def get(url, args={})
      params = {}

      if @conf['use_ssl'].nil? or @conf['use_ssl']
          params[:ssl_ca_file] = @conf['ca_file']
          params[:verify_ssl] = @conf['ca_verify']
          scheme = 'https'
      else
          scheme = 'http'
      end

      params[:url] = '%s://%s:%s%s' % [ scheme, @conf['host'], @conf['port'], url]
      params[:method] = :get
      params[:headers] = {}
      set_auth_params(params)

      params[:headers][:params] = args

      execute params
    end

    def post_json(url, args={})
      params = {}

      if @conf['use_ssl'].nil? or @conf['use_ssl']
          params[:ssl_ca_file] = @conf['ca_file']
          params[:verify_ssl] = @conf['ca_verify']
          scheme = 'https'
      else
          scheme = 'http'
      end

      params[:url] = '%s://%s:%s%s' % [ scheme, @conf['host'], @conf['port'], url]
      params[:method] = :post
      params[:headers] = { 'Content-Type' => 'application/json' }
      set_auth_params(params)

      params[:payload] = args.to_json

      execute params
    end

    private

    def execute(params)
      params[:open_timeout] = @conf[:open_timeout]
      params[:read_timeout] = @conf[:read_timeout]

      RestClient::Request.execute(params) do |resp|
        case resp.code
        when 200, 304
          resp
        when 403
          message = "Access denied for request #{resp.headers[:x_request_id]}"
          raise AccessDenied, message
        when 400..499
          message = "Bad request for request #{resp.headers[:x_request_id]}"
          raise BadRequest, message
        else
          message = "Response code #{resp.code} for request #{resp.headers[:x_request_id]}"
          raise ServerError, message
        end
      end
    rescue Error
      raise
    rescue => e
      raise ServerError, e.message
    end

    def set_auth_params(params)
        params[:headers]['X-WallarmAPI-UUID'] = @conf['uuid']
        params[:headers]['X-WallarmAPI-Secret'] = @conf['secret']
    end
  end
end
