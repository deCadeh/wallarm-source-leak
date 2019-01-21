# vim: foldlevel=2

require 'wallarm/api/version'
require 'wallarm/api/errors'
require 'thread/pool'
require 'net/https'
require 'json'
require 'msgpack'
 
class Wallarm
  class API
    DEFAULTS = {
      :host       => 'api.wallarm.com',
      :port       => 444,
      :use_ssl    => true,
      :ca_file    => '/usr/share/wallarm-common/ca.pem',
      :ca_verify  => true
    }.freeze

    # Wallarm::APIClient.new( hash)
    #
    #   :username, :password - for access with user account privileges
    #   :uuid, :secret - for access with node privileges
    #
    #   :host - wallarm api host (default: api.wallarm.com)
    #   :port - wallarm api port (default: 443)
    #   :use_ssl - use ssl for access api or not (default: true)
    #   :ca_file - path to file with CA for validate API server.
    #   :ca_verify - validate or not API server by CA
    #
    def initialize( args = {})
      args.merge!( DEFAULTS) { |key,value,default| value.nil? ? default : value }

      @host      = args[:host]
      @port      = args[:port]
      @use_ssl   = args[:use_ssl]
      @ca_file   = args[:ca_file]
      @ca_verify = args[:ca_verify]
      @open_timeout = args[:open_timeout] || 10
      @read_timeout = args[:read_timeout] || 60

      @headers = { 'User-Agent' => "ruby wallarm/api (#{Wallarm::API::VERSION})" }
      @http    = Array.new
      @pool    = Thread.pool( args[:pool_size] || 1)

      if args.has_key? :username
        login( args[:username], args[:password])
      elsif args.has_key? :uuid
        @headers["X-WallarmAPI-Node"] = args[:uuid]
        @headers["X-WallarmAPI-Secret"] = args[:secret]
      else
        raise RuntimeError, "no one of username or uuid specified"
      end
    end

    # Make blocking request
    def get( method, data, opts={})
      opts.merge!( {:format=>:msgpack}) { |k,o,n| o }
      _request( :get, method, data, opts)
    end

    def post( method, data, opts={})
      opts.merge!( {:format=>:msgpack}) { |k,o,n| o }
      _request( :post, method, data, opts)
    end

    def request( method, data, opts={})
      opts.merge!( {:format=>:msgpack}) { |k,o,n| o }
      _request( :post, method, data, opts)
    end

    # Make async request. Returns instance of Thread::Pool::Task
    def arequest( method, data, opts={}, userdata=nil)
      opts.merge!( {:format=>:msgpack}) { |k,o,n| o }

      @pool.process do
        resp = _request( :post, method, data, opts)
        userdata.nil? ? resp : [ resp, userdata ]
      end
    end

    def user
      @user ||= request( '/v1/user', {})['body']
    end

    def clientid
      @clientid ||= user['clientid']
    end

    def node_data(type, formats, current = nil)
      args = {}
      args[:type] = type
      args[:format] = formats
      args[:current] = current unless current.nil?

      request('/v1/objects/node_data', args)
    rescue NotModified
    end

    private

    def with_conn
      http = @http.shift || new_conn
      yield http
      @http << http
    end

    def new_conn
      http = Net::HTTP.new( @host, @port)
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      http.use_ssl = @use_ssl
      http.ca_file = @ca_file
      http.verify_mode = @ca_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http
    end

    def login( username, password)
      with_conn do |http|
        headers = @headers.merge( 'Content-Type' => 'application/msgpack')
        data    = { :username => username, :password => password }

        http.request_post( '/v1/login', data.to_msgpack, headers) do |response|
          data = parse_response( response)

          begin
            status = data["status"]
            token = data["body"]["token"]
          rescue
            raise ServerError.new( "Server reply by bad json data", response)
          end

          raise LoginFailed, data["body"] if status != 200

          @token = token
          @headers["cookie"] = response.get_fields('set-cookie').map{ |c| c.gsub( /; .*/, '') }.join '; '
        end
      end
    end

    def _request( http_method, api_method, data, opts)
      unless data.is_a? Hash
        raise TypeError, "data must be Hash, not #{data.class}"
      end

      data = data.clone
      data[:token] = @token if @token

      opts[:format] = :form if http_method == :get

      case opts[:format]
      when :json
        data = data.to_json
        headers = @headers.merge( 'Content-Type' => 'application/json')
      when :msgpack
        data = data.to_msgpack
        headers = @headers.merge( 'Content-Type' => 'application/msgpack')
      when :form
        r = Net::HTTP::Get.new('/')
        r.set_form_data( data)
        data = r.body
      else
        raise TypeError, "Format option can be :json or :msgpack"
      end


      response = nil

      with_conn do |http|
        case http_method
        when :get
          uri = "%s?%s" % [api_method, data]
          response = http.request_get( uri, @headers)
        when :post
          response = http.request_post( api_method, data, headers )
        else
          raise "#{http_method.to_s.upcase} requests not supported"
        end
      end

      data = parse_response( response)

      case response.code
      when "200"
        # all ok
      when "304"
        raise NotModified
      when "403"
        raise AccessDenied
      when "400"
        if data.is_a? Hash
          raise AlreadyExists if data["body"] == "Already exists"
          raise AccessDenied if data["body"] == "denied"
          raise BadRequest.new( data["body"], response)
        else
          raise BadRequest.new( data, response)
        end
      else
        if data.is_a? Hash
          raise ServerError.new( data["body"], response)
        else
          raise ServerError.new( data, response)
        end
      end

      data
    end

    def parse_response( response)
      case response.content_type.to_s.gsub( /;.*/, '')
      when 'application/json'
        begin
          JSON.parse response.body
        rescue
          raise ServerError.new( "Server reply by bad json data", response)
        end
      when 'application/msgpack'
        begin
          MessagePack.unpack response.body
        rescue
          raise ServerError.new( "Server reply by bad msgpack data", response)
        end
      else
        response.body
      end
    end
  end
end
