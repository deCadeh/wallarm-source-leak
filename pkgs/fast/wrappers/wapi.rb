require 'thread/pool'
require 'net/https'
require 'json'
require 'msgpack'

class Wallarm
  class API
    VERSION = '0.0.1'

    class LoginFailed         < RuntimeError; end
    class ServerError         < RuntimeError; end
    class AccessDenied        < RuntimeError; end
    class BadRequest          < RuntimeError; end
    class AlreadyExists       < RuntimeError; end
    class NotModified         < RuntimeError; end
    class NotFound            < RuntimeError; end
    class InternalServerError < RuntimeError; end
    class AlreadyLocked       < RuntimeError; end

    DEFAULTS = {
      host:      'api.wallarm.com',
      port:      444,
      use_ssl:   true,
      ca_file:   '/usr/share/wallarm-common/ca.pem',
      ca_verify: true
    }.freeze

    # Wallarm::API.new(hash)
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
    def initialize(args = {})
      args.merge!(DEFAULTS) { |_key, value, _default| value }

      @host         = args[:host]
      @port         = args[:port]
      @use_ssl      = args[:use_ssl]
      @ca_file      = args[:ca_file]
      @ca_verify    = args[:ca_verify]
      @open_timeout = args[:open_timeout] || 10
      @read_timeout = args[:read_timeout] || 20

      @headers = {
        'User-Agent' => "ruby wallarm/api (#{Wallarm::API::VERSION})"
      }
      @http = []
      @pool = Thread.pool(args[:pool_size] || 1)

      if args.key? :username
        login(args[:username], args[:password])
      elsif args.key? :uuid
        @headers['X-WallarmAPI-Node']   = args[:uuid]
        @headers['X-WallarmAPI-Secret'] = args[:secret]
      else
        raise 'No one of username or uuid specified'
      end
    end

    # Make blocking request
    def request(method, data, opts = {})
      opts.merge!(format: :msgpack) { |_k, o, _n| o }
      _request(method, data, opts)
    end

    # Make async request. Returns instance of Thread::Pool::Task
    def arequest(method, data, opts = {}, userdata = nil)
      opts.merge!(format: :msgpack) { |_k, o, _n| o }

      @pool.process do
        resp = _request(method, data, opts)
        userdata.nil? ? resp : [resp, userdata]
      end
    end

    def user
      @user ||= request('/v1/user', {})['body']
    end

    def clientid
      @clientid ||= user['clientid']
    end

    private

    def with_conn
      http = @http.shift || new_conn
      yield http
      @http << http
    end

    def new_conn
      http = Net::HTTP.new(@host, @port)
      http.open_timeout = @open_timeout
      http.read_timeout = @read_timeout
      http.use_ssl      = @use_ssl
      http.ca_file      = @ca_file
      http.verify_mode  = (
        @ca_verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      )
      http
    end

    def login(username, password)
      with_conn do |http|
        headers = @headers.merge('Content-Type' => 'application/msgpack')
        data    = { username: username, password: password }

        http.request_post('/v1/login', data.to_msgpack, headers) do |response|
          data = parse_response(response)

          begin
            status = data['status']
            token  = data['body']['token']
          rescue
            raise ServerError, "Server reply bad json data (#{response.body})"
          end

          raise LoginFailed, data['body'] if status != 200

          @token = token
          @headers['cookie'] = response.get_fields('set-cookie').map do |c|
            c.gsub(/; .*/, '')
          end.join '; '
        end
      end
    end

    def _request(method, data, opts)
      unless data.is_a? Hash
        raise TypeError, "data must be Hash, not #{data.class}"
      end

      data = data.clone

      unless opts[:without_token] == true
        data[:token] = @token if @token
      end

      case opts[:format]
      when :json
        data = data.to_json
        headers = @headers.merge('Content-Type' => 'application/json')
      when :msgpack
        data = data.to_msgpack
        headers = @headers.merge('Content-Type' => 'application/msgpack')
      else
        raise TypeError, 'Format option can be :json or :msgpack'
      end

      response = nil

      req_klass =
        case opts[:method]
        when :get
          Net::HTTP::Get
        when :post
          Net::HTTP::Post
        when :put
          Net::HTTP::Put
        when :delete
          Net::HTTP::Delete
        when :head
          Net::HTTP::Head
        else
          Net::HTTP::Post
        end

      req = req_klass.new(method)
      req.body = data

      opts_headers = opts[:headers] || {}
      headers.merge(opts_headers).each { |k, v| req[k] = v }

      with_conn do |http|
        response = http.request(req)
      end

      data = parse_response(response)
      return data if opts[:raw]

      case response.code
      when '200'
        # all ok
      when '304'
        raise NotModified
      when '403'
        raise AccessDenied
      when '400'
        raise BadRequest, data unless data.is_a? Hash
        raise AlreadyExists if data['body'] == 'Already exists'
        raise AccessDenied  if data['body'] == 'denied'
        raise BadRequest,   data['body']
      when '423'
        raise AlreadyLocked
      when '409'
        raise AlreadyExists
      when '500'
        raise InternalServerError
      when '404'
        raise NotFound
      else
        raise ServerError, data
      end

      data
    end

    def parse_response(response)
      case response.content_type.to_s.gsub(/;.*/, '')
      when 'application/json'
        begin
          JSON.parse response.body
        rescue
          raise ServerError, "Server reply bad json data: #{response.body}"
        end
      when 'application/msgpack'
        begin
          MessagePack.unpack response.body
        rescue
          raise ServerError, "Server reply bad msgpack data: #{response.body}"
        end
      else
        response.body
      end
    end
  end
end
