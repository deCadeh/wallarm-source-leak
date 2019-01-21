require 'base64'
require 'hashie/mash'
require 'logger'
require 'wallarm/api2'
require 'yaml'

class CloudNode
  attr_reader :conf, :logger

  def initialize(args = {})
    @conf = Hashie::Mash.new(
        api: {
            host: 'api.wallarm.com',
            port: 444
        },
        regtoken: nil,

        node_yaml: '/etc/wallarm/node.yaml',
        node_yaml_tmp: '/etc/wallarm/.node.yaml.tmp',
        heartbeat_interval: 5)

    @api = nil
    @logger = args[:logger] || Logger.new(nil)
    @on_register = []
    @on_deregister = []

    configure!

    load_node_yaml
  end

  def register
    return true if registered?

    begin
      uuid, secret = reg_api.create_instance
    rescue Wallarm::API2::AccessDenied
      logger.error "Can't create new instance - access denied"
      return false
    rescue Wallarm::API2::Error => e
      logger.error "Can't create new instance - #{e}"
      return false
    end

    begin
      store_node_yaml(uuid, secret)
    rescue => e
      logger.error "Can't store instance credentials - #{e.message}"
      return false
    end

    connect_api(uuid, secret)

    logger.info "Registered new instance #{uuid}"

    @on_register.each{ |blk| blk.call api }

    true
  end

  def heartbeat_loop
    next_heartbeat = 0
    errors = 0

    loop do
      time = Time.now.to_i

      unless registered? && time > next_heartbeat
        sleep 1
        next
      end

      begin
        api.heartbeat
        next_heartbeat = time + conf.heartbeat_interval
        errors = 0
        logger.debug 'heartbeat success!'
      rescue Wallarm::API2::AccessDenied
        mark_unregistered
        errors = 0
        next
      rescue => e
        errors += 1
        next_heartbeat = time + 1
        logger.error "#{errors} last heartbeats failed: #{e}" if errors % 12 == 3
      end
    end
  end

  attr_reader :api

  def on_register(&blk)
    @on_register << blk
    blk.call api unless api.nil?
  end

  def on_deregister(&blk)
    @on_deregister << blk
  end

  private

  def with_env(name)
    value = ENV[name]
    yield value if value
  end

  def with_bool_env(name)
    with_env(name) do |value|
      case value.downcase
      when 'true', 'yes', '1'
        yield true
      else
        yield false
      end
    end
  end

  def configure!
    conf.regtoken = ENV.fetch('WALLARM_API_TOKEN', '').strip

    if conf.regtoken == ''
      logger.error 'Missed required env variable WALLARM_API_TOKEN'
      exit 1
    end

    with_env('WALLARM_API_HOST')           { |v| conf.api.host = v }
    with_env('WALLARM_API_PORT')           { |v| conf.api.port = v.to_i }
    with_env('WALLARM_API_CA_PATH')        { |v| conf.api.ca_path = v }
    with_bool_env('WALLARM_API_CA_VERIFY') { |v| conf.api.ca_verify = v }
    with_bool_env('WALLARM_API_USE_SSL')   { |v| conf.api.use_ssl = v }
  end

  def reg_api
    return @reg_api if @reg_api

    begin
      secret, *uuid = Base64.strict_decode64(conf.regtoken).unpack('H64H8H4H4H4H12')
    rescue
      raise 'Bad api token'
    end

    @reg_api = Wallarm::API2.new(conf.api.merge(uuid: uuid.join('-'), secret: secret))
  end

  def registered?
    !@api.nil?
  end

  def mark_unregistered
    logger.info "Instance registration was lost!"

    @api = nil
    File.unlink conf.node_yaml

    @on_deregister.each(&:call)
  end

  def connect_api(uuid, secret)
    @api = Wallarm::API2.new(conf.api.merge(uuid: uuid, secret: secret))
  end

  def load_node_yaml
    data = YAML.load(File.read(conf.node_yaml)) rescue nil
    return if data.nil?
    return if data['api'] != conf.api

    api = Wallarm::API2.new(conf.api.merge(uuid: data['uuid'], secret: data['secret']))

    cloud_node = reg_api.user
    node = api.user

    return if node['cloud_node_id'] != cloud_node['id']

    @api = api

    logger.info "Detected instance #{data['uuid']}"
  rescue
  end

  def store_node_yaml(uuid, secret)
    data = {
      'api' => conf.api.to_hash,
      'uuid' => uuid,
      'secret' => secret
    }
    IO.binwrite conf.node_yaml_tmp, data.to_yaml
    File.rename conf.node_yaml_tmp, conf.node_yaml
  end
end
